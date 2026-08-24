# Syncthing 发现服务器架构分析

**来源**: syncthing v1.30.0 源码

---

## 1. 总体架构

```
┌───────────────────┐     HTTPS JSON     ┌───────────────────┐
│  全球发现服务器    │◄─────────────────►│  Syncthing 客户端  │
│  (stdiscosrv)     │    注册/查询       │                   │
│  :8443            │                    ├───────────────────┤
│                   │    ip:port/token   │  本地发现 (LAN)    │
└───────────────────┘                    │  (beacon 广播/多播) │
                                         └───────────────────┘
```

两种发现机制配合使用:
- **本地发现**: LAN 内通过广播/多播，毫秒级响应
- **全球发现**: 跨越 NAT，通过 HTTPS 向公共目录服务注册和查询

---

## 2. 全球发现服务器 (stdiscosrv)

### 2.1 启动流程 (`cmd/stdiscosrv/main.go`)

1. **解析 CLI 参数**: 监听地址、数据库路径、证书路径、速率限制、HTTP 重定向
2. **加载数据库**: 使用 `cockroachdb/pebble` (LSM-Tree KV 存储)
3. **TLS 配置**: 服务器证书 + 可选的客户端证书认证
4. **启动 HTTP 服务**: `:8443` (默认)

**CLI 选项**:
- `-db-dir` (默认 `./discovery-db`) — Pebble 数据库路径
- `-http` (默认 `:8443`) — 监听地址
- `-cert` / `-key` — TLS 证书路径（默认自动生成 2048-bit RSA）
- `-db-compression` — Pebble 压缩算法 (snappy/zstd/none)
- `-rate-requests` — 每秒最大查询请求数（0=不限）
- `-rate-certs` — 白名单证书数量上限
- `-redirect-http-to` — HTTP 重定向目标 URL
- `-access-control` — 允许注册的证书指纹白名单文件

### 2.2 存储架构 (`db.go`)

基于 CockroachDB Pebble (LSM-Tree)，比 BoltDB 更适合写密集场景。

**存储格式**: 3 个 key 空间:

```
注册记录:    certHash -> encryptedCert (Blake2b-160 + NaCl 密封)
老化记录:    extinctKey -> extinctTime
地址记录:    certHash + announcement -> []address (protobuf 编码)
```

**过期清理**: 定时器每 2 分钟运行，删除过期的注册和老化记录。

### 2.3 API 端点

服务器暴露一个端点，根据 HTTP 方法和头部行为不同:

**统一端点**: `/v2/` (或任何路径)

#### 2.3.1 注册 (PUT)

```
PUT /v2/<deviceID-hex> HTTP/1.1
Content-Type: application/json
Authorization: <token>

{"instanceID": "<instance>", "addresses": [...]}
```

处理 (`handleRegister`):
1. 从路径解析设备 ID（十六进制）
2. 验证 token（通过 TLS 客户端证书或认证头）
3. 提取客户端 IP
4. 存储地址记录（含过期时间）
5. 返回 `204 No Content`

**认证方式**:
- **TLS 客户端证书**: 配置 `-access-control` 限制特定证书指纹
- **Authorization 头**: 用于从其他发现服务器转发

#### 2.3.2 查询 (GET)

```
GET /v2/<deviceID-hex> HTTP/1.1
```

处理 (`handleLookup`):
1. 从路径解析设备 ID
2. 查询数据库获取地址记录
3. 返回 `200 OK` 含 JSON 地址列表
4. 未找到时返回 `404`

**去重保护** (`globals.go`):
使用 `sync.Map` 实现请求去重:
```go
type lookupContext struct {
    lookupResult []byte
    gotResult    chan struct{}
}
```

同一客户端的相同设备 ID 16 秒内的并发查询会被合并。

#### 2.3.3 访问控制 (`record.go`)

返回自己的公钥和服务实例 ID:
```
GET /v2/
```
响应:
```json
{"instanceID": "<instanceID>", "publicKey": "<serverPublicKey>"}
```

**令牌计算**: `Blake2b-160(certificateFingerprint)` + NaCl 密封加密设备 ID

### 2.4 速率限制 (`rate.go`)

**令牌桶 (Token Bucket)**: `golang.org/x/time/rate` 实现，每秒 `rateRequests` 个令牌。

额外限制: **允许的最大证书数** = `rateCerts`（白名单容量限制）。

### 2.5 数据记录格式 (`record.go`)

注册时，设备 ID 使用服务器的公钥通过 NaCl 密封加密 (`box.SealAnonymous`)，确保只有服务器能解密。

地址记录格式:
```go
type record struct {
    InstanceID   string   // 服务器实例 ID
    Addresses    []string // "tcp://ip:port" 格式
    Certificate  []byte   // 设备证书
    Seen         int64    // 最后一次看到的时间戳 (UnixNano)
}
```

缓存控制: 响应包含 `Cache-Control: max-age=<ttl>`，TTL = `announcement.Until - time.Now()`。

---

## 3. 本地发现 (LAN)

### 3.1 实现 (`lib/discover/local.go`)

**接口**: `Discoverer` 接口:
```go
type Discoverer interface {
    Lookup(ctx context.Context, deviceID protocol.DeviceID) ([]string, error)
    Error() error
    String() string
    Cache() map[protocol.DeviceID]CacheEntry
}
```

**本地发现** 使用两种协议:
| 协议 | 实现 | 默认端口 | 特征 |
|---|---|---|---|
| IPv4 广播 | `lib/beacon/broadcast.go` | 21027/UDP | 发送到 `255.255.255.255:21027` |
| IPv6 多播 | `lib/beacon/multicast.go` | 21027/UDP | 发送到 `[ff12::8384]:21027` |

**数据格式**（protobuf 编码）:
```
AnnounceMessage:
  magic: 0x9E79BC39
  deviceID: [32]byte
  addresses: []struct{ port: uint16; ... }
```

**发送间隔**: 每 30 秒发送一次本地发现公告（可配置）。

**接收处理**: 收到公告后，ping 对等端地址进行可达性验证后，将地址加入本地发现缓存。

### 3.2 缓存管理

```go
type CacheEntry struct {
    Addresses  []string
    Seen       time.Time
}
```

- 每个设备 ID 最多缓存 16 个地址
- 缓存条目 15 分钟后过期

---

## 4. 全球发现客户端

### 4.1 实现 (`lib/discover/global.go`)

**构造**:
```go
func NewGlobalDiscoverer(server string, cert tls.Certificate, timeout time.Duration) *GlobalDiscoverer
```
- `server`: 发现服务器 URL（如 `https://discovery.syncthing.net/v2/`）
- `cert`: 设备证书（用于请求认证）
- `timeout`: 请求超时

**查询流程** (`Lookup`):
1. 使用设备 ID 构建查询 URL
2. 发起 HTTPS GET 请求
3. 解析返回的 JSON 地址列表
4. 返回地址列表

**注册流程** (`announce`):
1. 定期（默认每 30 分钟）向发现服务器发送设备地址
2. 使用 `net/http/httpproxy` 支持 HTTP 代理
3. 发送含设备基本信息的 JSON 负载

### 4.2 端到端流程

```
客户端 A:
  1. 监听 TCP :22000
  2. 向发现服务器注册 (tcp://public_ip_1:22000, relay://relay.example.com:22067?id=...)
  3. 每 30 分钟更新注册

客户端 B 查找 A:
  1. 同时发起:
     a. 本地发现 (LAN broadcast/multicast) -> 同局域网时秒级响应
     b. 全球发现 (HTTPS to stdiscosrv) -> 返回 A 的地址和中继 URI
  2. 先到先用: 本地发现更快，全球发现补充
```

---

## 5. 配置集成 (`lib/config/optionsconfiguration.go`)

```go
type OptionsConfiguration struct {
    // ...
    GlobalAnnEnabled    bool     `default:"true"`
    GlobalAnnServers    []string `default:"default"`
    RelaysEnabled       bool     `default:"true"`
    // ...
}
```

`GlobalAnnServers` 默认值展开为:
```go
"default"  // -> "https://discovery.syncthing.net/v2/"
```

可配置为:
- `"https://discovery.syncthing.net/v2/"` — 官方公共发现服务器
- `"https://my-custom-discosrv:8443/"` — 自建发现服务器
- `""` — 禁用全球发现

---

## 6. 关键文件索引

| 文件 | 角色 |
|---|---|
| `cmd/stdiscosrv/main.go` | 发现服务器入口、CLI、HTTPS 设置 |
| `cmd/stdiscosrv/record.go` | 记录定义、令牌计算、访问控制 |
| `cmd/stdiscosrv/db.go` | Pebble KV 存储、CRUD、过期清理 |
| `cmd/stdiscosrv/globals.go` | 请求去重 (sync.Map)、16 秒合并窗口 |
| `cmd/stdiscosrv/rate.go` | 令牌桶速率限制 |
| `lib/discover/local.go` | 本地发现 (LAN broadcast/multicast) |
| `lib/discover/global.go` | 全球发现客户端 (HTTPS) |
| `lib/beacon/broadcast.go` | IPv4 UDP 广播实现 |
| `lib/beacon/multicast.go` | IPv6 UDP 多播实现 |
| `lib/config/optionsconfiguration.go` | 发现配置选项 |

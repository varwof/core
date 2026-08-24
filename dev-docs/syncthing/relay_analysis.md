# Syncthing 中继服务器架构分析

**来源**: syncthing v1.30.0 源码  
**分析日期**: 2026-06-23

---

## 目录

1. [总体架构](#1-总体架构)
2. [中继协议](#2-中继协议)
3. [中继服务器 strelaysrv](#3-中继服务器-strelaysrv)
4. [中继客户端库](#4-中继客户端库)
5. [中继池服务器 strelaypoolsrv](#5-中继池服务器-strelaypoolsrv)
6. [主 syncthing 集成](#6-主-syncthing-集成)
7. [端到端连接流程](#7-端到端连接流程)
8. [关键文件索引](#8-关键文件索引)

---

## 1. 总体架构

中继系统由四个逻辑组件构成：

```
┌─────────────────────┐      HTTP/JSON       ┌──────────────────────┐
│   中继池服务器      │◄────────────────────►│   中继服务器         │
│   (目录服务)        │  注册/心跳           │   (strelaysrv)       │
│   :80               │                      │   :22067 (TLS relay) │
│                     │                      │   :22070 (状态页)    │
└─────────┬───────────┘                      └──────────┬───────────┘
          │                                              │
          │ HTTP/JSON                                     │ 中继协议 (XDR)
          │ (客户端查询池)                                │ (TLS 加密 TCP)
          ▼                                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Syncthing 客户端 (主二进制)                      │
│  lib/connections/relay_dial.go    -- 出站 (拨号器)                │
│  lib/connections/relay_listen.go  -- 入站 (监听器)                │
│  lib/relay/client/                -- 客户端库                      │
│  lib/relay/protocol/              -- 线缆协议                      │
└──────────────────────────────────────────────────────────────────┘
```

**协议分层**:

```
BEP (块交换协议)     ← syncthing 自身同步协议
┌─────────────────────────────┐
│        TLS                  │ ← 双向 TLS（设备证书）
├─────────────────────────────┤
│   中继协议 (XDR编码)        │ ← 自定义成帧协议
├─────────────────────────────┤
│   原始 TCP                  │ ← 网络传输
└─────────────────────────────┘
```

---

## 2. 中继协议

### 2.1 线缆格式

**文件**: `lib/relay/protocol/protocol.go`  
**报文编码**: `lib/relay/protocol/packets.go`  
**XDR 编码**: `lib/relay/protocol/packets_xdr.go` (通过 `calmh/xdr` 自动生成)

所有消息使用 **头部 + 负载** 的成帧格式，XDR 编码:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          magic (0x9E79BC40)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       messageType (int32)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      messageLength (int32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                   message payload (variable)                  /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic**: `0x9E79BC40` — 读写时均验证
- **最大负载**: 1024 字节
- **ALPN**: `"bep-relay"`

### 2.2 消息类型

| 常量 | 类型 | 字段 | 方向 |
|---|---|---|---|
| `messageTypePing` (0) | `Ping` | (空) | 双向 |
| `messageTypePong` (1) | `Pong` | (空) | 双向 |
| `messageTypeJoinRelayRequest` (2) | `JoinRelayRequest` | `Token string` | 客户端→中继 |
| `messageTypeJoinSessionRequest` (3) | `JoinSessionRequest` | `Key []byte`(最多32) | 客户端→中继(数据连接) |
| `messageTypeResponse` (4) | `Response` | `Code int32, Message string` | 中继→客户端 |
| `messageTypeConnectRequest` (5) | `ConnectRequest` | `ID []byte`(最多32,设备ID) | 客户端→中继 |
| `messageTypeSessionInvitation` (6) | `SessionInvitation` | `From, Key, Address []byte, Port uint16, ServerSocket bool` | 中继→客户端 |
| `messageTypeRelayFull` (7) | `RelayFull` | (空) | 中继→客户端 |

### 2.3 标准响应

```go
ResponseSuccess           = Response{0, "success"}
ResponseNotFound          = Response{1, "not found"}
ResponseAlreadyConnected  = Response{2, "already connected"}
ResponseWrongToken        = Response{3, "wrong token"}
ResponseUnexpectedMessage = Response{100, "unexpected message"}
```

### 2.4 SessionInvitation 结构

```go
type SessionInvitation struct {
    From         []byte // 对等设备 ID (最多 32 字节)
    Key          []byte // 32 字节随机会话密钥
    Address      []byte // 中继 IP 地址
    Port         uint16 // 中继端口
    ServerSocket bool   // true=本端应作为 TLS Server
}
```

`ServerSocket` 标记至关重要：告诉每一端在 TLS 包裹数据连接时谁当 Server、谁当 Client，从而通过中继完成双向 TLS 握手。

---

## 3. 中继服务器 strelaysrv

**关键文件**:
- `cmd/strelaysrv/main.go` — 入口、CLI、TLS 设置
- `cmd/strelaysrv/listener.go` — TCP 接收、协议分发
- `cmd/strelaysrv/session.go` — 会话管理、数据转发
- `cmd/strelaysrv/pool.go` — 池注册
- `cmd/strelaysrv/status.go` — HTTP 状态 API
- `cmd/strelaysrv/utils.go` — TCP socket 调优

### 3.1 启动流程

`main()` 顺序执行:

1. **解析 CLI 参数** — 监听地址(`:22067`)、密钥目录、超时、速率限制、池地址、NAT 选项
2. **加载/生成 TLS 证书** — 使用 `tlsutil.NewCertificate()`，CN=`"strelaysrv"`，20 年有效期
3. **设置 TLS 配置** — ALPN=`"bep-relay"`，请求客户端证书，指定 TLS 1.2+ 套件
4. **计算设备 ID** — `syncthingprotocol.NewDeviceID(cert.Raw)`
5. **NAT 设置** — UPnP/PMP（若启用）
6. **全局速率限制器** — `golang.org/x/time/rate`
7. **构建中继 URI** — `relay://<IP>:<port>/?id=<deviceID>&pingInterval=...&networkTimeout=...`
8. **启动池注册** — 对每个池 URL 启动 goroutine 运行 `poolHandler()`
9. **启动 TCP 监听** — `listener()` goroutine，使用 `DowngradingListener`
10. **等待 SIGINT/SIGTERM** — 优雅关闭

### 3.2 连接接收 (`listener.go`)

使用 `DowngradingListener` (`lib/tlsutil/tlsutil.go:175`) 读取首字节区分 TLS 还是裸 TCP:

- **若字节 == 0x16 (TLS record)**: 视为 **控制通道**，由 `protocolConnectionHandler` 处理
- **若字节 != 0x16**: 视为 **数据通道**，由 `sessionConnectionHandler` 处理

**TCP Socket 选项** (`utils.go`):
```go
tcpConn.SetLinger(0)               // 关闭时立即断开
tcpConn.SetNoDelay(true)           // 禁用 Nagle
tcpConn.SetKeepAlive(true)         // 启用 TCP keepalive
tcpConn.SetKeepAlivePeriod(2min)   // 2 分钟
```

### 3.3 控制通道协议 (`protocolConnectionHandler`)

每个连接客户端获得一条 TLS 控制连接。

**认证流程**:
1. 客户端通过 TLS 连接，中继验证:
   - 客户端必须提供恰好 1 个证书
   - 从证书派生出设备 ID
2. 连接进入消息分发循环

**消息处理**:

| 消息 | 动作 |
|---|---|
| `JoinRelayRequest` | 加入中继。验证 token（若设置）。检查 `overLimit`。检查重复 ID。创建 outbox 通道。发送 `ResponseSuccess`。 |
| `ConnectRequest` | 想连接到另一个对等端。查找目标 outbox 通道。创建 `session` 含两个随机 32 字节 key。发送 `SessionInvitation` 给请求方和目标方。 |
| `Ping` | 回复 `Pong` |
| `Pong` | 无操作 |
| 未知 | 发送 `ResponseUnexpectedMessage` 并断开 |

**保活机制**:
- `pingTicker` 每 `pingInterval`(默认 1 分钟) 发送 `Ping`
- `timeoutTicker` 每次收到消息时重置；若超时（默认 2 分钟）则断开
- 超限时，无活跃会话的客户端被 `RelayFull` 断开

**Outbox 模式**:
每个已加入的客户端拥有一个 outbox 通道（`map[deviceID]chan interface{}`）。`ConnectRequest` 到达时，服务器推送 `SessionInvitation` 到目标 outbox，由消息分发循环写入目标 TLS 控制连接。

### 3.4 会话管理 (`session.go`)

**会话**表示两端之间的代理连接。

**会话生命周期**:

1. **创建** (`newSession`):
   - 生成两个随机 32 字节 key: `serverkey` 和 `clientkey`
   - 存入 `pendingSessions` 映射（keyed by both keys）
   - 每个会话有一个 `connsChan`（缓冲为 1 的 channel）

2. **邀请** — 服务器向双方发送 `SessionInvitation`，每端收到的 key 不同

3. **加入** — 每端建立裸 TCP 连接到中继，发送 `JoinSessionRequest{Key: invitation.Key}`

4. **代理启动** — 双方都到达后，启动两个 goroutine 执行 `session.proxy(c1, c2)`:
   ```go
   func (s *session) proxy(c1, c2 net.Conn) error {
       buf := make([]byte, 65536)
       for {
           c1.SetReadDeadline(time.Now().Add(networkTimeout))
           n, err := c1.Read(buf)
           if err != nil { return err }
           c2.SetWriteDeadline(time.Now().Add(networkTimeout))
           _, err = c2.Write(buf[:n])
           if err != nil { return err }
       }
   }
   ```
   这是简单的 **读A→写B** 循环，无协议感知。

5. **拆除** — 出错或超时时从 `pendingSessions` 和 `activeSessions` 移除，关闭所有连接。

**超时**: 若双方未在 `messageTimeout`(默认 1 分钟) 内连接，会话超时。

### 3.5 速率限制

两个独立的 token bucket 限速器 (`golang.org/x/time/rate`):

- **`--per-session-rate`**: 每会话 `rate.Limiter`，burst = 2x rate
- **`--global-rate`**: 全局 `rate.Limiter`，跨所有会话

`makeRateLimitFunc()` 在会话创建时优化：
- `nil` — 不限速
- 仅调用 `take(bytes, globalRateLimit)`
- 仅调用 `take(bytes, sessionRateLimit)`
- 两者都调用

### 3.6 资源管理

- **文件描述符限制**: 启动时 `osutil.MaximizeOpenFileLimit()` 提升 fd 限制。80% 作为 `descriptorLimit`。`monitorLimits()` 每分钟检查。
- **超限行为**: 新 `JoinRelayRequest` 被拒绝 (`RelayFull`)。已连接但无活跃会话的客户端被断开。
- **`numConnections`** — TLS 控制连接数
- **`numProxies`** — 活跃代理 goroutine 数（每个会话 2 个）

### 3.7 池注册 (`pool.go`)

`poolHandler()` goroutine:
1. HTTP POST 到池服务器，JSON `{"url": "relay://..."}`
2. 若池 URL 是 HTTPS，发送中继自身的 TLS 证书作为客户端证书
3. 解析 `evictionIn` 持续时间
4. 休眠 `evictionIn - evictionIn/5`（80% 时间后重新注册）
5. 出错时 1 分钟后重试
6. 收到 `401 Unauthorized`(IP 不匹配) 时永久中止

### 3.8 状态服务 (`status.go`)

HTTP 服务器在 `:22070`:
- `GET /status` — JSON：构建信息、运行时间、会话计数、连接计数、代理字节数、速率历史、选项
- `GET /debug/pprof/` — 若 `-pprof` 启用

速率计算器以 10 秒间隔跟踪 60 分钟吞吐量，报告 10s/1m/5m/15m/30m/60m 均值。

---

## 4. 中继客户端库

**关键文件**:
- `lib/relay/client/client.go` — 接口定义
- `lib/relay/client/static.go` — 静态中继客户端
- `lib/relay/client/dynamic.go` — 动态池客户端
- `lib/relay/client/methods.go` — 工具函数

### 4.1 接口

```go
type RelayClient interface {
    suture.Service
    Error() error
    String() string
    Invitations() <-chan protocol.SessionInvitation
    URI() *url.URL
}
```

创建方式: `NewClient(uri, certs, timeout)`
- `relay://...` → `staticClient`
- `dynamic+http://...` 或 `dynamic+https://...` → `dynamicClient`

### 4.2 静态客户端 (`staticClient`)

**`serve()` 方法**:
1. **连接** (`connect()`): TCP dial + TLS 握手 + ALPN `"bep-relay"` + 可选中继 ID 验证
2. **加入** (`join()`): 发送 `JoinRelayRequest`(可选 token)，期望 `Response{0}` 或 `RelayFull`
3. **消息循环**: 读取控制连接消息:
   - `Ping` → 回复 `Pong`
   - `SessionInvitation` → 修正地址后发送到 `invitations` channel
   - `RelayFull` → 返回错误，触发重连
   - 未知 → 返回错误
4. 使用 `messageTimeout` 定时器（2 分钟）作为不活跃超时

**ID 验证** (`performHandshakeAndValidation`):
若中继 URI 包含 `?id=<deviceID>`，验证中继的 TLS 证书与广告的设备 ID 匹配。

### 4.3 动态客户端 (`dynamicClient`)

从池服务器发现中继。

**`serve()` 方法**:
1. **获取中继列表**: HTTP GET 到池端点
2. **解析响应**: JSON `{"relays": [{"url": "relay://..."}, ...]}`
3. **按延迟排序**: `relayAddressesOrder()`:
   - 测量每个中继的延迟
   - 按 50ms 延迟范围分桶
   - 桶内随机打乱
   - 按延迟升序返回
4. **逐个尝试**: 对每个中继创建 `staticClient` 并调用 `Serve()`。若断开（如 `RelayFull`），尝试下一个。

### 4.4 工具函数 (`methods.go`)

**`GetInvitationFromRelay(ctx, uri, peerID, certs, timeout)`** — 拨号器使用:
1. 建立 TLS 连接到中继
2. TLS 握手 + ALPN + ID 验证
3. 发送 `ConnectRequest{ID: peerID[:]}`
4. 读取响应: `Response`(错误) 或 `SessionInvitation`(成功)
5. 若地址未指定则修正（使用连接远程地址）

**`JoinSession(ctx, invitation)`** — 拨号器和监听器都使用:
1. 建立裸 TCP 连接到中继地址:端口
2. 发送 `JoinSessionRequest{Key: invitation.Key}`
3. 读取 `Response{0}` 表示成功
4. 返回原始 TCP 连接（未 TLS 包裹）

---

## 5. 中继池服务器 strelaypoolsrv

**关键文件**:
- `cmd/infra/strelaypoolsrv/main.go` — 所有 HTTP 处理
- `cmd/infra/strelaypoolsrv/stats.go` — 中继统计和 Prometheus 指标

### 5.1 架构

池服务器是中继的**目录服务**。作为 HTTP(S) 服务器提供三个端点:

| 端点 | 方法 | 描述 |
|---|---|---|
| `/endpoint` | GET | 返回最小中继列表 (仅 URL) |
| `/endpoint/full` | GET | 返回完整中继列表（含元数据、位置、统计） |
| `/endpoint` | POST | 中继注册 |
| `/` | GET | 状态页面 |

### 5.2 中继注册 (`handleRegister`)

流程:
1. **IP 提取**: 从 `RemoteAddr` 或配置的 `ip-header` 获取客户端 IP
2. **黑名单检查**: 每个主机错误计数在 LRU 缓存中。连续 10 次失败后，主机收到 `401 Unauthorized`（中继永久中止加入）
3. **证书验证**: 若连接是 TLS 且中继提供了客户端证书，验证广告的设备 ID 与证书匹配
4. **IP 验证**: 若中继广告的 IP 与连接 IP 不同且无 TLS 证书，返回 `401`
5. **去重检查**: 若主机与永久中继匹配则拒绝
6. **异步测试**: 请求排队；`requestProcessor` goroutine 调用 `client.TestRelay()` 验证中继可用
7. **统计获取**: 调用中继的 `/status` 端点收集运营指标
8. **GeoIP 查询**: 从 IP 解析中继位置（MaxMind GeoLite2）
9. **驱逐定时器**: 设置定时器，到期后从中继列表中移除
10. **响应**: 返回 `{"evictionIn": <duration>}`（默认 1 小时）
11. **持久化**: 保存中继 URL 到 `knownRelaysFile`

### 5.3 客户端查询端点

**短端点**: 返回 `{"relays": [{"url": "relay://..."}]}`，最多 `maxRelaysReturned`(默认 100)，超限随机打乱。

**完整端点**: 包含 GeoIP 位置、运营统计、速率历史。

### 5.4 统计收集 (`stats.go`)

`statsRefresher` goroutine 每隔 `statsRefresh`(默认 1 分钟) 从中继的 `/status` 获取:
- 运行时间、会话数、连接数、代理数、代理字节数、Go 运行时信息、速率
- 通过 Prometheus 指标暴露在 `:8081/metrics`
- 优雅处理计数器重置（通过 `mergeStats()`）

---

## 6. 主 syncthing 集成

### 6.1 优先级连接系统

| 连接类型 | 优先级 (默认值) |
|---|---|
| TCP LAN | 10 |
| QUIC LAN | 20 |
| TCP WAN | 30 |
| QUIC WAN | 40 |
| **中继** | **50** (最低) |

中继连接优先级**最低** — 仅在无法直接连接时使用。

### 6.2 中继作为监听器 (`relay_listen.go`)

`relayListenerFactory` 注册 scheme `relay`、`dynamic+http`、`dynamic+https`。

**`serve()`**: 创建 `client.NewClient()`，启动 `handleInvitations()` goroutine 处理入站会话邀请。

**`handleInvitations()`**: 监听 `Invitations()` channel，对每个邀请调用 `client.JoinSession()`，然后 TLS 包裹（取决于 `ServerSocket` 标记），推送到共享 `conns` channel。

### 6.3 中继作为拨号器 (`relay_dial.go`)

**`Dial()`**:
1. 调用 `client.GetInvitationFromRelay()` — 通过中继请求连接到目标设备
2. 调用 `client.JoinSession()` — 在数据端口加入会话
3. 设置 TCP 选项和流量类别
4. TLS 包裹（取决于 `ServerSocket` 标记）
5. 返回 `newInternalConn(tc, connTypeRelayClient, false, wanPriority)`

### 6.4 中继 vs 直连: 决策流程

**`resolveDialTargets()`** (`service.go:656`):
1. 解析设备地址（通过配置和/或发现）
2. 对每个地址:
   - 解析 URI scheme（`tcp://`、`relay://` 等）
   - 查找对应的拨号器工厂
   - 检查拨号器优先级是否优于截止值
   - 构建 `dialTarget`（含优先级、拨号器、URI）

**`dialParallel()`** (`service.go:1139`):
1. 按优先级分组目标
2. 同级优先级的所有目标并行拨号（每设备最多 8 个，全局最多 64 个）
3. 返回**第一个成功连接**
4. 同级的其余连接被丢弃
5. 若当前优先级级别无成功连接，进入下一级

### 6.5 默认配置

默认监听地址:
```go
"default"  // 展开为:
    "tcp://0.0.0.0:22000"
    "dynamic+https://relays.syncthing.net/endpoint"
```

默认情况下 Syncthing:
- 监听 TCP 22000 端口
- 连接到公共中继池 `relays.syncthing.net`（作为客户端接收入站中继连接）
- 使用池发现出站连接所需的中继服务器

---

## 7. 端到端连接流程

### 场景: 客户端 A 要通过中继连接到客户端 B

```
1. 发现:
   客户端 A 通过全局发现获知 B 的地址
   返回: ["tcp://1.2.3.4:22000", "relay://relay.example.com:22067?id=<B's ID>", ...]

2. 拨号循环 (service.go:connect):
   - 按优先级分组目标:
     优先级 10: TCP LAN 地址
     优先级 30: TCP WAN 地址
     优先级 50: relay://relay.example.com

3. 先尝试高优先级:
   - 尝试 TCP 连接 -- 全部失败 (B 在 NAT 后)

4. 降级到中继 (优先级 50):
   relayDialer.Dial(ctx, B's ID, relayURI):
     a. TLS 连接 relay.example.com:22067
     b. ALPN 协商 "bep-relay"
     c. 发送 ConnectRequest{ID: B's device ID bytes}

5. 中继处理 ConnectRequest:
   a. 查找 B 的 outbox 通道
   b. 创建新会话（随机 key）
   c. 向 A 发送 SessionInvitation (通过 A 的控制连接)
   d. 向 B 发送 SessionInvitation (通过 B 的 outbox 通道)
   e. 关闭 A 的控制连接

6. 客户端 B 通过其控制连接收到 SessionInvitation:
   relayListener.handleInvitations():
     a. 调用 JoinSession(invitation)
     b. 建立 TCP 到 relay:22067 (裸 socket)
     c. 发送 JoinSessionRequest{Key: B's session key}
     d. 收到 Response{0}
     e. 作为 TLS Server 包裹 (ServerSocket=true)
     f. 推送到 conns channel

7. 客户端 A (从 GetInvitationFromRelay 返回后):
   a. 调用 JoinSession(invitation)
   b. 建立 TCP 到 relay:22067 (裸 socket)
   c. 发送 JoinSessionRequest{Key: A's session key}
   d. 收到 Response{0}
   e. 作为 TLS Client 包裹 (ServerSocket=false)

8. 中继 session.go:
   - 双方连接都到达会话
   - Session.Serve() 启动两个代理 goroutine
   - 数据流: A ↔ 中继 ↔ B (原始 TCP 中继)

9. 通过隧道:
   - A 和 B 通过中继进行双向 TLS 握手
   - TLS 握手成功 (ServerSocket 标记确保正确角色)
   - 交换 BEP Hello 消息
   - 开始正常 syncthing 协议

10. 连接管理:
    - 任一端从中继断开时，中继通过代理读错误检测
    - 会话清理从 activeSessions 移除
    - 客户端 B 的中继监听器检测断开，可能尝试池中另一个中继
    - 优先级系统监控：若有更好的 (TCP/QUIC) 连接可用，中继连接将被关闭并报 errReplacingConnection
```

---

## 8. 关键文件索引

| 文件 | 角色 |
|---|---|
| `cmd/strelaysrv/main.go` | 中继服务器入口、CLI、TLS、URI 构建 |
| `cmd/strelaysrv/listener.go` | TCP 接收、协议分发、控制消息处理 |
| `cmd/strelaysrv/session.go` | 会话生命周期、数据代理循环、速率限制 |
| `cmd/strelaysrv/pool.go` | 池服务器注册 (HTTP POST 心跳) |
| `cmd/strelaysrv/status.go` | HTTP 状态端点、速率计算器 |
| `cmd/strelaysrv/utils.go` | TCP socket 选项调优 |
| `lib/relay/protocol/protocol.go` | 线缆协议: ReadMessage/WriteMessage、magic、标准响应 |
| `lib/relay/protocol/packets.go` | 消息类型定义 (Ping/Pong/JoinRelayRequest 等) |
| `lib/relay/protocol/packets_xdr.go` | 自动生成 XDR 编解码 |
| `lib/relay/client/client.go` | RelayClient 接口 + 工厂 (NewClient) |
| `lib/relay/client/static.go` | 静态中继客户端: 连接、加入、邀请处理 |
| `lib/relay/client/dynamic.go` | 动态池客户端: 获取中继列表、延迟排序、故障转移 |
| `lib/relay/client/methods.go` | GetInvitationFromRelay、JoinSession、TestRelay |
| `lib/connections/relay_listen.go` | 中继监听器: 入站中继连接 |
| `lib/connections/relay_dial.go` | 中继拨号器: 出站中继连接 |
| `lib/connections/service.go` | 连接服务: 拨号循环、优先级系统、并行拨号、身份验证 |
| `lib/connections/structs.go` | internalConn、connType、dialTarget、commonDialer、priority |
| `lib/connections/dialqueue.go` | 拨号队列排序 (最近优先、旧记录打乱) |
| `lib/connections/tcp_dial.go` | TCP 拨号器 (优先级高于中继) |
| `lib/config/optionsconfiguration.go` | 配置: RelaysEnabled、ConnectionPriorityRelay 等 |
| `lib/tlsutil/tlsutil.go` | DowngradingListener TLS/裸TCP 多路分解 |
| `cmd/infra/strelaypoolsrv/main.go` | 池服务器: 注册、查询端点、黑名单、驱逐 |
| `cmd/infra/strelaypoolsrv/stats.go` | 池服务器: 统计收集、Prometheus 指标 |

# varwof-gateway

三层零信任安全网关，统一 TCP/HTTP/UDP 协议，支持 mTLS、RBAC 和 AIC 能力验证。

**模块**：`github.com/varwof/gateway`
**许可证**：Apache-2.0
**状态**：预览版

## 概述

varwof 网关提供三个协议特定的二进制程序：

| 二进制程序 | 层级 | 协议 | 用途 |
|------------|------|------|------|
| `gateway-http` | L7 | HTTP/1.1、HTTP/2、H2C、gRPC、WebSocket、HTTP/3、QUIC | Web 应用、API、微服务 |
| `gateway-tcp` | L4 | TCP、mTLS、Mesh | 数据库代理、SSH、通用 TCP |
| `gateway-udp` | L3 | UDP、DTLS、QUIC | DNS、VoIP、物联网、游戏 |

三个二进制程序共享相同的安全核心（`gateway-core`）：
- mTLS 客户端证书认证
- CRL 实时吊销
- OCSP Stapling/检查
- AIC（Agent Identity Certificate）验证
- RBAC（基于角色的访问控制）
- 能力插件系统
- 短期证书自动签发
- 基于 Merkle 哈希链的审计日志
- Prometheus 指标
- SIGHUP 热重载

## 架构

```
                    ┌─────────────────────────────────────┐
                    │         gateway-core (shared)        │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ CRL     │ │ OCSP   │ │ Audit  │ │
                    │  │ Cache   │ │ Cache  │ │ Logger │ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ RBAC    │ │ AIC    │ │ CapReg │ │
                    │  │ Check   │ │ Verify │ │        │ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ Short   │ │ Revoker│ │ Risk   │ │
                    │  │ Lived   │ │        │ │ Monitor│ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
    ┌─────────▼─────────┐ ┌───────▼───────┐ ┌──────────▼──────────┐
    │   gateway-http    │ │  gateway-tcp  │ │    gateway-udp      │
    │   (L7 反向        │ │  (L4 映射     │ │    (L3 转发         │
    │    代理)          │ │   + 隧道)     │ │     + DTLS/QUIC)    │
    └───────────────────┘ └───────────────┘ └─────────────────────┘
```

## 安装

```bash
# 构建全部三个程序
go build -o gateway-http ./cmd/http/
go build -o gateway-tcp ./cmd/tcp/
go build -o gateway-udp ./cmd/udp/
```

## 快速开始

### HTTP 网关

```bash
# 1. 创建配置文件
cat > gateway-http.json << 'EOF'
{
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http2",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "/etc/varwof/gateway/ca.pem"
      },
      "routes": [
        {
          "path": "/api/*",
          "target": "http://backend:8080",
          "allow_roles": ["gateway:ops"]
        }
      ]
    }
  ],
  "management": {
    "listen": "127.0.0.1:9443",
    "cert_file": "/etc/varwof/gateway/mgmt.pem",
    "key_file": "/etc/varwof/gateway/mgmt.key",
    "ca_file": "/etc/varwof/gateway/ca.pem"
  },
  "capreg": {
    "capability_dir": "/etc/varwof/capabilities"
  }
}
EOF

# 2. 启动
gateway-http --config gateway-http.json

# 3. 验证
curl --cert client.pem --key client.key --cacert ca.pem \
  https://localhost:443/api/healthz
```

### TCP 网关

```bash
# 映射服务器
gateway-tcp server \
  --listener "name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem"

# 客户端隧道
gateway-tcp tunnel \
  --gateway gateway-host:8443 \
  --server-cert client.pem \
  --server-key client.key \
  --ca-cert ca.pem \
  --target 10.0.0.1:3306 \
  --name db-tunnel
```

### UDP 网关

```bash
gateway-udp \
  --config gateway-udp.json
```

## 配置

### HTTP 配置

```json
{
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http2",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "/etc/varwof/gateway/ca.pem",
        "cert_file": "/etc/varwof/gateway/server.pem",
        "key_file": "/etc/varwof/gateway/server.key"
      },
      "routes": [
        {
          "path": "/api/*",
          "target": "http://backend:8080",
          "allow_roles": ["gateway:ops"],
          "allow_methods": ["GET", "POST"],
          "required_capabilities": ["read:data"],
          "upstream_tls": {
            "enabled": true,
            "ca_file": "/etc/varwof/gateway/upstream-ca.pem"
          }
        }
      ],
      "http_ext": {
        "max_body_bytes": 10485760,
        "request_timeout": "30s"
      }
    }
  ],
  "management": {
    "listen": "127.0.0.1:9443",
    "cert_file": "/etc/varwof/gateway/mgmt.pem",
    "key_file": "/etc/varwof/gateway/mgmt.key",
    "ca_file": "/etc/varwof/gateway/ca.pem"
  },
  "capreg": {
    "capability_dir": "/etc/varwof/capabilities"
  },
  "shortlived_cert": {
    "enabled": true,
    "validity": "1h",
    "renew_before": "5m"
  },
  "revoker": {
    "enabled": true
  },
  "risk_monitor": {
    "enabled": true,
    "violation_threshold": 5,
    "action": "disconnect"
  }
}
```

### TCP 配置

```json
{
  "mappings": [
    {
      "name": "db-proxy",
      "listen": ":8443",
      "target": "10.0.0.1:3306",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "ca.pem",
        "cert_file": "server.pem",
        "key_file": "server.key",
        "allow_roles": ["gateway:ops"],
        "max_conns_per_ip": 100,
        "max_conns_per_cert": 50,
        "max_total_conns": 500
      }
    }
  ],
  "mesh": {
    "enabled": true,
    "listen": ":7000",
    "peers": [
      {
        "name": "node-b",
        "address": "10.0.0.2:7000",
        "ca_cert_file": "ca.pem"
      }
    ],
    "target_allowlist": ["10.0.0.0/24"]
  },
  "management": { ... },
  "capreg": { ... }
}
```

### UDP 配置

```json
{
  "listeners": [
    {
      "name": "dtls-gw",
      "listen": ":5353",
      "target": "10.0.0.5:8080",
      "tls_mode": "dtls",
      "mtls": {
        "ca_cert_file": "ca.pem",
        "cert_file": "server.pem",
        "key_file": "server.key"
      },
      "rate_limit": {
        "requests_per_second": 1000,
        "burst": 2000
      },
      "nonce_ttl_sec": 300
    }
  ],
  "management": { ... },
  "capreg": { ... }
}
```

## 安全管道

每个连接都经过准入管道：

```
TLS 握手（客户端证书验证）
  → CRL 检查（证书是否在吊销列表中？）
  → OCSP 检查（在线状态验证）
  → RBAC 检查（证书 OU 是否匹配允许的角色？）
  → AIC 解析 + 验证（委托签名、nonce、能力）
  → 参数边界验证
  → 能力插件评估
  → 风险信号记录
  → 准入决策：允许或拒绝
```

## TLS 模式

| 模式 | 说明 |
|------|------|
| `plain` | 不使用 TLS |
| `server` | 仅服务器端 TLS |
| `mtls` | 双向 TLS（要求客户端证书） |
| `client` | 客户端 TLS（用于上游连接） |
| `mesh` | 网关间 mTLS（TCP Mesh 联邦） |
| `dtls` | Datagram TLS（UDP） |
| `quic` | QUIC 协议（UDP） |

## 管理 API

所有网关均暴露受 mTLS 保护的管理 API：

| 端点 | 说明 |
|------|------|
| `GET /healthz` | 健康检查 |
| `GET /metrics` | Prometheus 指标 |
| `POST /reload` | 热重载配置 |
| `GET /connections` | 活跃连接 |
| `POST /crl/refresh` | 强制刷新 CRL |
| `GET /audit` | 查询审计日志 |
| `GET /policy/version` | 当前策略版本 |

## 协议支持

### HTTP 网关

| 协议 | 说明 |
|------|------|
| HTTP/1.1 | 标准 HTTP |
| HTTP/2 | 多路复用流 |
| H2C | 明文 HTTP/2 |
| gRPC | 远程过程调用 |
| WebSocket | 全双工通信 |
| WebSocket Secure | 基于 TLS 的 WebSocket |
| HTTP/3 | 基于 QUIC 的 HTTP |
| QUIC | 原始 QUIC 流 |

### TCP 网关

| 功能 | 说明 |
|------|------|
| TCP 映射 | 带 mTLS 的端口转发 |
| 客户端隧道 | 用于 NAT 穿越的穿透隧道 |
| Mesh 联邦 | 跨节点状态同步 |

### UDP 网关

| 协议 | 说明 |
|------|------|
| UDP | 普通数据包转发 |
| DTLS | Datagram TLS |
| DTLS mTLS | 双向 DTLS |
| QUIC | QUIC 流 |
| QUIC mTLS | 双向 QUIC |

## 功能特性

### mTLS 认证

使用服务器证书进行双向客户端证书认证。

### CRL 实时吊销

每个监听器维护独立的 CRL 缓存，支持定期刷新和通过 API 强制重载。

### OCSP Stapling

在线证书状态验证，支持可配置的回退策略（允许/拒绝/CRL）。

### AIC 验证

解析自定义 OID 扩展，用于：
- 委托授权签名
- Nonce 防重放（5 分钟窗口）
- 能力子集验证

### RBAC

将证书 OU 字段映射到角色。支持每个监听器/每个路由的角色限制。

### 能力插件系统

两阶段路由：
1. 连接/声明层插件
2. 操作层插件

从磁盘加载已签名的规则。

### 短期证书

自动后台签发和续期，实现零停机证书切换。

### 条件吊销

任务完成后自动吊销。基于风险的吊销由 RiskMonitor 实现。

### 审计日志

JSON Lines 格式，使用 Merkle 哈希链。支持 TSA 时间戳作为外部证明。

### Prometheus 指标

每个协议的指标：
- `pki_gateway_http_*`（HTTP）
- `pki_gateway_mapping_*`（TCP）
- `pki_gateway_udp_*`（UDP）

### 热重载

SIGHUP 触发配置重载，无需重启。

## 连接限制

| 限制 | 说明 |
|------|------|
| 每 IP | 单个 IP 的最大连接数 |
| 每证书 | 每个客户端证书的最大连接数 |
| 全局 | 总连接数限制 |

## Mesh 联邦（TCP）

网关节点组成 mTLS Mesh，用于：
- 跨节点吊销广播
- 断开连接传播
- 状态同步

帧格式：`0xC0 魔术字节 + 2 字节大端序长度 + JSON`

## CLI 参考

### gateway-http

```
gateway-http [flags]
  --config <path>          JSON 配置文件
  --lang <en|zh>           UI 语言
  --port <port>            管理 API 端口
  --admin <user>           管理员用户名
  --agent-id <id>          代理标识符
  --management <addr>      管理监听地址
  --management-cert <path> 管理 TLS 证书
  --management-key <path>  管理 TLS 密钥
  --management-ca <path>   管理 CA 证书
  --version                打印版本信息
```

### gateway-tcp

```
gateway-tcp server [flags]   以映射服务器模式运行
gateway-tcp tunnel [flags]   以客户端隧道模式运行
gateway-tcp audit [flags]    查询审计日志
```

**服务器参数：**
```
  --config <path>          JSON 配置文件
  --listener <name=...>    定义 TCP 映射（可重复）
  --lang <en|zh>           UI 语言
  --port <port>            管理 API 端口
```

**隧道参数：**
```
  --gateway <host:port>    网关地址
  --server-cert <path>     服务器证书
  --server-key <path>      服务器私钥
  --ca-cert <path>         CA 证书
  --target <host:port>     后端目标
  --name <string>          隧道名称
```

**审计参数：**
```
  --dir <path>             审计日志目录
  --since <time>           开始时间过滤
  --until <time>           结束时间过滤
  --action <string>        操作类型过滤
  --limit <n>              最大条目数
  --search <keyword>       全文搜索
  --chain                  打印审计链 DAG
```

### gateway-udp

```
gateway-udp [flags]
  --config <path>          JSON 配置文件
  --listener <name=...>    定义 UDP 监听器（可重复）
  --lang <en|zh>           UI 语言
  --port <port>            管理 API 端口
```

## 内联监听器语法

```bash
# TCP
gateway-tcp server --listener "name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem"

# UDP
gateway-udp --listener "name=dns,listen=:5353,target=10.0.0.5:53,tls-mode=dtls,ca-cert=ca.pem"
```

## 与核心系统的关系

```
varwof-cli ──mTLS──> varwof-core (PKI CA)
                         │
                         ▼
varwof-gateway ──mTLS──> varwof-core (CRL/OCSP/AIC 验证)
```

网关使用核心 PKI 进行：
- 客户端证书验证（CRL + OCSP）
- AIC 签名验证
- 短期证书签发
- 审计日志 TSA 时间戳

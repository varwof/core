# 架构概览

## 系统架构

```
                           ┌─────────────────────────────────────────┐
                           │            pki (single binary)          │
                           ├─────────────────────────────────────────┤
                           │                                         │
   ┌──────────┐            │  ┌─────────┐  ┌──────────┐  ┌────────┐ │
   │ Web UI   │◄───────────┼─►│  serve   │  │  config  │  │  i18n  │ │
   │ (SPA)    │            │  │ (HTTP)  │  │          │  │        │ │
   └──────────┘            │  └────┬────┘  └──────────┘  └────────┘ │
                           │       │                                  │
   ┌──────────┐            │  ┌────▼────┐  ┌──────────┐             │
   │ CLI      │◄───────────┼─►│   ca    │  │ provisioner│            │
   │ (cobra)  │            │  │ (engine)│  │ (mTLS/   │             │
   └──────────┘            │  └────┬────┘  │  Token/  │             │
                           │       │       │  OIDC)   │             │
   ┌──────────┐            │  ┌────▼────┐  └──────────┘             │
   │ REST API │◄───────────┼─►│   db    │                           │
   │ (:8443)  │            │  │(SQLite/ │  ┌──────────┐             │
   └──────────┘            │  │ PG/MySQL│  │ routing  │             │
                           │  └─────────┘  └──────────┘             │
                           │                                         │
                           │  ┌─────────┐  ┌──────────┐             │
                           │  │  ocsp   │  │   tsa    │             │
                           │  │(RFC6960)│  │(RFC3161) │             │
                           │  └─────────┘  └──────────┘             │
                           │                                         │
                           │  ┌─────────┐  ┌──────────┐  ┌────────┐│
                           │  │  acme   │  │   scep   │  │  dns   ││
                           │  │(RFC8555)│  │(RFC8894) │  │        ││
                           │  └─────────┘  └──────────┘  └────────┘│
                           │                                         │
                           │  ┌─────────┐  ┌──────────┐  ┌────────┐│
                           │  │ pkcs7   │  │ pkcs12   │  │notifier││
                           │  │(signing)│  │ (export) │  │(webhook││
                           │  └─────────┘  └──────────┘  └────────┘│
                           │                                         │
                           │  ┌─────────┐  ┌──────────┐            │
                           │  │rbac     │  │ratelimit │            │
                           │  │(authz)  │  │(token    │            │
                           │  │         │  │ bucket)  │            │
                           │  └─────────┘  └──────────┘            │
                           └─────────────────────────────────────────┘
```

## 组件概览

### 核心引擎 (`internal/ca/`)

系统的核心。处理证书签发、续期、吊销和 CRL 生成。内存引擎提供高吞吐量读写，并异步批量持久化到数据库。

主要职责：
- 证书签名（X.509 v3）
- CSR 解析和验证
- SAN 处理（DNS、IP、URI、email）
- 名称约束执行
- 基于配置文件的扩展模板
- CRL 生成和签名
- 密钥托管加密/解密

### HTTP 服务器 (`internal/serve/`)

双路复用架构：
- **完整路复用**（`:8443`）：所有端点，包括管理操作
- **公共路复用**（`:4430`）：健康检查、CRL 分发、OCSP

中间件栈：
1. 访问日志
2. 速率限制（令牌桶）
3. RBAC 授权（简单/企业模式）
4. mTLS 客户端证书验证
5. 委托代理会话处理

### 数据库层 (`internal/db/`)

通过 `github.com/varwof/engine/db` 接口抽象。支持：
- **SQLite**：零配置，单节点（推荐用于开发/小规模）
- **PostgreSQL**：多写入者，生产级
- **MySQL/MariaDB**：多写入者，MySQL 生态系统

Schema 迁移在启动时自动应用。

### 协议服务器

#### OCSP 响应器 (`internal/ocsp/`)
- 符合 RFC 6960
- 内存缓存，可选磁盘后端持久化
- 通过 `cache_file` 支持无状态节点

#### TSA (`internal/tsa/`)
- 符合 RFC 3161
- 自动签名证书续期
- 可配置精度（秒/毫秒/微秒）

#### ACME (`internal/acme/`)
- 符合 RFC 8555（ACME v2）
- HTTP-01 和 DNS-01 验证支持
- 外部账户绑定（EAB）
- 自动续期信息（ARI，RFC 9445）
- 按 IP 速率限制

#### SCEP (`internal/scep/`)
- 符合 RFC 8894
- 企业环境设备注册

#### DNS 服务器 (`internal/dns/`)
- ACME DNS-01 验证的权威 DNS
- DoH（DNS over HTTPS）通过主端口
- DoT（DNS over TLS）在独立端口
- CERT、SRV 记录支持

### 安全组件

#### Provisioner (`internal/provisioner/`)
认证链：
1. mTLS 客户端证书
2. API Token（`X-Auth-Token`）
3. OIDC（OpenID Connect）
4. HTTP Basic Auth（后备）

#### RBAC (`auth/`)
两种模式：
- **简单**：基于 OU 的角色映射
- **企业**：完整的权限矩阵，带 CA 作用域

#### 策略签名
`authz.json` 和 `routes.json` 的 PKCS#7 签名验证。防止本地篡改，采用失败关闭行为。

### 通知

#### Webhook (`internal/notifier/`)
证书生命周期事件的 HTTP POST JSON 负载：
- 证书已签发
- 证书已吊销
- 证书即将过期（可配置阈值）

#### SMTP
相同事件的邮件通知。

### 密码学操作

#### PKCS#7 签名 (`internal/pkcs7/`)
- 分离式签名
- 嵌入式签名
- CAdES-T（时间戳）签名

#### PKCS#12 导出 (`internal/pkcs12/`)
- PFX/PKCS#12 包创建
- 密码保护的私钥

#### 密钥后端 (`internal/remotesigner/`)
可插拔远程 HSM 签名器委托，用于硬件安全模块集成。

### 身份集成

#### LDAP (`internal/ldap/`)
目录集成用于：
- 用户认证
- 从目录属性自动填充主体 DN

#### 身份桥
从身份源自动签发证书：
- LDAP 桥接（`bridge-ldap`）
- OAuth 桥接（密码授予 + userinfo）

### 监控

#### 审计日志
- Merkle 哈希链完整性
- 每日 HMAC 盐值掩码保护 PII
- 可配置的保留和清理

#### 指标
Prometheus 兼容的 `/metrics` 端点（启用后）。

#### 仪表板
证书生命周期事件的实时 SSE 推送。

## 数据流

### 证书签发

```
客户端请求 → 认证 (mTLS/Token/OIDC) → RBAC 检查 → 速率限制
    → CA 引擎 → CSR 解析 → 应用配置文件 → 签名 → 存储 (DB + Engine)
    → Webhook 通知 → 响应
```

### 证书吊销

```
吊销请求 → 认证 → RBAC 检查 → 引擎更新 (内存)
    → DB 异步持久化 → CRL 重新生成 → OCSP 缓存失效
    → Webhook 通知 → 响应
```

### 配置热重载

```
SIGHUP / 轮询定时器 → 解析 JSON → 验证 → 原子切换：
    (处理程序、DB、引擎、provisioner、路由规则、能力方案)
```

## 端口分配

| 服务 | 端口 | 协议 | 描述 |
|------|------|------|------|
| 主服务器 | `:8443` | HTTP | Web UI + REST API + TSA + OCSP + CRL + DoH |
| TLS 服务器 | `:4433` | HTTPS | mTLS 保护的端点 |
| DNS | `:53` | UDP/TCP | ACME DNS-01 + CERT + SRV |
| DoT | `:853` | TLS | DNS over TLS |
| TSA（独立） | `:3180` | HTTP | RFC 3161 时间戳 |
| OCSP（独立） | `:9080` | HTTP | RFC 6960 响应器 |

## 源码树

```
core/
├── cmd/pki/                  CLI 入口点 (cobra 命令)
│   ├── main.go               根命令、信号处理
│   ├── cmd_*.go              子命令实现
│   ├── serve.go              HTTP 服务器引导
│   └── *_test.go             测试套件
├── internal/
│   ├── ca/                   CA 签发引擎
│   ├── serve/                HTTP API 处理程序 + 中间件
│   ├── db/                   数据库抽象
│   ├── config.go             配置结构体
│   ├── acme/                 ACME v2 协议
│   ├── ocsp/                 OCSP 响应器
│   ├── tsa/                  TSA 时间戳
│   ├── dns/                  DNS 服务器
│   ├── pkcs7/                PKCS#7 签名
│   ├── pkcs12/               PFX 导出
│   ├── notifier/             Webhook 通知
│   ├── provisioner/          认证提供者
│   ├── routing/              路由规则引擎
│   ├── i18n/                 国际化 (en.json, zh.json)
│   ├── engine/               内存引擎
│   ├── secrets/              CA 密钥密码解析
│   ├── capregistry/          能力方案注册表
│   └── remotesigner/         HSM/远程签名器委托
├── auth/                     RBAC 策略、策略签名
├── deploy/                   部署脚本
└── docs/                     文档
```

## 卫星项目

| 项目 | 描述 |
|------|------|
| `varwof-gateway-tcp` | TCP 安全网关 |
| `varwof-gateway-http` | HTTP 安全网关 |
| `varwof-gateway-udp` | UDP 安全网关 |
| `varwof-protocols` | EST/SCEP/CMP 协议 |
| `pki-dns-server` | 独立 DNS 服务器 |
| `bridge-ldap` | LDAP 桥接服务 |
| `pki-pades` | PAdES PDF 签名 |
| `pki-deploy` | 部署工具 |
| `pki-webhook` | Webhook 推送服务 |
| `varwof-cli` | CLI 管理工具 |
| `user-signer` | 远程签名服务 |
| `pki-hsm-proxy` | HSM 适配器 |
| `console` | Web 控制台 |

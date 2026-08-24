# varwof REST API 文档

**Base URL**: `http://<host>:8443/api/v1`

认证方式：`X-Auth-Token: <token>` 或 `Authorization: Bearer <token>`

---

## 认证

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/users/login` | 登录获取 token | ❌ 公开 |
| GET | `/users/info` | 当前用户信息 | ✅ Token |
| GET | `/session` | 会话身份探测（用户 + 绑定证书身份，Web 用户侦测） | ✅ mTLS 证书 / Token / Cookie |
| POST | `/users/logout` | 登出吊销 token | ✅ Token |

### 登录

```bash
curl -s -X POST http://localhost:8443/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"Admin","password":"Secret123"}'
# → {"token":"...","user_id":1,"username":"Admin","role":"admin"}
```

### 当前用户

```bash
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/info
# → {"user_id":1,"username":"Admin","role":"admin"}
```

### 会话身份探测

支持完整认证链（mTLS 证书 / 网关证书透传 / token / cookie / Basic），返回当前身份
及绑定的客户端证书信息（若有）。Web 控制台启动时调用此端点侦测用户与证书身份。

```bash
# mTLS 直连（客户端证书在 TLS 层）
curl -s --cert client.pem --key client.key --cacert ca.pem \
  https://<host>:4433/api/v1/session
# → {"authenticated":true,"username":"varwof:alice:","role":"admin(agent)",
#    "cert_identity":{"serial":"...","issuer":"...","cn":"...","spki_hash":"...",
#    "principal_uid":"varwof:alice:","agent_id":"agent-1","not_after":"..."}}

# token 会话（无证书）
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/session
# → {"authenticated":true,"username":"Admin","role":"admin"}
```

`cert_identity` 仅在会话绑定到客户端证书时返回（mTLS 直连或经网关 B2 证书透传）；
token/Basic 登录无证书，仅返回 `username`/`role`。
```

---

## 用户管理

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/users` | 用户列表 | ✅ |
| POST | `/users` | 创建用户 | ✅ |
| DELETE | `/users/{id}` | 删除用户 | ✅ |
| POST | `/users/{id}/operator-cert` | 绑定操作证书（代理该用户的 CA scope） | ✅ admin |
| DELETE | `/users/{id}/operator-cert` | 解绑操作证书 | ✅ admin |

```bash
# 创建用户
curl -s -X POST http://localhost:8443/api/v1/users \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"Pass1234","role":"operator"}'

# 删除用户
curl -s -X DELETE -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/1

# 绑定操作证书（证书必须由本 PKI 签发、未过期未吊销，OU 映射到真实角色）
curl -s -X POST -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n"}'
# → {"status":"bound","scope":["VPC Client CA"]}

# 解绑
curl -s -X DELETE -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/1/operator-cert
```

> **操作证书代理（operator-cert proxy）**：给通过用户名/密码或 token 登录的用户绑定一张 CA scope 限定好的 `m-*` 管理证书后，该用户登录时以证书的 scope（SAN URI + OID 双写）作为其有效 CA scope——密码学绑定，证书到期/吊销即失去对应 CA 的权限。绑定即校验（fail-closed），过期/吊销/非本 PKI 签发的证书会立即被拒绝。

---

## Token 管理

> 权限（AUTH-005）：路由表精确门控——`GET` 需 `user:list`，`POST`/`DELETE` 需 `user:manage`。
> cert-first 体系下仅持有对应 grants 的管理证书可访问（如 `m-superadmin`）；密码/token 登录（operator）无法访问。

| 方法 | 路径 | 说明 | 认证 | 权限 |
|------|------|------|------|------|
| GET | `/tokens?user_id=N` | Token 列表 | ✅ | `user:list` |
| POST | `/tokens` | 创建 Token | ✅ | `user:manage` |
| DELETE | `/tokens/{id}` | 吊销 Token | ✅ | `user:manage` |

---

## 证书操作

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/certs` | 签发证书 | ✅ |
| POST | `/certs/upload` | 上传外部证书（如 NAS 设备证书）入库存档 | ✅ |
| GET | `/certs` | 证书列表 | ✅ |
| GET | `/certs/report.pdf` | PDF 报告 | ✅ |
| POST | `/certs/batch` | 批量签发 | ✅ |
| GET | `/cert/{ca}/{serial}` | 证书详情 | ✅ |
| POST | `/cert/{ca}/{serial}/revoke` | 吊销证书 | ✅ |
| POST | `/cert/{ca}/{serial}/renew` | 续期证书 | ✅ |
| POST | `/cert/{ca}/{serial}/export` | 导出证书 PEM | ✅ |
| POST | `/certs/revoke-by-principal` | 按 PrincipalUid 批量吊销 | ✅ |
| POST | `/certs/revoke-batch` | 批量吊销（吊销洪峰，引擎内存即真相） | ✅ |

### 签发证书

```bash
curl -s -X POST http://localhost:8443/api/v1/certs \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ca": "tls",
    "cn": "server.example.com",
    "san": "DNS:san1.example.com",
    "profile": "tls-server",
    "key_type": "ecdsa-p256",
    "validity": 365,
    "subject": "/C=CN/ST=BJ/L=Beijing/O=Acme/OU=IT/CN=server.example.com"
  }'

# 管理证书：使用 m-* profile 自动设 OU（e.g., m-admin, m-operator, m-auto-renew）
# curl -s -X POST ... -d '{"ca":"admin-ca","cn":"Alice","profile":"m-admin","validity":180}'
# → {"serial_number":"...","cert_pem":"...","key_pem":"..."}

# 带 scope 的管理员证书（m-admin/m-superadmin）：scope 写入 SAN URI + OID 扩展，
# 限定该证书只能管理指定子 CA。仅 superadmin 可任意指定 scope（防提升）。
# curl -s -X POST ... -d '{"ca":"admin-ca","cn":"Bob","profile":"m-admin","validity":180,"ca_scope":"Client CA"}'
```

#### identity-user 自动签发（身份源 → 基础身份证书）

`identity-user` profile 从配置的身份源（bridge-ldap `/api/v1/lookup` 或 bridge-oauth userinfo）自动拉取人员属性，填充证书 CN/OU/email，无需手工指定 subject。前提：`config identity.source_url` 已配置（Phase 2 身份源统一）。

```bash
curl -s -X POST http://localhost:8443/api/v1/certs \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ca": "issuing",
    "profile": "identity-user",
    "identity_username": "001",
    "identity_source": "ad-main",
    "key_type": "ecdsa-p256"
  }'
# → {"serial_number":"...","common_name":"张三","cert_pem":"...","key_pem":"..."}
# CN=张三（full_name），OU=gateway:ops（ou_from_groups 映射），email SAN=zhangsan@hospital.local
```

- `identity_username`：身份源用户名（必填，或省略 cn 由身份源决定 CN）
- `identity_source`：可选 source_tag 覆盖（默认 `config identity.source`）
- `ou_from_groups` 把身份源组映射为证书 OU（RBAC 角色）；`default_ou` 兜底；无映射时用 dept
- 禁用账号默认拒绝（403），`disabled_ok: true` 可放行
- 身份源未配置 → 400；用户未找到 → 502；身份源不可达 → 502

### 上传外部证书（NAS 等设备证书入库）

将外部签发/自签的设备证书登记进 PKI 库存用于生命周期跟踪（不持有私钥）。

```bash
curl -s -X POST http://localhost:8443/api/v1/certs/upload \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "ca_name": "NAS Devices",
    "device_type": "nas",
    "device_name": "nas1"
  }'

# → 201 {"serial_number":"...","common_name":"nas1.varwof.com","ca_name":"NAS Devices",
#        "not_before":"...","not_after":"...","fingerprint":"..."}
# 重复上传同一 Serial 返回 409；证书无效返回 400。
# profile_used 记录为 uploaded-<device_type>（如 uploaded-nas），可在证书列表/详情中检索。


### 吊销证书

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/revoke \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
# → {"status":"revoked","ca":"root","serial":"..."}
```

### 批量吊销（吊销洪峰）

批量吊销大量证书，单次请求即可完成。启用内存引擎时，整批证书在单次锁内立即置为已吊销（内存即真相，读操作立即可见），后台异步落库；非内存驻留的证书自动回退 DB 事务兜底。

```bash
curl -s -X POST http://localhost:8443/api/v1/certs/revoke-batch \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {"ca":"root","serial":"AB12","reason":"keyCompromise"},
      {"ca":"root","serial":"CD34"},
      {"ca":"issuing","serial":"EF56","reason":"cACompromise"}
    ]
  }'
# → {"status":"ok","revoked_count":3}
```

`reason` 可选，取值同单张吊销（`keyCompromise`/`cACompromise`/`affiliationChanged`/...）。

### 续期证书

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/renew \
  -H "X-Auth-Token: <token>"
# → {"serial_number":"...","cert_pem":"...","key_pem":"..."}
```

### 导出证书 PEM

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/export \
  -H "X-Auth-Token: <token>" \
  -o cert.pem
```

### 证书列表参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `ca` | string | CA 名称过滤 |
| `status` | string | V(有效) / R(吊销) / E(过期) |
| `cn` | string | 通用名称搜索 |
| `format` | string | json / csv |

---

## CA 管理

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/cas` | CA 列表 | ✅ |
| GET | `/cas/tree` | CA 树结构 | ✅ |
| GET | `/ca/{name}` | CA 详情 | ✅ |
| GET | `/ca/{name}/rotation` | CA 主密钥轮换状态（active/legacy 双签过渡信息） | ✅ |
| POST | `/ca/{name}/rotate` | CA 主密钥轮换（原子热切换 + 过渡期双签，需 superadmin/admin） | ✅ |

### CA 主密钥轮换（C7）

CA 到期前应轮换主密钥。轮换不会中断在线签发：新密钥原子生效，旧密钥在过渡期保留供已签发证书/CRL 验证。

```bash
# 查看轮换状态
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotation

# 执行轮换（提供新 CA 证书 + 私钥 PEM，inline 或文件路径）
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

响应 `{"status":"rotated","ca":"...","old_serial":"...","new_serial":"...","active":{...}}`。
服务端每 12h 检查各 CA 到期情况，临近 7 天在日志告警 `WARN serve: CA master key approaching expiry`。

---

## CRL

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/crl/{ca}` | 下载 CRL | ✅ |
| POST | `/crl/{ca}/generate` | 生成 CRL | ✅ |

---

## 交叉证书

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/cross-certs` | 列表 | ✅ |
| POST | `/cross-cert/issue` | 签发 | ✅ |
| POST | `/cross-cert/revoke` | 吊销 | ✅ |

---

## 统计与仪表盘

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/dashboard` | 完整仪表盘统计 | ✅ |
| GET | `/dashboard/events` | SSE 实时推送 | ✅ |
| GET | `/stats` | 简要统计 | ✅ |

### 仪表盘响应

```json
{
  "summary": {
    "total_certs": 100,
    "total_cas": 5,
    "valid": 85,
    "revoked": 10,
    "expired": 5,
    "expiring_30d": 3,
    "revoked_ratio": 0.1
  },
  "per_ca": [
    {"name": "root", "certs": 50, "revoked": 5, "expiring_30d": 1}
  ],
  "expiry": {
    "within_30d": 3, "within_60d": 5, "within_90d": 8,
    "within_180d": 15, "within_365d": 30, "over_365d": 39
  },
  "trends": {
    "issued_today": 2, "issued_this_week": 10,
    "issued_this_month": 25, "revoked_today": 0
  }
}
```

---

## 审计 / RA / 密钥恢复

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/audit?limit=50&offset=0` | 审计日志（`username`/`remote_addr` 默认按当日盐 HMAC 脱敏，见 `audit_salt` 配置） | ✅ |
| GET | `/ra?status=pending` | RA 请求列表 | ✅ |
| POST | `/ra` | 提交 RA 请求 | ✅ |
| POST | `/ra/{id}/approve` | 审批通过 | ✅ |
| POST | `/ra/{id}/reject` | 驳回 | ✅ |
| POST | `/keys/recover` | 恢复托管密钥 | ✅ |

---

## Webhook

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/webhooks` | 订阅列表 | ✅ |
| POST | `/webhooks` | 创建订阅 | ✅ |

---

## DNS 服务

### 概述

内置权威 DNS 服务器，用于 ACME DNS-01 挑战验证和证书分发。管理 API 通过主端口 `:8443` 访问，DNS 查询支持 DoH 和 DoT。

### 启动

```bash
varwof --config config.json serve dns
```

配置项：
| 参数 | 默认 | 说明 |
|------|------|------|
| `dns.enable` | false | 启用 DNS 服务器 |
| `dns.addr` | `:53` | DNS UDP 监听地址 |
| `dns.zone` | - | 权威区域 |
| `dns.dot_addr` | - | DoT 监听地址（如 `:853`，需证书）|
| `dns.server_cert` | - | DoT 服务器证书 PEM |
| `dns.server_key` | - | DoT 服务器密钥 PEM |
| `dns.ca_cert` | - | 客户端证书验证的 CA |
| `dns.crl_path` | - | CRL 文件路径 |
| `dns.crl_refresh` | `60s` | CRL 刷新间隔 |
| `dns.ocsp_url` | - | OCSP 响应器地址 |

### DNS 管理 API（`:8443`）

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/api/v1/dns/records` | DNS 记录列表 | Token |
| GET | `/api/v1/dns/healthz` | 健康检查 | 公开 |
| PUT | `/api/v1/dns/acme-challenge/{domain}` | 设置 ACME DNS-01 | Token |
| DELETE | `/api/v1/dns/acme-challenge/{domain}` | 清除 ACME DNS-01 | Token |
| PUT | `/api/v1/dns/cert/{domain}` | 设置 CERT 记录 | Token |
| DELETE | `/api/v1/dns/cert/{domain}` | 清除 CERT 记录 | Token |

### ACME DNS-01

```bash
# 设置
curl -X PUT http://localhost:8443/api/v1/dns/acme-challenge/example.com \
  -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  -d '{"key_auth":"..."}'

# 验证
dig @localhost -p 53 _acme-challenge.example.com TXT
```

### DNS over HTTPS (DoH)

通过主端口 `:8443` 加密查询：

```bash
curl "http://localhost:8443/api/v1/dns-query?name=example.com&type=TXT"
```

支持的类型：A, AAAA, TXT, CNAME, MX, NS, SOA, PTR, SRV, CERT, TLSA

### DNS over TLS (DoT)

```bash
# 配置
{ "dns": { "dot_addr": ":853", "server_cert": "...", "server_key": "..." } }
# 客户端：kdig @localhost -p 853 example.com TXT +tls
```

### 安全验证

管理 API 支持 mTLS + CRL + OCSP 三重验证：
- 客户端证书 (`dns.ca_cert`): TLS 握手时验证
- CRL 检查 (`dns.crl_path`): 定期刷新吊销列表
- OCSP 查询 (`dns.ocsp_url`): 实时在线状态

---


## 端口

| 服务 | 端口 | 说明 |
|------|------|------|
| `varwof serve` | `:8443` | Web UI + REST API + TSA + OCSP + CRL + DoH |
| `varwof serve dns` | `:53` | DNS UDP（ACME DNS-01）|
| `varwof serve dns` (DoT) | `:853` | DNS over TLS（需配置 `dot_addr` + 证书）|

## 协议端点（非 JSON API）

| 路径 | 方法 | 说明 |
|------|------|------|
| `/tsa` | POST | RFC 3161 时间戳 (application/timestamp-query) |
| `/ocsp` | POST/GET | RFC 6960 OCSP (application/ocsp-request) |
| `/acme/` | — | RFC 8555 ACME v2 自动签发 |
| `/acme/renewalInfo/{cert-id}` | GET | RFC 9445 ACME ARI 续期信息（cert-id = base64url(SHA-256(DER))） |
| `/scep` | — | RFC 8894 SCEP 网络设备注册 |

---

## 系统

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/healthz` | 健康检查 | ❌ 公开 |
| GET | `/readyz` | 就绪检查 | ❌ 公开 |
| GET | `/swagger/` | Swagger UI 交互文档 | ✅ readonly |
| GET | `/version` | 版本信息 | ❌ 公开 |

### Swagger UI

启动服务后浏览器打开：

```
http://localhost:8443/swagger/
```

---

## 国际化

Web UI 支持中英文双语。通过以下方式切换语言：
- **自动**：浏览器 `Accept-Language` 头
- **手动**：URL 参数 `?lang=zh` 或 `?lang=en`

CLI 消息语言由配置文件 `locale` 字段控制。

---

## 错误响应格式

```json
{
  "code": 401,
  "message": "unauthorized",
  "detail": "optional detail"
}
```

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 401 | 未认证/token 无效 |
| 403 | 权限不足 |
| 404 | 资源不存在 |
| 500 | 服务端错误 |

---

## CLI 命令

| 命令 | 说明 |
|------|------|
| `varwof report --template soc2\|pci\|nist\|iso --out report.pdf --ca name` | 生成合规报告 PDF（SOC 2 / PCI DSS v4.0 / NIST SP 800-53 / ISO 27001） |

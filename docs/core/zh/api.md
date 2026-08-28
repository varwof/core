# REST API 参考

**基础 URL**：`http://<host>:8443/api/v1`

**认证**：`X-Auth-Token: <token>` 或 `Authorization: Bearer <token>`

---

## 认证

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| POST | `/users/login` | 登录获取令牌 | 公开 |
| GET | `/users/info` | 当前用户信息 | Token |
| GET | `/session` | 会话身份探测 | mTLS/Token/Cookie |
| POST | `/users/logout` | 登出并吊销令牌 | Token |

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

返回当前身份及绑定的证书信息（如有）。

```bash
# mTLS 连接
curl -s --cert client.pem --key client.key --cacert ca.pem \
  https://<host>:4433/api/v1/session

# Token 会话
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/session
```

---

## 用户管理

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/users` | 列出用户 | Token |
| POST | `/users` | 创建用户 | Token |
| DELETE | `/users/{id}` | 删除用户 | Token |
| POST | `/users/{id}/operator-cert` | 绑定操作员证书 | admin |
| DELETE | `/users/{id}/operator-cert` | 解绑操作员证书 | admin |

### 创建用户

```bash
curl -s -X POST http://localhost:8443/api/v1/users \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"Pass1234","role":"operator"}'
```

角色：`admin`、`operator`、`auditor`、`readonly`

### 绑定操作员证书

```bash
curl -s -X POST -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n"}'
# → {"status":"bound","scope":["VPC Client CA"]}
```

---

## 令牌管理

| 方法 | 路径 | 描述 | 认证方式 | 权限 |
|------|------|------|---------|------|
| GET | `/tokens?user_id=N` | 列出令牌 | Token | `user:list` |
| POST | `/tokens` | 创建令牌 | Token | `user:manage` |
| DELETE | `/tokens/{id}` | 吊销令牌 | Token | `user:manage` |

---

## 证书操作

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| POST | `/certs` | 签发证书 | Token |
| POST | `/certs/upload` | 上传外部证书 | Token |
| GET | `/certs` | 列出证书 | Token |
| GET | `/certs/report.pdf` | PDF 报告 | Token |
| POST | `/certs/batch` | 批量签发 | Token |
| GET | `/cert/{ca}/{serial}` | 证书详情 | Token |
| POST | `/cert/{ca}/{serial}/revoke` | 吊销证书 | Token |
| POST | `/cert/{ca}/{serial}/renew` | 续期证书 | Token |
| POST | `/cert/{ca}/{serial}/export` | 导出证书 PEM | Token |
| POST | `/certs/revoke-by-principal` | 按 PrincipalUid 批量吊销 | Token |
| POST | `/certs/revoke-batch` | 批量吊销 | Token |

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
```

### 上传外部证书

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
```

### 吊销证书

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/revoke \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
```

### 批量吊销

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
```

### 续期证书

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/renew \
  -H "X-Auth-Token: <token>"
```

### 证书列表参数

| 参数 | 类型 | 描述 |
|------|------|------|
| `ca` | string | 按 CA 名称过滤 |
| `status` | string | V(有效) / R(已吊销) / E(已过期) |
| `cn` | string | 按通用名称搜索 |
| `format` | string | json / csv |

---

## CA 管理

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/cas` | 列出 CA | Token |
| GET | `/cas/tree` | CA 树结构 | Token |
| GET | `/ca/{name}` | CA 详情 | Token |
| GET | `/ca/{name}/rotation` | CA 密钥轮换状态 | Token |
| POST | `/ca/{name}/rotate` | CA 主密钥轮换 | admin |

### CA 主密钥轮换

```bash
# 检查轮换状态
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotation

# 执行轮换
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

---

## CRL

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/crl/{ca}` | 下载 CRL | Token |
| POST | `/crl/{ca}/generate` | 生成 CRL | Token |

---

## 交叉证书

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/cross-certs` | 列出 | Token |
| POST | `/cross-cert/issue` | 签发 | Token |
| POST | `/cross-cert/revoke` | 吊销 | Token |

---

## 统计与仪表板

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/dashboard` | 完整仪表板统计 | Token |
| GET | `/dashboard/events` | SSE 实时推送 | Token |
| GET | `/stats` | 汇总统计 | Token |

### 仪表板响应

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

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/audit?limit=50&offset=0` | 审计日志 | Token |
| GET | `/ra?status=pending` | 列出 RA 请求 | Token |
| POST | `/ra` | 提交 RA 请求 | Token |
| POST | `/ra/{id}/approve` | 批准请求 | Token |
| POST | `/ra/{id}/reject` | 拒绝请求 | Token |
| POST | `/keys/recover` | 恢复托管密钥 | Token |

---

## Webhook

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/webhooks` | 列出订阅 | Token |
| POST | `/webhooks` | 创建订阅 | Token |

---

## DNS 服务

### DNS 管理 API（`:8443`）

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/api/v1/dns/records` | 列出 DNS 记录 | Token |
| GET | `/api/v1/dns/healthz` | 健康检查 | 公开 |
| PUT | `/api/v1/dns/acme-challenge/{domain}` | 设置 ACME DNS-01 | Token |
| DELETE | `/api/v1/dns/acme-challenge/{domain}` | 清除 ACME DNS-01 | Token |
| PUT | `/api/v1/dns/cert/{domain}` | 设置 CERT 记录 | Token |
| DELETE | `/api/v1/dns/cert/{domain}` | 清除 CERT 记录 | Token |

### ACME DNS-01

```bash
# 设置验证
curl -X PUT http://localhost:8443/api/v1/dns/acme-challenge/example.com \
  -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  -d '{"key_auth":"..."}'

# 验证
dig @localhost -p 53 _acme-challenge.example.com TXT
```

### DNS over HTTPS (DoH)

```bash
curl "http://localhost:8443/api/v1/dns-query?name=example.com&type=TXT"
```

支持的类型：A、AAAA、TXT、CNAME、MX、NS、SOA、PTR、SRV、CERT、TLSA

---

## 协议端点

| 路径 | 方法 | 描述 |
|------|------|------|
| `/tsa` | POST | RFC 3161 时间戳（application/timestamp-query） |
| `/ocsp` | POST/GET | RFC 6960 OCSP（application/ocsp-request） |
| `/acme/` | — | RFC 8555 ACME v2 |
| `/acme/renewalInfo/{cert-id}` | GET | RFC 9445 ACME ARI |
| `/scep` | — | RFC 8894 SCEP |

---

## 系统

| 方法 | 路径 | 描述 | 认证方式 |
|------|------|------|---------|
| GET | `/healthz` | 健康检查 | 公开 |
| GET | `/readyz` | 就绪检查 | 公开 |
| GET | `/swagger/` | Swagger UI | readonly |
| GET | `/version` | 版本信息 | 公开 |

---

## 端口分配

| 服务 | 端口 | 描述 |
|------|------|------|
| `pki serve` | `:8443` | Web UI + REST API + TSA + OCSP + CRL + DoH |
| `pki serve dns` | `:53` | DNS UDP（ACME DNS-01） |
| `pki serve dns` (DoT) | `:853` | DNS over TLS |

---

## 错误响应格式

```json
{
  "code": 401,
  "message": "unauthorized",
  "detail": "optional detail"
}
```

| 状态码 | 描述 |
|--------|------|
| 200 | 成功 |
| 400 | 无效请求参数 |
| 401 | 未认证/无效令牌 |
| 403 | 权限不足 |
| 404 | 资源未找到 |
| 500 | 服务器错误 |

---

## 国际化

Web UI 支持中文和英文：
- **自动**：浏览器 `Accept-Language` 头
- **手动**：URL 参数 `?lang=zh` 或 `?lang=en`

CLI 消息语言由配置中的 `locale` 字段控制。

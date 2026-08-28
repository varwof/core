# RBAC 与权限系统

## 概览

varwof PKI 实现了基于角色的访问控制（RBAC）系统，包含两种模式：
- **简单**：基于角色，CA 作用域可选
- **企业**：基于角色 + 强制 CA 作用域

## 认证链

每个请求通过以下方法之一进行认证（按优先级排列）：

```
1. mTLS 客户端证书
   ├── AIC 证书（具有 AIC 扩展）→ 委托认证验证
   ├── 可信网关委托 (B2: X-Client-Cert-DER, B1: X-Agent-User)
   ├── 标准管理证书 → 从 OU 获取角色，从 PA 扩展获取权限
   └── 委托代理证书 → 需要有效的 X-Agent-TTL 头

2. X-Auth-Token 头 / pki_token cookie → 数据库查找 → "operator" 角色

3. Authorization: Bearer → 与 X-Auth-Token 相同

4. Authorization: Basic → Argon2id 密码验证 + 缓存
```

**证书优先授权模型**：
- mTLS 证书：权限**仅**来自证书的 PrincipalAuthorization (PA) 扩展
- 非证书认证（token/basic/cookie）：始终分配 "operator" 角色
- AIC 证书：`权限 = PA 授权 ∩ AIC 能力`

## 角色

### 核心角色

| 角色 | 配置文件 | 作用域 | 描述 |
|------|---------|--------|------|
| `superadmin` | `m-superadmin` | `["Management CA"]` | 完全访问权限，包括 CA 创建/删除 |
| `admin` | `m-admin` | — | 除 CA/用户管理外的所有权限 |
| `operator` | — | — | 证书签发/吊销/续期、CRL、日志 |
| `revoker` | `m-revoker` | `["*"]` | 仅证书吊销 |
| `auditor` | `m-auditor` | — | 只读：日志、报告、证书 |
| `readonly` | `m-readonly` | — | 最小只读访问权限 |
| `console` | — | — | Web 控制台操作 |
| `auto-renew` | `m-auto-renew` | — | 仅证书续期 |
| `reporter` | `m-reporter` | — | 报告生成和导出 |
| `agent` | `agent-proxy` | — | 具有网关能力的 AI 代理 |

### 网关角色（命名空间 `gateway:`）

| 角色 | 授权 |
|------|------|
| `gateway-admin` | `gateway:*`（所有网关操作） |
| `gateway-reader` | `SELECT:*`（只读） |
| `gateway-writer` | `SELECT:*`、`INSERT:*`、`UPDATE:*` |
| `gateway-ops` | `SELECT:*`、`INSERT:*`、`UPDATE:*`、`DELETE:*` |
| `gateway-ddl` | 所有 DML + `DDL:*` |

## 权限

32 个权限常量，格式为 `resource:action`：

| 资源 | 操作 |
|------|------|
| `ca` | `create`、`delete`、`list`、`info` |
| `cert` | `issue`、`revoke`、`renew`、`list`、`export`、`batch` |
| `crl` | `generate` |
| `user` | `manage`、`list`、`revoke-all` |
| `log` | `read`、`export` |
| `report` | `view`、`export`、`generate` |
| `config` | `read`、`write` |
| `ra` | `approve`、`reject` |
| `cross-cert` | `issue`、`revoke` |
| `webhook` | `manage` |
| `key` | `recover` |
| `dns` | `manage` |
| `trust` | `import`、`list`、`delete` |
| `agent` | `manage` |
| `swagger` | `view` |
| `web` | `view` |

## 权限矩阵

| 角色 | ca:create | ca:delete | cert:issue | cert:revoke | cert:renew | user:manage | config:write | log:read |
|------|-----------|-----------|------------|-------------|------------|-------------|--------------|----------|
| superadmin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| admin | — | — | ✓ | ✓ | ✓ | — | — | ✓ |
| operator | — | — | ✓ | ✓ | ✓ | — | — | ✓ |
| revoker | — | — | — | ✓ | — | — | — | ✓ |
| auditor | — | — | — | — | — | — | — | ✓ |
| readonly | — | — | — | — | — | — | — | — |
| auto-renew | — | — | — | — | ✓ | — | — | ✓ |
| reporter | — | — | — | — | — | — | — | ✓ |

## 授权模式

### 简单模式

```json
{
  "rbac": {
    "enabled": true,
    "mode": "simple"
  }
}
```

- 仅基于角色的权限检查
- 除非用户有绑定作用域，否则**不强制** CA 作用域
- 没有作用域的用户允许所有操作
- 适用于单 CA 部署

### 企业模式

```json
{
  "rbac": {
    "enabled": true,
    "mode": "enterprise"
  }
}
```

- 基于角色的权限检查 + 强制 CA 作用域
- **没有作用域的用户被拒绝**（失败关闭）
- CA 作用域从操作员证书、数据库或配置中提取
- 多 CA 部署需要此模式

## CA 作用域

CA 作用域限制用户可以操作哪些证书颁发机构。

### 作用域来源（按顺序评估）

1. **操作员证书（密码学绑定）**
   - SAN URI 匹配 `urn:pki:ca:<scope>`
   - OID 扩展 `1.3.6.1.4.1.66257.1.5.1`
   - 必须通过完整验证（有效、未吊销、由此 PKI 签发）

2. **数据库 `ca_scopes` 列**
   - 按用户存储的逗号分隔作用域列表

3. **配置文件 `rbac.ca_scopes`**
   ```json
   {
     "rbac": {
       "ca_scopes": {
         "operator": ["Client CA", "VPN CA"],
         "admin": ["*"]
       }
     }
   }
   ```

4. **策略 `scope` 字段**（在 `authz.json` 中）
   ```json
   {
     "roles": {
       "superadmin": { "scope": ["Management CA"] },
       "revoker": { "scope": ["*"] }
     }
   }
   ```

### 作用域解析逻辑

1. 框架操作（`ca:create`/`ca:delete`）免作用域（仅 superadmin）
2. 只读角色（`auditor`、`readonly`、`reporter`）始终允许
3. 带有 `scope: ["*"]` 的角色始终允许
4. 未定义作用域：
   - 简单模式 → 允许
   - 企业模式 → 拒绝
5. 作用域包含 `*` → 允许
6. 从请求中提取 CA 名称（路径、查询或 POST 正文）
7. 与作用域列表进行精确字符串匹配
8. 配置文件后备匹配
9. 无匹配 → 拒绝

### CA 名称提取

| 来源 | 模式 |
|------|------|
| URL 路径 | `/api/v1/cert/{ca}/{serial}/revoke` |
| 查询参数 | `?ca=<name>` |
| POST/PUT 正文 | `{"ca": "<name>"}`（最多窥视 64KB） |

## 路由级授权

路由规则在 `routes.json`（或嵌入默认值）中定义：

```json
{
  "version": "v1",
  "public_paths": ["/healthz", "/readyz", "/metrics"],
  "rules": [
    {
      "method": "POST",
      "path": "/api/v1/certs",
      "permission": "cert:issue",
      "description": "签发证书",
      "ca_scope": true,
      "require_role": ["superadmin", "admin"],
      "allow_aic": false
    }
  ]
}
```

### RouteRule 字段

| 字段 | 类型 | 描述 |
|------|------|------|
| `method` | string | HTTP 方法（`*` 表示任意） |
| `path` | string | URL 模式（`/api/v1/cert/{ca}/{serial}`） |
| `permission` | string | 所需权限 |
| `ca_scope` | bool | 启用 CA 作用域检查 |
| `require_role` | []string | 附加角色白名单 |
| `allow_aic` | *bool | 允许 AIC 代理访问（nil = true） |
| `max_validity` | string | 签发的最大证书有效期 |

### 路径模式匹配

| 模式 | 优先级 | 示例 |
|------|--------|------|
| 字面量 | 1000+ | `/api/v1/certs` |
| 参数 | 600+ | `/api/v1/cert/{ca}/{serial}` |
| 单通配符 | 500+ | `/api/v1/ca/*` |
| 双通配符 | 400+ | `/api/**` |

### 公共路径（绕过所有认证）

- `/healthz`、`/readyz`、`/metrics`
- `/api/v1/users/login`、`/api/v1/users/info`、`/api/v1/users/logout`
- `/api/v1/session`、`/api/v1/version`
- `/tsa`、`/ocsp`、`/acme/`

## 操作员证书绑定

将管理证书绑定到用户账户以进行密码学作用域定义。

### 绑定

```bash
# CLI
pki user bind-operator-cert --username operator1 --cert operator.pem

# API
curl -X POST -H "X-Auth-Token: <token>" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n..."}'
```

### 证书验证

绑定的证书必须满足以下所有条件：

1. 有效的 PEM，可解析的 X.509
2. 管理证书（DigitalSignature + ClientAuth + 有效 OU）
3. OU 映射到真实角色
4. 在 NotBefore/NotAfter 时间窗口内
5. 由此 PKI 签发（数据库记录存在）
6. 未吊销（状态 "V"）

如果验证失败，认证失败（无静默降级）。

### 作用域推导

```
绑定的操作员证书 → ExtractAdminScope(cert)
  → SAN URI: urn:pki:ca:<scope>
  → OID 扩展: 1.3.6.1.4.1.66257.1.5.1
  → 覆盖数据库 ca_scopes
```

作用域缓存 30 秒（最多 4096 条目）。

## 策略文件签名

策略文件（`authz.json`、`routes.json`）可以使用 PKCS#7 分离签名进行签名。

### 配置

```json
{
  "policy_signing": {
    "enabled": true,
    "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
    "require_admin_ou": true,
    "require": true,
    "sig_suffix": ".sig"
  }
}
```

### 签名

```bash
# CLI
pki policy sign --file authz.json --cert admin.pem --key admin.key --out authz.json.sig

# varwof-cli
varwof-cli config.json policy sign --file authz.json --cert admin.pem --key admin.key
```

### 验证

1. PKCS#7 分离签名验证
2. Admin OU 检查（`admin` 或 `gateway:admin`）
3. 对配置的 CA 信任池进行链验证
4. 失败关闭：缺少/无效签名拒绝加载

## HTTP 中间件栈

```
请求
  │
  ▼
1. 正文大小限制 (10MB)
  │
  ▼
2. 速率限制（按 IP 令牌桶）
  │
  ▼
3. 公共路径检查 → 绕过
  │
  ▼
4. TSA/OCSP 协议分发
  │
  ▼
5. 路由规则引擎
   ├── CORS 检查
   ├── authenticate()
   │   ├── mTLS 证书
   │   ├── Token/Cookie
   │   └── Basic auth (Argon2id)
   ├── require_role 检查
   ├── 权限检查 (user.HasPerm)
   ├── CA 作用域检查（企业模式）
   ├── AIC 身份检查
   └── 将 AuthUser 存入上下文
  │
  ▼
6. 处理程序执行
```

## 委托代理会话

| 控制项 | 描述 |
|--------|------|
| `X-Agent-TTL` 头 | 要求 RFC3339 未来时间戳 |
| 最大 TTL | `serve.agent_session_max_ttl`（默认 24h） |
| 禁用 | 设置 `agent_session_max_ttl = "0"` |
| 可信网关 | `serve.trusted_gateway_ous`（空 = 拒绝所有） |

## 命名空间系统

| 命名空间 | 前缀 | 角色 |
|----------|------|------|
| 核心 | （无） | `admin`、`operator`、`auditor` 等 |
| 网关 | `gateway:` | `gateway-admin`、`gateway-reader` 等 |
| Web | `web:` | 保留给 Web 控制台 |

通配符匹配：`gateway:*` 匹配任何网关角色，`*` 全局匹配。

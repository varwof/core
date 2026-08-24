# varwof 配置参考

配置文件是一个 JSON 文档，在启动时加载。
默认位置：`/etc/varwof/core/pki.json`（Linux）或 `%PROGRAMDATA%/varwof/core/pki.json`（Windows）。

使用以下命令生成示例：

```bash
varwof init-config > pki.json
```

---

## 顶层字段

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `db` | string | `/var/lib/pki/pki.db` | 数据库路径（推荐 SQLite；`db.dialect` 可选 PG/MySQL，社区维护） |
| `db.dialect` | string | `"sqlite3"` | SQL 方言驱动：`"sqlite3"`（推荐）、`"pgx"`（PostgreSQL，社区维护）、`"mysql"`（MySQL/MariaDB，社区维护） |
| `tsa` | object | 见下文 | 时间戳服务设置 |
| `ocsp` | object | 见下文 | 在线证书状态协议设置 |
| `cas` | object | 见下文 | CA 证书/密钥定义 |
| `serve` | object | 见下文 | HTTP/HTTPS 服务器设置 |
| `defaults` | object | 见下文 | 证书操作默认值 |
| `crl` | object | 见下文 | 证书吊销列表设置 |
| `webhook` | object | 见下文 | 事件通知 Webhook |
| `key_escrow` | object | 见下文 | 密钥托管（管理员恢复） |
| `ct_log` | object | 见下文 | 证书透明度日志 |
| `ldap` | object | 见下文 | LDAP 目录集成 |
| `identity` | object | `null` | 身份源 → 证书自动化（identity-user profile，见下文）|
| `acme` | object | 见下文 | ACME v2 协议设置 |
| `scep` | object | 见下文 | SCEP 协议设置 |
| `ra` | object | 见下文 | 注册机构设置 |
| `web` | object | 见下文 | Web UI 设置（含语言）|
| `locale` | string | `"en"` | 界面语言（`en` 或 `zh`），空=自动检测 |
| `key_backend` | object | `null` | 远程 HSM 签名后端（见下文）|
| `rate_limit` | object | 见下文 | API 速率限制 |
| `engine` | object | `null` | 内存引擎（高性能签发/查询；nil=不启用，见下文）|
| `record_buffer` | object | 见下文 | 批量落库缓冲（引擎未启用时的写加速，见下文）|
| `authorization_file` | string | `""` | 授权策略文件路径（authz.json，OU→角色映射 + 权限矩阵）|
| `routes_file` | string | `""` | URL 级路由权限规则文件路径（routes.json）；为空时默认 `<config_dir>/routes.json` |
| `policy_signing` | object | `null` | 策略文件（authz.json / routes.json）PKCS#7 签名校验配置（见下文）|

---

## `serve` — HTTP/HTTPS 服务器

控制内置 HTTP 服务器及可选的 HTTPS 服务器。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `addr` | string | `:4430` | HTTP 监听地址（证书分发，始终启用） |
| `tls_addr` | string | `""` | HTTPS 监听地址（可选，独立端口） |
| `tls_cert` | string | `""` | TLS 证书 PEM 文件路径 |
| `tls_key` | string | `""` | TLS 私钥 PEM 文件路径 |
| `static` | string | `/etc/varwof/core/www/pki` | Web UI 静态文件目录 |
| `auth_username` | string | `""` | 受保护端点的 HTTP 基本认证用户名 |
| `auth_password` | string | `""` | 受保护端点的 HTTP 基本认证密码 |
| `reload_poll_interval` | string | `10s` | 配置文件热重载轮询间隔（例如 `10s`、`30s`） |
| `shutdown_timeout` | string | `10s` | 优雅关闭超时（例如 `10s`、`30s`） |
| `log_format` | string | `text` | 结构化日志格式：`text`（键值对文本）或 `json`（JSON Lines，便于 SIEM/日志采集） |
| `log_dest` | string | `stderr` | 日志输出目标：`stderr`（默认）、`file:/path/to/pki.log`（追加写入文件）、`syslog`（本地 syslog `/dev/log` 或 UDP `localhost:514`，程序名 `varwof-core`）。格式不受影响；Syslog 目标会自动把日志行发往系统日志服务 |
| `agent_session_max_ttl` | string | `24h` | Delegated-Agent 委派会话最长时限。客户端必须提供 `X-Agent-TTL`（RFC3339），缺失/已过期/超过该窗口一律拒绝；`0` 完全禁用委派会话 |
| `trusted_gateway_ous` | array | `[]` | 可信网关服务证书 OU 列表。仅这些 OU 的 mTLS 证书可透传委派身份：`X-Client-Cert-DER`（B2 证书透传，推荐，核心按证书查 DB 恢复 principal/吊销/权限）或 `X-Agent-User`（B1，降级兑底，无证书身份）。为空则拒绝一切网关断言的委派请求。直连客户端无网关 OU 无法伪造 |
| `audit_salt` | object | 见下 | 审计日志 PII 加盐脱敏（每日换盐） |
| `audit_salt.enabled` | bool | `true` | 是否对审计日志的 `username`/`remote_addr` 做每日盐 HMAC 脱敏。为 `false` 时回退明文（旧行为） |
| `audit_salt.retention_days` | int | `365` | 每日盐保留天数。超过该期限后当日盐被自动删除，当日被脱敏的用户身份永久不可逆（满足 GDPR 存储最小化、网络安全法日志留存等合规要求）；Merkle 哈希链对脱敏值的可验证性不受影响 |
| `audit_salt.cleanup_interval` | string | `24h` | 扫描并清除过期盐的周期（例如 `24h`） |
| `audit_verify` | object | 见下 | 审计 Merkle 链自动完整性校验（AUTH-016） |
| `audit_verify.enabled` | bool | `true` | 定时重算审计日志哈希链，链断裂（日志被删改）时告警。设为 `false` 关闭自动校验 |
| `audit_verify.interval` | string | `24h` | 链校验周期（例如 `1h`、`24h`）。校验需全量读取审计日志，超大日志请放宽周期 |
| `da_max_timestamp_skew` | string | `30s` | DelegationAuthorization 签名时间戳新鲜度窗口（`|now - timestamp|` 上限）。签发 AIC/agent-proxy 证书时校验，超窗拒绝（403 `api.da_timestamp_stale`）——DA 签名后拖延太久才提交签发视为可疑（重放/盗签）。设为 `"0"` 禁用该防线 |

---

## `defaults` — 证书默认值

当未通过 CLI 标志显式指定时应用的默认值。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `ca` | string | `issuing` | 签名操作的默认 CA 名称 |
| `profile` | string | `tls-server` | 默认证书模板：`root-ca`、`sub-ca`、`tls-server`、`tls-client`、`ocsp-signer`、`timestamp`、`codesigning`、`email`、`document` |
| `key_type` | string | `ecdsa-p256` | 默认密钥类型：`ecdsa-p256`、`ecdsa-p384`、`ed25519`、`rsa-2048`、`rsa-4096` |
| `hash` | string | `sha256` | 默认哈希算法：`sha256`、`sha384`、`sha512` |
| `default_country` | string | `CN` | 新证书的默认主题国家/地区 |
| `default_org` | string | `example.com` | 新证书的默认主题组织 |
| `cert_validity` | string | `2160h` | 已签发证书的默认有效期（例如 `168h` = 7 天，`2160h` = 90 天） |
| `ocsp_url` | string | `""` | 已签发证书 AIA 扩展中的默认 OCSP 响应器 URL |
| `issuer_url` | string | `""` | AIA 扩展中的默认 caIssuers URL（指向签发 CA 证书） |
| `issuer_alt_names` | []string | `[]` | 签发者备用名称条目（RFC 5280 2.5.29.18），例如 `["DNS:ca.example.com","URI:https://ca.example.com"]` |
| `subject_info_access` | []string | `[]` | 主体信息访问条目（RFC 5280 1.3.6.1.5.5.7.1.11），例如 `["ocsp:http://ocsp.example.com","ca_repository:http://ca.example.com","time_stamping:http://tsa.example.com"]` |
| `policy_oids` | []string | `[]` | 证书策略 OID（RFC 5280 2.5.29.32），例如 `["2.16.840.1.101.3.2.1.48.1"]` |
| `policy_mappings` | []string | `[]` | 策略映射（RFC 5280 2.5.29.33，仅 CA 证书），每项格式 `issuerPolicy:subjectPolicy`，例如 `["2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2"]` |
| `require_explicit_policy` | int | `0` | 策略约束 explicitPolicyIndicator（RFC 5280 2.5.29.36，仅 CA 证书）；证书链中跳过策略的中间 CA 数量上限，`0` 表示启用但必须显式匹配策略 |
| `inhibit_policy_mapping` | int | `0` | 策略约束 inhibitPolicyMapping（RFC 5280 2.5.29.36，仅 CA 证书）；禁止策略映射的中间 CA 数量上限 |
| `inhibit_any_policy` | int | `0` | 抑制 anyPolicy（RFC 5280 2.5.29.54，仅 CA 证书）；忽略 anyPolicy 的中间 CA 数量上限 |
| `report_max_rows` | int | `5000` | PDF 报告最大证书行数，超过此数量将截断并提示 |
| `agent_proxy_max_validity` | string | `1h` | agent-proxy / authorized 模式 AIC 证书的有效期上限（≤24h），例如 `6h`；配置超过 24h 将被忽略回退默认 1h |

---

## `acme` — ACME v2 协议

自动证书管理环境（RFC 8555）。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `enable` | bool | `false` | 启用 ACME v2 协议支持 |
| `directory` | string | `/acme` | ACME 端点的 URL 路径前缀 |
| `ca_name` | string | `issuing` | 用于签署 ACME 签发证书的 CA |
| `default_key_type` | string | `ecdsa-p256` | ACME 签发的终端实体证书的密钥类型 |
| `default_hash` | string | `sha256` | ACME 签发证书的哈希算法 |
| `authz_expiry` | string | `24h` | 授权有效期 |
| `order_expiry` | string | `168h` | 订单有效期（7 天） |
| `cert_validity` | string | `2160h` | 证书有效期（90 天） |
| `http01_timeout` | string | `10s` | HTTP-01 挑战获取超时 |
| `dns01_timeout` | string | `10s` | DNS-01 挑战查询超时 |
| `external_account_required` | bool | `false` | 是否要求外部账户绑定（EAB） |
| `external_account_keys` | array | `[]` | EAB 密钥对列表（见下表） |
| `renewal_info_url` | string | `""` | ACME ARI（RFC 9445）`renewalInfo` 端点返回的可选 `explanationURL` |
| `rate_limit` | object | `null` | 速率限制配置（见下表） |

### `acme.external_account_keys[]`

| 字段 | 类型 | 描述 |
|---|---|---|
| `key_id` | string | EAB 密钥标识符（kid） |
| `hmac_key` | string | HMAC-SHA256 密钥（Base64 编码） |
| `description` | string | 可选描述 |

### `acme.rate_limit`

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `new_account_rps` | float | `0` | 新账户每 IP 每秒请求数（0=不限制） |
| `new_order_rps` | float | `0` | 新订单每 IP 每秒请求数 |
| `challenge_rps` | float | `0` | 挑战查询每 IP 每秒请求数 |
| `burst` | int | `0` | 令牌桶突发大小（0=取 RPS 值） |

---

## `scep` — SCEP 协议

简单证书注册协议（RFC 8894）。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `enable` | bool | `false` | 启用 SCEP 支持 |
| `ca_name` | string | `""` | 用于签署 SCEP 签发证书的 CA |
| `cert_validity` | string | `8760h` | 证书有效期（365 天） |

---

## `tsa` — 时间戳服务

RFC 3161 时间戳协议服务器。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `addr` | string | `:3180` | TSA 监听地址 |
| `signer_cert` | string | `/etc/varwof/core/tsa-signer/tsa-signer.pem` | TSA 签名者证书 PEM 路径 |
| `signer_key` | string | `/etc/varwof/core/tsa-signer/tsa-signer.key` | TSA 签名者私钥 PEM 路径 |
| `chain` | string | `/etc/varwof/core/tsa/certs/ca.pem` | 可选的中继链 PEM 路径 |
| `tsa_policy` | string | `""` | TSA 策略 OID（例如 `1.2.3.4.5`） |
| `ordering` | bool | `false` | 在 TSTInfo 中设置 ordering 标志 |
| `accuracy_seconds` | int | `0` | 精度（秒）（1-999） |
| `accuracy_millis` | int | `0` | 精度（毫秒）（1-999） |
| `accuracy_micros` | int | `0` | 精度（微秒）（1-999） |

---

## `ocsp` — OCSP 响应器

在线证书状态协议（RFC 6960）响应器。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `addr` | string | `:9080` | OCSP 响应器监听地址 |
| `signer_cert` | string | `/etc/varwof/core/ocsp/ocsp.pem` | OCSP 响应器证书 PEM 路径 |
| `signer_key` | string | `/etc/varwof/core/ocsp/ocsp.key` | OCSP 响应器私钥 PEM 路径 |
| `next_update` | string | `""` | OCSP 响应 nextUpdate 时长（例如 `4h`、`24h`） |
| `cache_size` | int | `0` | OCSP 响应缓存最大条目数（0 = 禁用） |
| `cache_ttl` | string | `1h` | OCSP 响应缓存 TTL（例如 `1h`、`30m`） |
| `cache_file` | string | `""` | 持久化响应缓存文件；设置后以磁盘缓存替代进程内缓存，启动时加载、每次响应后原子写盘（支持无状态 OCSP 节点：冷启动/重启不压共享 CA 库，甚至可不连库） |

---

## `crl` — 证书吊销列表

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `validity_days` | int | `30` | CRL 有效期（天） |
| `output_dir` | string | `""` | 发布 CRL 文件供下载的目录 |
| `crl_base_url` | string | `""` | CRL 分发点基础 URL（同时也用作已签发证书中的 CRLDP） |
| `auto_renew` | string | `""` | CRL 自动续期间隔（例如 `24h`）。需要 `--reload` 标志。 |

---

## `cas` — 证书颁发机构

CA 名称到其证书和密钥路径的映射。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `<name>.cert` | string | — | CA 证书 PEM 文件路径 |
| `<name>.key` | string | — | CA 私钥 PEM 文件路径 |
| `<name>.chain` | string | `""` | 可选的中继链 PEM 文件路径 |

默认 CA：

```json
"cas": {
  "root":    { "cert": "/etc/varwof/core/root/certs/ca.pem",    "key": "/etc/varwof/core/root/private/ca.key" },
  "issuing": { "cert": "/etc/varwof/core/issuing/certs/ca.pem", "key": "/etc/varwof/core/issuing/private/ca.key" },
  "tsa":     { "cert": "/etc/varwof/core/tsa/certs/ca.pem",     "key": "/etc/varwof/core/tsa/private/ca.key" }
}
```

---

## `webhook` — 事件通知

在证书生命周期事件（签发、吊销、过期）发生时发送 HTTP POST JSON 负载。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `url` | string | `""` | 主要 Webhook 目标 URL |
| `timeout` | string | `10s` | Webhook 投递的 HTTP POST 超时 |
| `expiry_check_interval` | string | `24h` | 证书过期检查间隔 |
| `expiry_thresholds` | []int | `[30, 7, 1]` | 过期前发送预警的天数（支持多个阈值） |

---

## `key_escrow` — 密钥恢复

允许持有托管私钥的管理员解密已归档的证书私钥。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `admin_public_key` | string | `""` | 用于密钥托管的管理员 RSA 公钥 PEM 文件路径 |

---

## `ct_log` — 证书透明度

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `url` | string | `""` | 用于提交的证书透明度日志 URL |
| `api_key` | string | `""` | CT 日志的 API 密钥（如需要） |
| `public_key` | string | `""` | CT 日志公钥（base64 DER SPKI 或 PEM）。配置后 SCT 提交将执行完整 RFC 6962 §3.2 验签；未配置时 CLI 告警"SCT 签名未验证"（H11）。`logs[]` 子项同样支持 |

---

## `ldap` — LDAP 目录集成

与 LDAP 目录集成，用于用户认证和证书主题 DN 构建。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `url` | string | `""` | LDAP 服务器 URL（例如 `localhost:389`） |
| `bind_dn` | string | `""` | LDAP 认证的绑定 DN |
| `bind_password` | string | `""` | 绑定密码 |
| `base_dn` | string | `""` | 搜索基础 DN |
| `filter` | string | `(uid=%s)` | LDAP 搜索过滤器（`%s` 替换为用户名） |
| `uid_attr` | string | `uid` | 用户 ID 的 LDAP 属性 |
| `map_cn` | string | `cn` | 映射到证书通用名称的 LDAP 属性 |
| `map_o` | string | `""` | 映射到证书组织的 LDAP 属性 |
| `map_ou` | string | `""` | 映射到证书组织单位的 LDAP 属性 |
| `map_l` | string | `""` | 映射到证书所在地的 LDAP 属性 |
| `map_st` | string | `""` | 映射到证书州/省的 LDAP 属性 |
| `map_c` | string | `""` | 映射到证书国家的 LDAP 属性 |
| `map_email` | string | `""` | 映射到证书电子邮件的 LDAP 属性 |

---

## `identity` — 身份源 → 证书自动化（Phase 2）

配置身份源桥接服务，为 `identity-user` profile 自动拉取人员属性填充证书。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `type` | string | `ldap` | 身份源类型：`ldap`（bridge-ldap `/api/v1/lookup`）或 `oauth`（bridge-oauth password grant + userinfo） |
| `source_url` | string | `""` | **必填**。身份源桥接服务基础 URL，如 `http://127.0.0.1:8082` |
| `token` | string | `""` | 桥接服务管理 API Bearer token（空 = 无认证） |
| `source` | string | `""` | 默认 source_tag，请求未指定 `identity_source` 时使用 |
| `username` | string | `""` | OAuth 自动化账号用户名（`type=oauth` 必填，资源所有者授权） |
| `password` | string | `""` | OAuth 自动化账号密码（`type=oauth` 必填） |
| `timeout_sec` | int | `10` | 上游请求超时秒数 |
| `ou_from_groups` | object | `{}` | 身份源组 → 证书 OU（RBAC 角色）映射；键为组名或 LDAP 组 DN |
| `default_ou` | string | `""` | 无组映射时的兜底 OU；空则用身份源的 dept |
| `disabled_ok` | bool | `false` | 允许为禁用账号签发（默认拒绝，fail-closed） |

示例（bridge-ldap + OU 映射）：

```json
{
  "identity": {
    "type": "ldap",
    "source_url": "http://127.0.0.1:8082",
    "token": "bridge-token",
    "source": "ad-main",
    "ou_from_groups": {
      "CN=医生,OU=Groups,DC=hospital,DC=local": "gateway:ops"
    }
  }
}
```

签发：`POST /api/v1/certs` 带 `profile=identity-user` + `identity_username`。

---

## `ra` — 注册机构

控制证书签发的多方审批。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `required_approvals` | int | `1` | 证书签发所需的审批人数（1 = 自助服务） |
| `default_ca` | string | `issuing` | RA 审批证书的默认 CA |
| `default_profile` | string | `tls-server` | RA 审批证书的默认模板 |

---

## `key_backend` — 远程 HSM 签名后端

将签名委托给远程 HSM 代理（如 `pki-hsm-proxy`）。适用于生产环境，私钥在 HSM 内部永不泄露。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `type` | string | `"software"` | 签名后端类型。`"software"`（本地软签名）或 `"remote_hsm"`（远程 HSM）|
| `url` | string | `""` | HSM 代理 URL（例如 `"http://127.0.0.1:8445"`）|
| `tls.cert` | string | `""` | 连接 HSM 代理的客户端 TLS 证书（mTLS）|
| `tls.key` | string | `""` | 客户端 TLS 私钥 |
| `token` | string | `""` | Bearer Token，对应 HSM 代理的 `auth.token` |

**示例：**
```json
{
  "key_backend": {
    "type": "remote_hsm",
    "url": "http://127.0.0.1:8445",
    "token": "my-hsm-token"
  }
}
```

配置后，`varwof serve` 启动时自动启用远程签名，所有 CA 签名操作透明委托给 HSM 代理。无需修改任何签发命令或证书配置。

---

## `rate_limit` — API 速率限制

API 端点的令牌桶速率限制器。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `enabled` | bool | `true` | 启用速率限制（AUTH-017：默认开启，防暴力破解与拒绝服务；不需要时可显式设 `false`） |
| `rate` | float | `100` | 每秒添加的令牌数 |
| `burst` | int | `200` | 最大突发大小 |

---

## `engine` — 内存引擎（高性能签发/查询）

常驻内存数据引擎。启用后证书/吊销/nonce 等高频读写先命中内存（内存权威），
再异步批量落库（WAL 崩溃安全）。**`nil` 或省略 = 不启用引擎**，读写全部回源 DB。
引擎启用时 `record_buffer` 自动失效（两者互斥，内存引擎自带写管道）。

**性能调优核心**：`write_threshold` 控制攒批落库条数。默认 `100` 时高并发签发
吞吐约 12K TPS（SQLite 批量 INSERT 成为瓶颈）；调到 `1000-10000` 可提升至
~13.5K TPS（+15%），代价是 WAL 更大、crash 后重放更久。**建议**：按
「同时有效证书峰值 × 1.5」设置 `max_certs`，监控签发 503 率与引擎逐出指标调参。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `max_certs` | int | `200000` | 内存证书上限。达到上限且存量全部未过期时新签发返回 503（ErrBackpressure） |
| `max_nonces` | int | `100000` | 内存一次性 nonce 上限 |
| `max_revoked` | int | `50000` | 每 CA 吊销集上限 |
| `grace` | string | `"24h"` | 过期证书在内存保留窗口（janitor 在此窗口内不逐出） |
| `janitor_interval` | string | `"60s"` | 过期清理周期（O(n) 遍历 + DB 查询，高 QPS 时段周期性抖动，需压测确认） |
| `nonce_ttl` | string | `"24h"` | 未用 nonce 存活期 |
| `write_threshold` | int | `100` | 证书批量落库触发阈值（性能调优点，见上方说明） |
| `write_max_pending` | int | `20000` | 待落库背压上限，超出返回 503（0=禁用背压） |
| `write_max_latency` | string | `"500ms"` | 最大落库延迟（到点强制 flush） |

```json
"engine": {
  "max_certs": 500000,
  "write_threshold": 1000,
  "write_max_pending": 50000,
  "write_max_latency": "500ms"
}
```

> 注意：engine 启用时**同 DB 目录只允许一个进程**启用引擎（WAL flock 互斥，
> 冲突方降级为 DB-only）；SIGHUP 热重载会重建引擎（大库全量 rebuild 需数秒-数十秒，
> 期间读请求回落 DB）。

---

## `record_buffer` — 批量落库缓冲（无引擎时的写加速）

引擎未启用时，证书签发可先入缓冲（WAL 保护）异步批量落库，避免每次请求同步写
SQLite（单写锁瓶颈）。默认启用（threshold=500, max_pending=20000, max_latency=500ms）。
**engine 启用时此段失效**（互斥）。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `disable` | bool | `false` | 完全关闭 RecordBuffer（签发同步落库，无 WAL） |
| `threshold` | int | `500` | 攒批触发落库阈值 |
| `max_pending` | int | `20000` | 待处理上限；`0`=禁用背压（Add 永不返回 false） |
| `max_latency` | string | `"500ms"` | 最大攒批延迟（到点强制落库） |

```json
"record_buffer": {
  "threshold": 2000,
  "max_pending": 50000,
  "max_latency": "500ms"
}
```

---

## `policy_signing` — 策略文件签名校验

防止 authz.json / routes.json 被本地篡改。启用后，加载策略文件前先校验其分离签名（`<file>.sig`）。签名必须是本 PKI 签发的 **admin** 角色证书（OU=admin 或 gateway:admin）的 PKCS#7 detached 签名（SHA-256，内容为策略文件原文）。签名文件由 `varwof policy sign` 或 `varwof-cli policy sign` 生成。

| 字段 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `enabled` | bool | `false` | 启用策略签名校验 |
| `ca_file` | string | `serve.tls_client_ca` | 信任的 CA 链 PEM 路径，用于验证签名者证书 |
| `require_admin_ou` | bool | `true` | 强制签名者证书 OU 含 admin 角色（nil=默认 true）|
| `require` | bool | `false` | `true`=签名缺失即拒绝加载；`false`=缺失时降级警告加载明文 |
| `sig_suffix` | string | `".sig"` | 签名文件后缀 |

**失败行为**：签名校验失败（篡改 / 非 admin 签名者 / CA 链不可信）时**拒绝加载**（fail-closed），启动时跳过并告警、热重载时保留旧策略。

```json
"policy_signing": {
  "enabled": true,
  "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
  "require_admin_ou": true,
  "require": true,
  "sig_suffix": ".sig"
}
```

---

## 验证

当 pki 加载配置文件时，会执行以下验证：

1. **密钥类型** — `defaults.key_type` 和 `acme.default_key_type` 必须是以下之一：
   `ecdsa-p256`、`ecdsa-p384`、`ed25519`、`rsa-2048`、`rsa-4096`；另支持 `sm2`（仅限 `-tags gmsm` 国密构建，签发的 SM2 证书携带纯正 SM2-with-SM3 签名算法 OID `1.2.156.10197.1.501`）。
2. **哈希算法** — `defaults.hash` 和 `acme.default_hash` 必须是以下之一：
   `sha256`、`sha384`、`sha512`
3. **时长** — 所有时长字段（以 `_interval`、`_timeout`、`_expiry`、`_validity` 等结尾）必须是有效的 Go `time.Duration` 字符串（例如 `10s`、`24h`、`168h`、`2160h`）。
4. **端口** — 监听地址必须包含有效的端口号（1–65535）。

---

## 完整示例

```json
{
  "db": "/var/lib/pki/pki.db",
  "serve": {
    "addr": ":4430",
    "static": "/etc/varwof/core/www/pki",
    "reload_poll_interval": "10s",
    "shutdown_timeout": "10s",
    "log_format": "json",
    "log_dest": "syslog"
  },
  "defaults": {
    "ca": "issuing",
    "profile": "tls-server",
    "key_type": "ecdsa-p256",
    "hash": "sha256",
    "default_country": "CN",
    "default_org": "example.com",
    "cert_validity": "2160h",
    "ocsp_url": "http://pki.example.com/ocsp",
    "issuer_url": "http://pki.example.com/ca.pem"
  },
  "acme": {
    "enable": true,
    "directory": "/acme",
    "ca_name": "issuing",
    "default_key_type": "ecdsa-p256",
    "default_hash": "sha256",
    "authz_expiry": "24h",
    "order_expiry": "168h",
    "cert_validity": "2160h",
    "http01_timeout": "10s"
  },
  "cas": {
    "root": {
      "cert": "/etc/varwof/core/root/certs/ca.pem",
      "key": "/etc/varwof/core/root/private/ca.key"
    },
    "issuing": {
      "cert": "/etc/varwof/core/issuing/certs/ca.pem",
      "key": "/etc/varwof/core/issuing/private/ca.key"
    }
  },
  "crl": {
    "validity_days": 30,
    "output_dir": "/etc/varwof/core/www/pki",
    "crl_base_url": "http://pki.example.com/pki",
    "auto_renew": "24h"
  },
  "webhook": {
    "url": "http://hooks.example.com/events",
    "timeout": "10s",
    "expiry_check_interval": "24h",
    "expiry_thresholds": [30, 7, 1]
  }
}
```

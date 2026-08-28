# 配置参考

配置文件是启动时加载的单个 JSON 文档。

默认位置（按顺序搜索）：
1. `--config <path>`（CLI 标志，最高优先级）
2. `./pki.json`（当前目录）
3. `~/.config/pki/pki.json`（用户配置）
4. `/etc/varwof/core/pki.json`（系统级）

生成示例：
```bash
varwof init-config > pki.json
```

---

## 顶层字段

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `db` | string | `/var/lib/pki/pki.db` | 数据库路径（推荐 SQLite） |
| `db.dialect` | string | `"sqlite3"` | SQL 驱动：`sqlite3`、`pgx`（PostgreSQL）、`mysql`（MariaDB） |
| `locale` | string | 自动 | `"zh"` 或 `"en"`（默认自动检测） |
| `hierarchy` | string | `"simple"` | `"simple"`（单级 CA）或 `"complex"`（多级 CA 层级） |
| `serve` | object | 见下文 | HTTP/HTTPS 服务器设置 |
| `defaults` | object | 见下文 | 证书操作的默认值 |
| `cas` | object | 见下文 | CA 证书/密钥定义 |
| `tsa` | object | 见下文 | RFC 3161 时间戳权威机构 |
| `ocsp` | object | 见下文 | RFC 6960 OCSP 响应器 |
| `crl` | object | 见下文 | 证书吊销列表 |
| `acme` | object | 见下文 | ACME v2 协议（RFC 8555） |
| `scep` | object | 见下文 | SCEP 协议（RFC 8894） |
| `webhook` | object | 见下文 | Webhook 通知 |
| `key_escrow` | object | 见下文 | 密钥托管/恢复 |
| `ct_log` | object | 见下文 | 证书透明度 |
| `ldap` | object | 见下文 | LDAP 目录集成 |
| `identity` | object | null | 身份源到证书自动化 |
| `ra` | object | 见下文 | 注册机构 |
| `rate_limit` | object | 见下文 | API 速率限制 |
| `authorization_file` | string | `""` | RBAC 策略文件路径（authz.json） |
| `routes_file` | string | `""` | URL 级路由权限规则（routes.json） |
| `policy_signing` | object | null | 策略文件的 PKCS#7 签名验证 |
| `rbac` | object | 见下文 | RBAC 设置 |
| `auto_renew` | object | 见下文 | 自动证书续期 |
| `archive` | object | 见下文 | 证书归档 |
| `trust_bridge` | object | 见下文 | 跨 CA 信任桥 |
| `smtp` | object | 见下文 | SMTP 通知 |
| `engine` | object | 见下文 | 内存引擎配置 |
| `device_profile` | string | `""` | 设备调优预设（`low_mem` / `high_throughput`）；见下文 |
| `persist` | object | 见下文 | 证书持久化模式 |
| `record_buffer` | object | 见下文 | 批量持久化 |
| `aggregator` | object | 见下文 | 批量签发聚合 |
| `key_backend` | object | 见下文 | 远程 HSM 签名器委托 |
| `spiffe` | object | 见下文 | SPIFFE 身份集成 |
| `k8s_enabled` | bool | false | 启用 `/api/v1/k8s/sign` 端点 |
| `policy` | string | `""` | CN/SAN 允许/拒绝策略 JSON 路径 |
| `enforce_policy` | bool | false | 使缺失策略成为硬错误 |

---

## 性能决策速查（哪些配置最关键）

负载测试结论（`docs/bench/zh/benchmark-report-2026-08-27.md` §5–§8）。按价值排序：

1. **`device_profile` — 选型预设**。每类机器设一次即可（`""` x86/台式机、`low_mem`
   树莓派 5 / 单板机、`high_throughput` 多核），自动设置写管线与内存预算。只写这一项
   就是一份经过调优的配置。
2. **`record_buffer.max_pending` 与 `engine.write_max_pending` — 突发/背压杠杆**。
   两者默认 20000，达到上限返回 HTTP 503。提高到 100000+ 吸收突发（实测 3000 agent 30s
   burst：错误率 15.1%→5.5%、吞吐 +32%）。代价：更多在途记录占用内存。
3. **`rate_limit` — 每 IP 防滥用保护**。与缓冲背压无关，是注入侧限速器；测真实容量时关闭。
4. **系统层（不在本文件）**：CPU governor + turbo（+43%）、MariaDB
   `innodb_flush_log_at_trx_commit=2`（SD 卡 iowait −58%）— 见报告 §5§6。

**别动三项**（实测调大使吞吐下降）：`record_buffer.threshold`（500）、
`engine.write_threshold`（100）、`engine.write_workers`（4）。profile 已编码这一结论；
手动覆盖唯一合理的场景是进一步加深 `max_pending`。

```json
// 开箱即用的部署
{ "device_profile": "high_throughput" }

// 突发密集部署（手动加深管线）
{
  "device_profile": "high_throughput",
  "record_buffer": { "max_pending": 300000 },
  "engine": { "write_max_pending": 300000 }
}
```

---

## `serve` — HTTP/HTTPS 服务器

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `addr` | string | `:8443` | HTTP 监听地址 |
| `tls_addr` | string | `""` | HTTPS mTLS 监听地址 |
| `api_addr` | string | `""` | 内部 API 监听地址 |
| `tls_cert` | string | `""` | TLS 证书 PEM 路径 |
| `tls_key` | string | `""` | TLS 私钥 PEM 路径 |
| `tls_client_ca` | string | `""` | 用于 mTLS 认证的客户端 CA 证书 |
| `static` | string | `/etc/varwof/core/www` | 静态文件目录（Web UI） |
| `auth_username` | string | `""` | HTTP Basic Auth 用户名（后备） |
| `auth_password` | string | `""` | HTTP Basic Auth 密码（后备） |
| `reload_poll_interval` | string | `10s` | 配置文件轮询间隔（热重载） |
| `shutdown_timeout` | string | `10s` | 优雅关闭超时 |
| `log_format` | string | `text` | `text`（key=value）或 `json`（JSON Lines） |
| `log_dest` | string | `stderr` | `stderr`、`file:/path` 或 `syslog` |
| `metrics_enabled` | bool | false | 启用 Prometheus `/metrics` |
| `agent_session_max_ttl` | string | `24h` | 委托代理最大会话窗口 |
| `trusted_gateway_ous` | []string | `[]` | 可信网关服务证书的 OU |
| `da_max_timestamp_skew` | string | `30s` | DA 签名时间戳新鲜度窗口 |
| `audit_salt` | object | 见下文 | 每日 HMAC 盐值掩码保护 PII |
| `audit_verify` | object | 见下文 | 定期 Merkle 链完整性验证 |

### `serve.audit_salt`

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enabled` | bool | true | 在审计日志中使用 HMAC 掩码用户名/remote_addr |
| `retention_days` | int | 365 | 保留每日盐值的天数 |
| `cleanup_interval` | string | `24h` | 清理过期盐值的频率 |

### `serve.audit_verify`

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enabled` | bool | true | 定时重新计算审计哈希链 |
| `interval` | string | `24h` | 链验证周期 |

---

## `defaults` — 证书默认值

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `ca` | string | `issuing` | 默认 CA 名称 |
| `profile` | string | `tls-server` | 默认证书配置文件 |
| `key_type` | string | `ecdsa-p256` | 默认密钥类型 |
| `hash` | string | `sha256` | 默认哈希算法 |
| `default_country` | string | `CN` | 默认主体国家 |
| `default_org` | string | `example.com` | 默认主体组织 |
| `cert_validity` | string | `2160h` | 默认证书有效期 |
| `ocsp_url` | string | `""` | AIA 的 OCSP 响应器 URL |
| `issuer_url` | string | `""` | AIA 的 caIssuers URL |
| `issuer_alt_names` | []string | `[]` | 颁发者备用名称条目 |
| `subject_info_access` | []string | `[]` | 主体信息访问条目 |
| `policy_oids` | []string | `[]` | 证书策略 OID |
| `policy_mappings` | []string | `[]` | 策略映射（仅 CA 证书） |
| `require_explicit_policy` | int | 0 | 策略约束 explicitPolicy |
| `inhibit_policy_mapping` | int | 0 | 策略约束 inhibitPolicyMapping |
| `inhibit_any_policy` | int | 0 | 抑制 anyPolicy |
| `report_max_rows` | int | 5000 | PDF 报告中最大证书行数 |
| `agent_proxy_max_validity` | string | `1h` | 代理证书最大有效期 |

### 支持的密钥类型

`ecdsa-p256`、`ecdsa-p384`、`ecdsa-p521`、`ed25519`、`rsa-2048`、`rsa-4096`、`rsa-8192`、`sm2`（需要 `-tags gmsm`）

### 支持的哈希算法

`sha256`、`sha384`、`sha512`

### 支持的配置文件

`root-ca`、`sub-ca`、`tls-server`、`tls-client`、`ocsp-signer`、`timestamp`、`codesigning`、`email`、`document`、`identity-user`、`m-admin`、`m-superadmin`、`m-operator`、`m-auto-renew`

---

## `acme` — ACME v2 协议

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enable` | bool | false | 启用 ACME v2 |
| `directory` | string | `/acme` | URL 路径前缀 |
| `ca_name` | string | `issuing` | ACME 签发证书使用的 CA |
| `default_key_type` | string | `ecdsa-p256` | ACME 证书的密钥类型 |
| `default_hash` | string | `sha256` | 哈希算法 |
| `authz_expiry` | string | `24h` | 授权有效期 |
| `order_expiry` | string | `168h` | 订单有效期（7 天） |
| `cert_validity` | string | `2160h` | 证书有效期（90 天） |
| `http01_timeout` | string | `10s` | HTTP-01 验证超时 |
| `dns01_timeout` | string | `10s` | DNS-01 验证超时 |
| `external_account_required` | bool | false | 要求 EAB |
| `external_account_keys` | array | `[]` | EAB 密钥对 |
| `renewal_info_url` | string | `""` | ARI 续期信息 URL（RFC 9445） |
| `rate_limit` | object | null | 按 IP 速率限制 |

### `acme.external_account_keys[]`

| 字段 | 类型 | 描述 |
|------|------|------|
| `key_id` | string | EAB 密钥标识符（kid） |
| `hmac_key` | string | HMAC-SHA256 密钥（Base64） |
| `description` | string | 可选描述 |

---

## `scep` — SCEP 协议

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enable` | bool | false | 启用 SCEP |
| `ca_name` | string | `""` | SCEP 签发证书使用的 CA |
| `cert_validity` | string | `8760h` | 证书有效期（365 天） |

---

## `tsa` — 时间戳权威机构

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `addr` | string | `:3180` | TSA 监听地址 |
| `signer_cert` | string | `/etc/varwof/core/tsa-signer/tsa-signer.pem` | 签名证书 |
| `signer_key` | string | `/etc/varwof/core/tsa-signer/tsa-signer.key` | 签名私钥 |
| `chain` | string | `/etc/varwof/core/tsa/certs/ca.pem` | 中间链 |
| `tsa_policy` | string | `""` | TSA 策略 OID |
| `ordering` | bool | false | 在 TSTInfo 中设置 ordering 标志 |
| `accuracy_seconds` | int | 0 | 精度（秒） |
| `accuracy_millis` | int | 0 | 精度（毫秒） |
| `accuracy_micros` | int | 0 | 精度（微秒） |

---

## `ocsp` — OCSP 响应器

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `addr` | string | `:9080` | OCSP 监听地址 |
| `signer_cert` | string | `/etc/varwof/core/ocsp/ocsp.pem` | 签名证书 |
| `signer_key` | string | `/etc/varwof/core/ocsp/ocsp.key` | 签名私钥 |
| `next_update` | string | `""` | 响应 nextUpdate 持续时间 |
| `cache_size` | int | 0 | 最大缓存条目（0=禁用） |
| `cache_ttl` | string | `1h` | 缓存 TTL |
| `cache_file` | string | `""` | 磁盘后端缓存文件（无状态 OCSP 节点） |

---

## `crl` — 证书吊销列表

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `validity_days` | int | 30 | CRL 有效期 |
| `output_dir` | string | `""` | CRL 文件目录 |
| `crl_base_url` | string | `""` | CRL 分发点基础 URL |
| `auto_renew` | string | `""` | 自动续期间隔（例如 `24h`） |

---

## `cas` — 证书颁发机构

CA 名称到证书和密钥路径的映射。

```json
"cas": {
  "root": {
    "cert": "/etc/varwof/core/root/certs/ca.pem",
    "key": "/etc/varwof/core/root/private/ca.key"
  },
  "issuing": {
    "cert": "/etc/varwof/core/issuing/certs/ca.pem",
    "key": "/etc/varwof/core/issuing/private/ca.key"
  }
}
```

| 字段 | 类型 | 描述 |
|------|------|------|
| `<name>.cert` | string | CA 证书 PEM 路径 |
| `<name>.key` | string | CA 私钥 PEM 路径 |
| `<name>.chain` | string | 可选中间链 PEM |

---

## `webhook` — 事件通知

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `url` | string | `""` | Webhook 目标 URL |
| `timeout` | string | `10s` | HTTP POST 超时 |
| `expiry_check_interval` | string | `24h` | 证书过期检查间隔 |
| `expiry_thresholds` | []int | `[30, 7, 1]` | 过期前发送警告的天数 |

---

## `key_escrow` — 密钥恢复

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `admin_public_key` | string | `""` | 用于密钥托管的管理员 RSA 公钥 PEM |

---

## `ct_log` — 证书透明度

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `url` | string | `""` | CT 日志 URL |
| `api_key` | string | `""` | API 密钥 |
| `public_key` | string | `""` | CT 日志公钥（base64 DER 或 PEM） |

---

## `ldap` — LDAP 目录集成

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `url` | string | `""` | LDAP 服务器 URL |
| `bind_dn` | string | `""` | 绑定 DN |
| `bind_password` | string | `""` | 绑定密码 |
| `base_dn` | string | `""` | 搜索基础 DN |
| `filter` | string | `(uid=%s)` | 搜索过滤器（`%s` = 用户名） |
| `uid_attr` | string | `uid` | 用户 ID 属性 |
| `map_cn` | string | `cn` | 映射到证书 CN |
| `map_o` | string | `""` | 映射到证书 O |
| `map_ou` | string | `""` | 映射到证书 OU |
| `map_l` | string | `""` | 映射到证书 L |
| `map_st` | string | `""` | 映射到证书 ST |
| `map_c` | string | `""` | 映射到证书 C |
| `map_email` | string | `""` | 映射到证书 Email |

---

## `identity` — 身份源自动化

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `type` | string | `ldap` | 源类型：`ldap` 或 `oauth` |
| `source_url` | string | `""` | 身份桥基础 URL |
| `token` | string | `""` | 桥接 API Bearer Token |
| `source` | string | `""` | 默认 source_tag |
| `username` | string | `""` | OAuth 自动化账户 |
| `password` | string | `""` | OAuth 自动化密码 |
| `timeout_sec` | int | 10 | 上游请求超时 |
| `ou_from_groups` | object | `{}` | 组 → OU（RBAC 角色）映射 |
| `default_ou` | string | `""` | 后备 OU |
| `disabled_ok` | bool | false | 允许已禁用的账户 |

---

## `ra` — 注册机构

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `required_approvals` | int | 1 | 所需审批数（1 = 自助服务） |
| `default_ca` | string | `issuing` | RA 证书的默认 CA |
| `default_profile` | string | `tls-server` | 默认配置文件 |

---

## `rate_limit` — API 速率限制

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enabled` | bool | true | 启用速率限制 |
| `rate` | float | 100 | 每秒令牌数 |
| `burst` | int | 200 | 最大突发大小 |

---

## `policy_signing` — 策略文件签名

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enabled` | bool | false | 启用签名验证 |
| `ca_file` | string | `serve.tls_client_ca` | 可信 CA 链 PEM |
| `require_admin_ou` | bool | true | 要求签名者具有 admin OU |
| `require` | bool | false | 缺少签名时拒绝 |
| `sig_suffix` | string | `.sig` | 签名文件后缀 |

---

## `engine` — 内存引擎

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `max_certs` | int | 100000 | 内存中最大证书数 |
| `max_nonces` | int | 100000 | 最大 nonce 数 |
| `max_da_nonces` | int | 100000 | 最大 DA（委派授权）nonce 数 |
| `max_revoked` | int | 10000 | 最大吊销证书数 |
| `grace` | string | `24h` | 过期证书在内存中的保留窗口 |
| `janitor_interval` | string | `60s` | 过期证书清扫间隔 |
| `nonce_ttl` | string | `24h` | 未使用 nonce 的存活时间 |
| `write_threshold` | int | 100 | 刷新前的待写入数 |
| `write_max_pending` | int | 20000 | 待写入的硬背压上限 |
| `write_max_latency` | string | `500ms` | 强制刷新前的最大延迟 |
| `write_workers` | int | 4 | 后端写 goroutine 数（吊销/nonce/元数据） |

---

## `device_profile` — 设备相关调优

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `device_profile` | string | `""` | 设备敏感默认值的预设。`""` = x86/台式机基线；`"low_mem"` 用于单板计算机/低内存设备（如树莓派 5）；`"high_throughput"` 用于吸收突发的多核服务器。显式配置的 `engine` / `record_buffer` 参数始终覆盖预设。由负载测试得出（见 `docs/bench/zh/benchmark-report-2026-08-27.md` §5–§7）。 |

各预设实际改动（其余保持内置默认）：

| 预设 | `record_buffer.max_pending` | `engine.max_certs` | `engine.max_da_nonces` | `engine.write_max_pending` |
|------|---------------------------|--------------------|------------------------|---------------------------|
| `""`（默认） | 20000 | 100000 | 100000 | 20000 |
| `low_mem` | 5000 | 50000 | 50000 | 5000 |
| `high_throughput` | 100000 | 100000 | 100000 | 100000 |

负载测试验证 —— 预设**刻意不碰**以下参数，在 18 核 turbo 参考机上调高反而拖慢 AIC：

- `record_buffer.threshold`（500）：500→1000 使单次 flush 持有 flush 互斥锁更久，burst 吞吐降 ~4%。
- `engine.write_threshold`（100）：100→500 加深写管线，吞吐降 ~4%。
- `engine.write_workers`（4）：4→8 加剧数据库连接池竞争，吞吐降 ~25%。

`high_throughput` 的价值纯粹来自更深的 `max_pending` 上限：3000 agent 30s burst（未手动 `-maxpending`）下背压错误率从 15.1% → 5.5%，吞吐 +32%（2,996 → 3,945 certs/s）。`low_mem` 用更小的在途上限换约 4× 的缓冲深度缩减，适合 Pi 5 / SBC 的内存预算。

---

## `persist` — 证书持久化

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `mode` | string | `realtime` | `realtime`、`batch` 或 `async` |
| `batch_size` | int | 50 | 批次大小 |
| `batch_interval` | string | `5s` | 批次间隔 |
| `queue_size` | int | 1000 | 异步队列大小 |

---

## `smtp` — 邮件通知

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `host` | string | `""` | SMTP 服务器主机 |
| `port` | int | 587 | SMTP 服务器端口 |
| `username` | string | `""` | SMTP 用户名 |
| `password` | string | `""` | SMTP 密码 |
| `from` | string | `""` | 发件人邮箱地址 |
| `tls` | bool | true | 使用 TLS |
| `events` | []string | `[]` | 通知事件（issue、revoke、expiry） |

---

## `rbac` — 基于角色的访问控制

| 字段 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `enabled` | bool | false | 启用 RBAC |
| `mode` | string | `simple` | `simple` 或 `enterprise` |
| `ca_scopes` | object | `{}` | CA 作用域定义 |

---

## 验证规则

1. **密钥类型**：`defaults.key_type` 和 `acme.default_key_type` 必须有效
2. **哈希算法**：`defaults.hash` 和 `acme.default_hash` 必须有效
3. **持续时间**：所有持续时间字段必须是有效的 Go `time.Duration` 字符串
4. **端口**：监听地址必须有有效的端口号（1–65535）

---

## 完整示例

```json
{
  "db": "/var/lib/pki/pki.db",
  "locale": "en",
  "serve": {
    "addr": ":8443",
    "tls_addr": ":4433",
    "tls_cert": "/etc/varwof/core/server.pem",
    "tls_key": "/etc/varwof/core/server.key",
    "tls_client_ca": "/etc/varwof/core/ca.pem",
    "static": "/etc/varwof/core/www",
    "log_format": "json",
    "log_dest": "syslog",
    "reload_poll_interval": "10s",
    "metrics_enabled": true
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
  "tsa": {
    "addr": ":3180",
    "signer_cert": "/etc/varwof/core/tsa-signer/tsa-signer.pem",
    "signer_key": "/etc/varwof/core/tsa-signer/tsa-signer.key"
  },
  "ocsp": {
    "addr": ":9080",
    "signer_cert": "/etc/varwof/core/ocsp/ocsp.pem",
    "signer_key": "/etc/varwof/core/ocsp/ocsp.key",
    "cache_size": 10000,
    "cache_ttl": "1h",
    "cache_file": "/var/lib/pki/ocsp-cache.db"
  },
  "crl": {
    "validity_days": 30,
    "output_dir": "/etc/varwof/core/www/pki",
    "crl_base_url": "http://pki.example.com/pki",
    "auto_renew": "24h"
  },
  "acme": {
    "enable": true,
    "directory": "/acme",
    "ca_name": "issuing",
    "default_key_type": "ecdsa-p256",
    "http01_timeout": "10s",
    "dns01_timeout": "10s"
  },
  "rate_limit": {
    "enabled": true,
    "rate": 100,
    "burst": 200
  },
  "webhook": {
    "url": "http://hooks.example.com/events",
    "timeout": "10s",
    "expiry_check_interval": "24h",
    "expiry_thresholds": [30, 7, 1]
  }
}
```

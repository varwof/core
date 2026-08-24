# PKI 功能全面文档

**项目：** `pki` — Go 1.26 实现的一体化 PKI 基础设施（单二进制替代 OpenSSL 包装器 + Python 服务）
**数据库：** SQLite（`modernc.org/sqlite`，纯 Go 无 CGO，**推荐**）；PostgreSQL / MySQL 通过 Dialect 可用但社区维护，新功能不以 PG/MySQL 为 CI 测试目标
**代码量：** ~8,300 行（50+ 个 `.go` 源文件，不含测试和工具）

---

## 1. 架构概览

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI (24 子命令)                          │
│ serve│issue│renew│batch│revoke│crl│sign│export│import│      │
│ init-ca│ca-list│ca-info│ct-submit│key│db│user│token│audit│  │
│ ra│recover│version│init-config│completion│pades              │
└──────┬───────────────────────────────────────────────────────┘
       │
       ├── internal/config     配置加载/合并/搜索
       ├── internal/ca         CA 创建、证书签发、CRL、吊销、RA 审批、密钥托管
       ├── internal/db         SQLite ORM (v1-v7 迁移)
       ├── internal/serve      HTTP 服务器 + Web UI + JSON API
       ├── internal/ocsp       OCSP 响应器 (RFC 6960)
       ├── internal/tsa        时间戳服务器 (RFC 3161)
        ├── internal/pades      PAdES PDF 签名
        ├── internal/pkcs7      PKCS#7/CMS SignedData (含 CAdES-T 真实 TSA)
       ├── internal/signer     文件分离/嵌入签名 + 验证
        ├── internal/pkcs12     PFX 导出 (纯 Go)
       ├── internal/acme       ACME v2 (RFC 8555)
       ├── internal/scep       SCEP (RFC 8894)
       ├── internal/notify     Webhook 通知
       ├── internal/rbac       RBAC + JWT 认证
       ├── internal/serve/ratelimit  令牌桶限流
       ├── internal/ocsp/cache       LRU 响应缓存
       ├── internal/ca/ldap          LDAP/AD 集成
       └── internal/signer/pbes2     私钥加密 (PBKDF2 + AES-256-CBC)
              │
              ▼
         /var/lib/pki/pki.db (SQLite)
```

---

## 2. CLI 子命令

### 2.1 `varwof serve` — 启动统一 PKI 服务

在一个进程中同时提供 TSA、OCSP、Web UI、REST API、ACME 和静态文件分发。

| 标志 | 说明 |
|------|------|
| `--config` | 配置文件路径 |
| `--reload` | 启用配置热重载（10s 轮询） |
| `--install` | (Windows) 安装为系统服务 |
| `--uninstall` | (Windows) 卸载系统服务 |

**端口架构：**
- `:4430` (HTTP) — 公共证书分发、健康检查、有限 API（无 RBAC）
- `:4433` (HTTPS) — 全功能：TSA / OCSP / API / Web UI / ACME / SCEP（需配置 `tls_addr`、`tls_cert`、`tls_key`）

**中间件层（HTTPS）：**
- RBAC 角色鉴权（Bearer/Basic）
- 令牌桶限流（`rate_limit.enabled`）
- 访问日志（accessLog）

**信号处理：**
- SIGINT/SIGTERM — 优雅关闭
- SIGHUP — 热加载配置（atomic.Pointer 安全交换）
- `--reload` — 自动轮询 `cfgFile` mtime 变化，调用 `reloadConfigNow()` 重建 handler/CRL 循环

---

### 2.2 `varwof issue` — 签发证书

从 CSR 或自动生成密钥对签发证书，自动存入数据库。

| 标志 | 默认值 | 说明 |
|------|--------|------|
| `--csr` | `""` | CSR PEM 文件（提供则使用 CSR 公钥签发，跳过密钥生成，不写私钥文件） |
| `--cn` | `""` | 通用名称 |
| `--san` | `""` | 逗号分隔 SAN（支持 `DNS:/IP:/URI:/email:`） |
| `--profile` | 配置默认值 | 证书模板（技术 profile + 管理 m-* profile） |
| `--as` | `""` | 以管理角色身份签发（自动设 OU+profile，取值：admin/operator/revoker/auditor/readonly/console/auto-renew/reporter） |
| `--key-type` | 配置默认值 | 密钥算法 |
| `--ca` | 配置默认值 | 签发 CA |
| `--validity` | 365 | 有效期天数 |
| `--out` / `--out-dir` / `--out-name` / `--out-key` | — | 输出路径 |
| `--encrypt` | false | 输出 PBKDF2+AES-256-CBC 加密私钥 |

**SAN 示例：** `--san "DNS:example.com,DNS:www.example.com,IP:1.2.3.4"`

**CSR 模式：** `--csr req.pem` 使用 CSR 内的公钥签发（CSR 签名校验失败即拒绝），私钥留在请求方，本地不写 `.key` 文件；`--cn` 缺省时回退使用 CSR subject 的 CN；CSR 内的 DNS/IP SAN 自动继承到证书（与 API `/api/v1/csr/sign` 行为一致），`--san` 指定的值会追加合并。

**私钥加密：** `--encrypt` 时读取配置 `pbes2_passphrase`，PBKDF2 (SHA-256, 100k 迭代) 派生密钥，AES-256-CBC 加密 PKCS#8 DER，输出带 `DEK-Info` header 的 PEM。

**密钥强度校验（NIST SP 800-57）：** 签发前强制校验请求公钥强度，弱密钥直接拒绝：
- RSA < 2048 bit 拒绝
- EC 曲线仅允许 NIST P-256 / P-384 / P-521，P-224 等遗留曲线拒绝
- Ed25519 恒接受
- 该校验覆盖所有签发路径：CLI `issue`/`batch`、CSR 签发、API、AIC、子 CA 密钥导入（`parsePrivateKey`/`ParsePrivateKey`/`DecryptKeyPKCS8`）

---

### 2.3 `varwof batch` — 批量签发

从 CSV 文件批量签发证书，自动写入 `{cn}.pem` / `{cn}.key`。

| 标志 | 说明 |
|------|------|
| `--csv` | CSV 文件路径（必需） |
| `--ca` | 签发 CA |
| `--profile` | 证书模板 |
| `--out-dir` | 输出目录 |

CSV 格式：
```csv
cn,san
server1,server1.example.com
server2,"DNS:server2.example.com,IP:10.0.0.2"
```

---

### 2.4 `varwof renew` — 证书续期

自动检测原证书 profile、SAN、密钥类型并续期。VPN 证书（`vpn-client`/`vpn-server`）续期时保留原 profile（按 DB 中 `profile_used` 优先，因 EKU 与 tls-client/tls-server 无法区分）。

| 标志 | 说明 |
|------|------|
| `--serial` | 原证书序列号 |
| `--ca` | 原证书所属 CA |
| `--validity` | 新有效期天数（默认同原证书） |

---

### 2.5 `varwof sign` — 文件签名 (PKCS#7 / CAdES-T)

签署文件生成分离签名（`.p7s`）或嵌入签名。支持 `--verify` 验证和 CAdES-T（真实 TSA 时间戳）。

| 标志 | 说明 |
|------|------|
| `--verify` | 验证模式（默认: 签署模式） |
| `--embed` | 嵌入签名到文件末尾 |
| `--cades` | 添加 CAdES-T 签名时间戳 unsigned attribute（需配置 TSA signer cert/key） |
| `--sig` | 验证时指定签名文件路径 |
| `--cert` / `--key` / `--chain` | 手动指定签名证书 |
| `--ca` | 使用 CA 配置自动加载签名证书 |

**CAdES-T：** `--cades` 时读取配置 TSA 签名证书，对 CMS SignedData 的 signatureValue 做 SHA256 哈希，构建 RFC 3161 TimeStampReq，调用进程内 `tsa.SignRequest` 签名，嵌入 unsigned attribute `id-aa-signatureTimeStampToken` (1.2.840.113549.1.9.16.2.14)。无 TSA 配置时自动跳过（输出 DER NULL 占位符）。

**嵌入签名格式：**
```
[原始内容]PKISIG\x00[8字符十六进制长度][PKCS#7 DER]
```

**验证支持：** ECDSA / RSA PKCS#1v1.5 / Ed25519 三种签名算法，可选根证书链验证。

---

### 2.6 `varwof pades sign` — PDF 签名 (PAdES-B)

签署 PDF 文件生成带 PAdES-B 签名的输出 PDF。

| 标志 | 说明 |
|------|------|
| `<file.pdf>` | 输入 PDF 路径（必需参数） |
| `--out` | 输出 PDF 路径（默认: `<file>-signed.pdf`） |
| `--ca` | 使用 CA 配置自动加载签名证书 |
| `--cert` / `--key` / `--cn` | 手动指定签名证书、私钥、Common Name |
| `--profile` | 签名证书 profile（需支持 digitalSignature） |
| `--config` | 配置文件路径 |

**实现原理：** 增量更新方式追加签名域，两步法：预留 16KB hex 占位符 → 计算 ByteRange → 构建 CMS 脱手签名（`/SubFilter /adbe.pkcs7.detached`） → 替换占位符。不依赖第三方 PDF 库。

---

### 2.7 `varwof revoke` — 吊销证书

| 标志 | 说明 |
|------|------|
| `--serial` | 十六进制序列号 |
| `--cert` | 证书文件（自动提取序列号） |
| `--reason` | 吊销原因（unspecified / keyCompromise / caCompromise / ...） |
| `--ca` | CA 名称 |

---

### 2.8 `varwof crl` — 生成 CRL

| 标志 | 说明 |
|------|------|
| `--out` | 输出 DER 路径（默认: `{output_dir}/{ca}.crl`） |
| `--ca` | CA 名称 |

---

### 2.9 `varwof import` — 从 OpenSSL 导入

兼容 OpenSSL 的 `index.txt` 格式，批量导入已有证书到数据库。

| 标志 | 说明 |
|------|------|
| `--index` | index.txt 路径（默认: `index.txt`） |
| `--cert-dir` | 证书 PEM 目录 |
| `--ca` | 分配 CA 名称 |
| `--ca-cert` | CA 证书（自动注册到 `ca_meta`） |

---

### 2.10 `varwof export` — PFX/PKCS#12 导出

通过纯 Go 实现（`software.sslmate.com/src/go-pkcs12`），使用 Modern 编码（AES-256-CBC + SHA-256）。

| 标志 | 说明 |
|------|------|
| `--cert` | 证书 PEM（必需） |
| `--key` | 私钥 PEM（必需） |
| `--chain` | 链证书 PEM |
| `--out` | 输出路径（必需） |
| `--password` | PFX 密码（空密码也支持） |
| `--pfx` | 必须设置为 true |

---

### 2.11 `varwof init-ca` — 初始化 CA

创建根 CA 或子 CA，存入数据库，输出 PEM 文件。

| 标志 | 默认值 | 说明 |
|------|--------|------|
| `--name` | — | CA 名称（必需） |
| `--profile` | `root-ca` | `root-ca` 或 `sub-ca` |
| `--parent` | `""` | 父 CA 名称 |
| `--key-type` | 配置默认值 | 密钥算法 |
| `--validity` | 3650 (10年) | 有效期天数 |
| `--out-cert` / `--out-key` | — | 输出 PEM 路径 |
| `--permitted-dns` | `""` | (子 CA) 允许的 DNS 后缀 |
| `--excluded-dns` | `""` | (子 CA) 排除的 DNS 后缀 |
| `--no-store-key` | false | 签发后不存储私钥（根 CA 离线化） |

---

### 2.12 `varwof ca-list` / `varwof ca-info` — CA 查询

列出所有 CA 或查看单个 CA 详情（含证书统计分布）。

`ca-info` 输出字段：Name, Subject, Issuer, Serial, Algorithm, 有效期, Fingerprint, 是否为 CA, Max Path, 证书统计（total/revoked/expired/expiring ≤30d）

### 2.12.1 `varwof ca cold-backup` — 根 CA 离线冷备

将根 CA 证书与私钥导出为单一加密冷备文件（私钥 PBES2 AES-256-CBC 加密 + HMAC 完整性封套），适合离线介质保管。

| 子命令 | 说明 |
|--------|------|
| `backup` | 导出冷备 JSON（`--ca-name`/`--ca-cert`/`--ca-key`/`--out`；备份密码 `--password`/`--password-file`/`PKI_BACKUP_PASSWORD`；`--shred` 成功后安全删除源密钥） |
| `verify` | 校验冷备（`--in` + 备份密码），验证 HMAC 并确认密钥与证书公钥匹配 |

详见 `dev-docs/RootKeySecurity_CN.md` §4。

---

### 2.13 `varwof ct-submit` — CT 日志提交

向 Certificate Transparency 日志服务器提交证书，获取 SCT。

| 标志 | 说明 |
|------|------|
| `--log-url` | CT 日志服务器 URL |
| `--cert` | 证书 PEM 文件 |
| `--chain` | 链证书 PEM 文件 |

签发后自动提交：配置 `ct.enabled=true` + `ct.logs` 列表，签发时自动调用 `ctSubmitLogs`。

---

### 2.14 `varwof key` — 私钥加密/解密

| 子命令 | 说明 |
|--------|------|
| `varwof key encrypt --in <key.pem> --out <enc-key.pem>` | 加密私钥 |
| `varwof key decrypt --in <enc-key.pem> --out <key.pem>` | 解密私钥 |

加密格式：PBKDF2 (SHA-256, 100k 迭代, 16B 随机盐) → AES-256-CBC (随机 16B IV) 加密 PKCS#8 DER。

---

### 2.15 `varwof recover` — 密钥恢复

使用管理员私钥解密之前托管的加密私钥。

| 标志 | 说明 |
|------|------|
| `--serial` | 证书序列号 |
| `--ca` | CA 名称 |
| `--admin-key` | 管理员私钥 PEM 路径 |

---

### 2.16 `varwof user` — 用户管理 (RBAC)

| 子命令 | 说明 |
|--------|------|
| `varwof user add --username U --role R [--password P]` | 创建用户 |
| `varwof user list` | 列出所有用户 |
| `varwof user update --username U [--role R] [--password P]` | 更新用户 |
| `varwof user delete --username U` | 删除用户 |
| `varwof user bind-operator-cert --username U --cert cert.pem` | 绑定操作证书（代理该用户的 CA scope） |
| `varwof user unbind-operator-cert --username U` | 解绑操作证书 |

角色: `admin` / `operator` / `revoker` / `auditor` / `readonly` / `console` / `auto-renew` / `reporter`

> **操作证书代理**：给密码登录用户绑定一张 scope 限定的 `m-*` 管理证书后，该用户登录时以证书 scope 为其有效 CA scope（密码学绑定）；绑定即校验，过期/吊销/非本 PKI 签发的证书立即拒绝。

---

### 2.17 `varwof token` — API 令牌管理

| 子命令 | 说明 |
|--------|------|
| `varwof token create --username U` | 创建 JWT API 令牌 |
| `varwof token list` | 列出所有活跃令牌 |
| `varwof token revoke --token T` | 吊销令牌 |

令牌用于 HTTP API 的 Bearer 或 Basic 认证。

---

### 2.18 `varwof audit` — 审计日志

| 子命令 | 说明 |
|--------|------|
| `varwof audit list` | 列出审计日志 |
| `varwof audit verify` | 验证 Merkle 哈希链完整性 |

完整性算法：`SHA256(prev_hash + "|" + timestamp + "|" + username + "|" + action + "|" + detail)`

---

### 2.19 `varwof ra` — RA 审批工作流

| 子命令 | 说明 |
|--------|------|
| `varwof ra submit --csr F --cn N [--san ...] [--approvals N]` | 提交审批请求 |
| `varwof ra list [--status pending/approved/rejected/issued]` | 请求列表 |
| `varwof ra approve --id N [--comment "..."]` | 审批（达阈值自动签发） |
| `varwof ra reject --id N [--reason "..."]` | 拒绝 |
| `varwof ra show --id N` | 请求详情 |

M/N 多级审批：需 `required_approvals` 人批准后自动调用 `ca.Sign` 签发证书。

---

### 2.20 `varwof db` — 数据库管理

```bash
varwof db init        # 初始化数据库（建库 + 迁移到最新 schema）
varwof db migrate     # 迁移 schema 到目标版本（升级或回滚）
varwof db backup      # 数据库在线备份
varwof db transfer    # 跨数据库迁移（SQLite → PG/MySQL）
```

`varwof db init --dsn <dsn>` 初始化目标数据库并自动迁移到最新 schema：
- **SQLite**（默认）：自动创建文件及父目录，幂等
- **PostgreSQL**（`postgres://user:pass@host:port/dbname`）：同凭据连接 `postgres` 维护库，`CREATE DATABASE`（若不存在）后迁移
- **MySQL/MariaDB**（`mysql://user:pass@host:port/dbname`）：无库名连接服务器，`CREATE DATABASE IF NOT EXISTS` 后迁移
- DSN 缺省时取配置 `db` 字段，其次 `DATABASE_URL` 环境变量

`varwof db backup --out <path>` 使用 SQLite `VACUUM INTO` 实现事务级一致性快照，不中断服务。

---

### 2.21 `varwof version` / `varwof init-config` / `varwof completion`

```bash
varwof version           # 版本 + 编译信息
varwof init-config       # 生成带注释的默认配置文件
varwof completion bash   # 生成 bash 自动补全脚本
```

### 2.21 `varwof deploy` — 部署配置生成器

| 参数 | 说明 |
|------|------|
| `--target` | 部署目标：`nginx`、`apache`、`k8s-secret` |
| `--cert` | 证书 PEM 文件路径 |
| `--key` | 私钥 PEM 文件路径 |
| `--chain` | CA 链 PEM 文件路径（可选） |
| `--out` | 输出文件路径（默认 stdout） |
| `--secret-name` | Kubernetes Secret 名称（k8s-secret 目标） |
| `--namespace` | Kubernetes 命名空间（k8s-secret，默认 "default"） |

示例：
```
varwof deploy --target nginx --cert server.pem --key server.key
varwof deploy --target k8s-secret --cert server.pem --key server.key \
  --secret-name myapp-tls --namespace production --out secret.yaml
```

### 2.22 `varwof report` — 合规报告生成

生成 SOC 2、PCI DSS、NIST SP 800-53、ISO 27001 标准的审计合规报告 PDF。

| 参数 | 说明 |
|------|------|
| `--template` | 报告模板：`soc2`、`pci`、`nist`、`iso`（默认 `soc2`） |
| `--out` | 输出 PDF 路径（默认 `compliance-<模板>-<日期>.pdf`） |
| `--ca` | 按 CA 名称过滤（可选） |

示例：
```
varwof report --template soc2 --out soc2-report.pdf
varwof report --template pci
varwof report --template nist --ca "Root CA"
```

报告内容包括：
- **范围** — PKI 基础设施概览
- **CA 层级** — 根 CA 与从属 CA 数量
- **证书清单** — 有效/吊销/过期证书统计
- **过期分析** — 30/90 天内到期证书
- **控制映射** — 各标准的控制项与通过状态
- **结论** — 合规性总结

---

### 2.23 `varwof benchmark` — 加密性能基准测试

测量当前硬件上哈希和签名算法的吞吐性能，用于容量规划和算法选型。

| 标志 | 默认值 | 说明 |
|------|--------|------|
| `--algo` | 全部 | 逗号分隔算法过滤（`sha256,sha384,sha512,rsa-2048,rsa-4096,ecdsa-p256,ecdsa-p384,ed25519`） |
| `--size` | 0（全尺寸） | 数据块大小（字节），0 表示 1KB / 2KB / 4KB / 8KB / 12KB / 16KB / 20KB / 32KB / 64KB（证书场景尺寸） |
| `--duration` | 2s | 每轮测试时长 |
| `--concurrency` | 1 | 并行 goroutine 数量（多核吞吐测试） |
| `--json` | false | 输出 JSON 格式 |

**示例：**
```bash
varwof benchmark                              # 全算法，2s/轮
varwof benchmark --algo ed25519,ecdsa-p256    # 仅 Ed25519 + ECDSA P-256
varwof benchmark --algo sha256 --size 1024    # 仅 SHA-256，1KB 数据块
varwof benchmark --concurrency 4              # 4 核并行测试
varwof benchmark --duration 5s --json         # 5s/轮，JSON 输出
```

**输出格式（表格）：**
```
Algorithm   Operation  Size  Ops/s   Latency  Throughput
─────────   ─────────  ────  ─────   ───────  ──────────
SHA256      hash       1KB   937.2K  1.0μs    915 MB/s
ED25519     sign       1KB   30.7K   32.0μs   —
```

**支持的算法：**
- 哈希：SHA-256、SHA-384、SHA-512（纯 Go，无 CGO）
- 签名：RSA-2048、RSA-4096、ECDSA P-256、ECDSA P-384、Ed25519
- 签名测量包含 key generation + sign + verify 全流程

---

## 3. HTTP API 端点

### 3.1 JSON REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/cas` | 列出所有 CA |
| GET | `/api/v1/ca/{name}` | 单个 CA 详情 |
| GET | `/api/v1/certs?ca=X&status=V/R&cn=Y` | 查询证书 |
| POST | `/api/v1/certs/upload` | 上传外部证书（NAS 等设备证书）入库存档（不持私钥） |
| GET | `/api/v1/cert/{caName}/{serial}` | 单个证书 |
| GET | `/api/v1/crl/{caName}` | CRL 下载 (DER) |
| GET | `/api/v1/healthz` | 健康检查 |

### 3.2 TSA 端点

| 方法 | 路径 | Content-Type | 说明 |
|------|------|-------------|------|
| POST | `/tsa` | `application/timestamp-query` | RFC 3161 时间戳 |
| POST | `/timestamp` | `application/timestamp-query` | 别名 |

### 3.3 OCSP 端点

| 方法 | 路径 | Content-Type | 说明 |
|------|------|-------------|------|
| POST | `/ocsp` | `application/ocsp-request` | OCSP 请求 |
| GET | `/ocsp` | `?query=<base64>` | GET 方式 OCSP |

### 3.4 ACME 端点 (v2)

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/acme` | ACME 目录 |
| POST | `/acme/new-nonce` | 获取 nonce |
| POST | `/acme/new-account` | 注册账户 |
| POST | `/acme/new-order` | 创建订单 |
| POST | `/acme/challenge/{id}` | HTTP-01 挑战 |
| GET | `.well-known/acme-challenge/{token}` | HTTP-01 验证 |
| POST | `/acme/cert/{order-id}` | 下载证书 |
| GET | `/acme/renewalInfo/{cert-id}` | ACME ARI（RFC 9445）续期信息，`cert-id` 为证书 DER 的 SHA-256（base64url） |

> **ACME ARI（RFC 9445）**：目录广告 `renewalInfo` 端点。客户端用证书 DER 的 SHA-256（base64url 编码）查询服务端建议续期窗口（默认取证书有效期的 1/3 至 2/3）。可选 `explanationURL` 由 `acme.renewal_info_url` 配置。

### 3.5 SCEP 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/scep?operation=GetCACert` | 获取 CA 证书 |
| GET | `/scep?operation=GetNextCACert` | 获取下一个 CA 证书（CA 轮换） |
| POST | `/scep?operation=PKCSReq` | 证书申请 |

### 3.6 公共端口（仅 HTTP）

| 路径 | 说明 |
|------|------|
| `/healthz`、`/readyz` | 健康检查 |
| `/pki/*` | 静态文件分发 |

---

## 4. 核心包

### 4.1 `internal/ca` — CA 操作

| 函数/文件 | 说明 |
|-----------|------|
| `CreateCA(cfg)` | 创建根 CA 或子 CA，自动生成密钥，存入数据库 |
| `Sign(cfg)` | 使用 CA 签发证书，20B 随机序列号，最多 10 次重试防冲突；支持 IssuerAltName/SubjectInfoAccess/CertificatePolicies 扩展 |
| `GenerateKey(keyType)` | 6 种密钥类型 (ecdsa-p256/p384, rsa-2048/4096, ed25519, sm2(需 -tags gmsm)) |
| SM2 纯正 OID | `-tags gmsm` 下签发的 SM2 证书携带纯正 SM2-with-SM3 签名算法 OID（`1.2.156.10197.1.501`），由 `tjfoc/gmsm/x509` 生成；国密互认场景专用（标准库 `crypto/x509` 无法解析 SM2 曲线，OCSP/CRL 等标准库路径暂不可用） |
| `GenerateCRL(cfg)` | 从数据库构建 DER CRL（含 InvalidityDate per-entry 扩展） |
| `Revoke(db, caName, serial, reason)` | 吊销证书 |
| `LoadSigner(certPath, keyPath)` | 加载 PEM 证书+密钥 |
| `escrow.go` | 密钥托管：AES-256-GCM + RSA-OAEP hybrid 加密 |
| `ra.go` | RA 审批：提交/审批/拒绝/列表 + signFn 回调解耦 |
| `CertToPEM(der)` / `KeyToPEM(key)` | DER/PKCS8 → PEM |

### 4.2 `internal/db` — SQLite 数据库层

**表：`ca_meta`**
| 列 | 说明 |
|------|------|
| `name` | 主键，CA 标识符 |
| `cert_der` | DER 编码的 CA 证书 |
| `subject` / `not_before` / `not_after` | 证书元数据 |
| `key_algorithm` / `fingerprint` | 算法/指纹 |

**表：`certificates`**
| 列 | 说明 |
|------|------|
| `serial_number` + `ca_name` | 联合主键 |
| `status` | V=有效, R=吊销, E=过期 |
| `subject` / `common_name` / `cert_der` | 主题和证书 |
| `not_before` / `not_after` / `revoked_at` | 时间戳 |
| `fingerprint` / `revoke_reason` / `invalidity_date` | 指纹/原因/失效日期 |

**表：`users`** (v2) | **表：`api_tokens`** (v3) | **表：`audit_log`** (v4+v7 hash chain) | **表：`ra_requests`** / `ra_approvals` (v6)

**自动迁移：** v1-v9，启动时自动执行，`user_version` 追踪版本。

### 4.3 `internal/pkcs7` — PKCS#7/CMS SignedData

| 函数 | 说明 |
|------|------|
| `BuildSignedData(eContentType, eContent, cert, signer, chain)` | 构建签名 CMS |
| `BuildSignedDataWithDigest(..., hash, signatureValue)` | 显式指定哈希算法 + 脱手签名 |
| `SignatureValue(eContentType, eContent, cert, signer, hash)` | 构建并返回 CMS signatureValue DER（计算 signatureValue 但不构建完整 CMS） |

**支持的签名 OID：**
- ECDSA：`sha256WithECDSA` / `sha384WithECDSA` / `sha512WithECDSA`
- RSA：`sha256WithRSAEncryption` / `sha384WithRSAEncryption` / `sha512WithRSAEncryption`
- Ed25519：`id-EdDSA25519`

**哈希自动选择：**
| 密钥类型 | 哈希 |
|-----------|------|
| ECDSA P-256 / RSA 2048 | SHA-256 |
| ECDSA P-384 / RSA 4096+ | SHA-384 |
| ECDSA P-521 | SHA-512 |
| Ed25519 | 无预哈希 |

**签名属性：** content-type OID、messageDigest、signingCertificate (RFC 2634 ESS)

### 4.4 `internal/signer` — 文件签名

| 函数 | 说明 |
|------|------|
| `SignDetached(filePath, cfg)` | 创建 `<文件>.p7s` 分离签名 |
| `SignEmbedded(filePath, cfg)` | 嵌入签名到文件尾 |
| `SignWithCades(filePath, cfg)` | 添加 CAdES-T 时间戳（真实 TSA 签名或占位符） |
| `VerifyDetached(filePath, sigPath, rootCAs)` | 验证分离签名 |
| `VerifyEmbedded(filePath, rootCAs)` | 验证嵌入签名 |

### 4.5 `internal/pades` — PAdES PDF 签名

| 函数 | 说明 |
|------|------|
| `SignPDF(inputPath, outputPath, cfg)` | 对 PDF 文件追加增量签名域，PAdES-B 格式（`/SubFilter /adbe.pkcs7.detached`） |
| `buildByteRange(inputPath)` | 计算 PDF ByteRange（文件大小 + 占位符偏移） |
| `buildSignatureDictionary(start, length, contents)` | 构建 PDF 签名对象字典 |

### 4.6 `internal/tsa` — RFC 3161 时间戳

| 函数 | 说明 |
|------|------|
| `ParseTimeStampReq(der)` | ASN.1 解析 TimeStampReq |
| `BuildTimeStampReq(hash, nonce, certReq)` | 构建 RFC 3161 TimeStampReq DER |
| `BuildTSTInfo(req, serial)` | 构建 TSTInfo（可配 accuracy/ordering/policy） |
| `SignRequest(reqDER, cfg)` | 全流程：解析 → TSTInfo → PKCS#7 签名 |

### 4.7 `internal/ocsp` — OCSP 响应器

| 函数 | 说明 |
|------|------|
| `NewHandler(cfg)` | 创建 OCSP HTTP 处理程序 |
| `(*Handler) ServeHTTP(w, r)` | 支持 POST（DER）和 GET（base64） |

**状态结果：** Good / Revoked（含时间+原因）/ Unknown

### 4.8 `internal/pkcs12` — PFX 导出

调用纯 Go PKCS#12 库（Modern 编码：AES-256-CBC + SHA-256），支持空密码和密码保护。

### 4.9 `internal/acme` — ACME v2 (RFC 8555)

| 功能 | 说明 |
|------|------|
| 目录 | `/acme` 返回 ACME 目录 |
| 账户 | new-account 注册（JWS with JWK or KID） |
| 订单 | new-order 创建，SAN 列表验证 |
| 挑战 | HTTP-01 / DNS-01 验证 |
| 授权 | "任一挑战通过"策略（RFC 8555 §7.1.5） |
| 签发 | 完整 E2E 流程 → 通过 `ca.Sign` 签发证书（经 lego 测试验证） |
| Retry-After | 挑战返回 `Retry-After: 5`，authz 轮询带指数退避 |
| SQLite WAL 模式 | `_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` 防止并发锁竞争 |

### 4.10 `internal/scep` — SCEP (RFC 8894)

| 操作 | 说明 |
|------|------|
| GetCACert | 返回封装在退化 PKCS#7 中的 CA 证书 |
| GetNextCACert | 返回下一个 CA 证书（GET/POST），当前等同 GetCACert |
| PKCSReq | 解析 PKCS#7 包裹的 CSR → 调用 `ca.Sign` 签发 → 返回 CertRep |

### 4.11 `internal/notify` — Webhook 通知

| 功能 | 说明 |
|------|------|
| 事件推送 | 签发/吊销/证书过期事件 POST JSON 到配置 URL |
| 定时扫描 | 24h 定时器扫描过期 CA 和证书并推送 |
| 配置 | `webhook.url` + `webhook.events` 列表 |

### 4.12 `internal/rbac` — RBAC + JWT 认证

| 功能 | 说明 |
|------|------|
| 用户 | 本地 SQLite 存储, bcrypt 密码哈希 |
| 角色 | admin / operator / revoker / auditor / readonly / console / auto-renew / reporter |
| JWT | `golang.org/x/crypto` Ed25519 签发, RBAC 中间件校验 |
| 认证 | Bearer Token / Basic Auth 均支持 |

### 4.13 `internal/serve/ratelimit` — 令牌桶限流

| 功能 | 说明 |
|------|------|
| 算法 | `golang.org/x/time/rate` 每 IP 令牌桶 |
| 配置 | `rate_limit.enabled` / `rate` (rps) / `burst` |
| 响应 | 超限时 HTTP 429 Too Many Requests |
| 清理 | 后台 goroutine 每分钟清理过期 IP 记录 |

### 4.14 `internal/ocsp/cache` — OCSP LRU 缓存

| 功能 | 说明 |
|------|------|
| 结构 | 线程安全 LRU map + TTL 过期 |
| 键 | SHA256(OCSP 请求 DER) |
| 配置 | `ocsp.cache_size` / `ocsp.cache_ttl` |
| 策略 | 查前取缓存，签后存缓存 |

### 4.15 `internal/ca/ldap` — LDAP/AD 集成

| 功能 | 说明 |
|------|------|
| 连接 | `NewLDAPConn(cfg)` dial + bind |
| 查询 | `LookupLDAP(conn, cfg, username)` 搜索 BaseDN |
| 映射 | map_* 配置项自动映射到 pkix.Name (CN/O/OU/L/ST/C/email) |
| 校验 | `CheckLDAPGroupMembership(entry, groupDN)` memberOf 检查 |
| 集成 | `issue.go` 签发时自动使用 LDAP 填充 Subject |

---

## 5. 证书模板 (Profiles)

### 技术模板

| 模板 | KeyUsage | ExtKeyUsage | 特殊扩展 |
|------|----------|-------------|----------|
| `root-ca` | certSign, crlSign | — | CA:true, pathLen:1 |
| `sub-ca` | certSign, crlSign | — | CA:true, pathLen:0, CRL DP, Name Constraints (DNS/Email/URI/IP) |
| `tls-server` | digitalSignature, keyEncipherment | serverAuth, clientAuth | CRL DP, AIA (OCSP+caIssuers) |
| `tls-client` | digitalSignature | clientAuth | CRL DP, AIA (OCSP+caIssuers) |
| `ocsp-signer` | digitalSignature | OCSPSigning | CRL DP, AIA (OCSP+caIssuers) |
| `timestamp` | digitalSignature | — | CRL DP, AIA (OCSP+caIssuers), EKU timeStamping critical via ExtraExtensions |
| `codesigning` | digitalSignature | CodeSigning | CRL DP, AIA (OCSP+caIssuers) |
| `email` | digitalSignature, keyEncipherment | EmailProtection | CRL DP, AIA (OCSP+caIssuers) |
| `document` | digitalSignature, contentCommitment | — | CRL DP, AIA (OCSP+caIssuers) |
| `agent-proxy` | digitalSignature | clientAuth | CRL DP, AIA, 有效期 ≤ 1h, AIC 扩展, 至少一个 OU |
| `vpn-client` | digitalSignature, keyEncipherment | clientAuth | CRL DP, AIA (OCSP+caIssuers) — 用于 WireGuard/OpenVPN 等 mTLS VPN 客户端证书 |
| `vpn-server` | digitalSignature, keyEncipherment | serverAuth, clientAuth | CRL DP, AIA — VPN 服务端证书（双向认证场景） |
| `identity-user` | digitalSignature, keyEncipherment | emailProtection, clientAuth | CRL DP, AIA — 身份源自动签发的基础身份证书（Phase 2）；CN/OU/email 从 bridge-ldap/bridge-oauth 自动填充，可选 PA 扩展 |

**所有 EE profile 均含 BasicConstraints CA:FALSE。**

**全部 EE profile 均支持可选扩展：** IssuerAltName (2.5.29.18)、SubjectInfoAccess (1.3.6.1.5.5.7.1.11)、CertificatePolicies (2.5.29.32)，通过 `defaults.issuer_alt_names`/`subject_info_access`/`policy_oids` 配置。

### 管理证书模板 (m-*)

内置 PKI 管理角色证书预设，自动设置 `OU=<角色名>` + `ClientAuth EKU` + `DigitalSignature KU`，签发时只需指定 `--as` 快捷参数，无需手动传 subject。

| 模板 | OU | 对应角色 | 推荐场景 |
|------|-----|---------|---------|
| `m-admin` | admin | admin | 超级管理员 mTLS 证书 |
| `m-operator` | operator | operator | 运营管理员 mTLS 证书 |
| `m-revoker` | revoker | revoker | 吊销员 mTLS 证书 |
| `m-auditor` | auditor | auditor | 审计员 mTLS 证书 |
| `m-readonly` | readonly | readonly | 监控/外部查看 mTLS 证书 |
| `m-console` | console | console | Web Console 后端服务证书 |
| `m-auto-renew` | auto-renew | auto-renew | 自动化续期机器人 mTLS 证书 |
| `m-reporter` | reporter | reporter | 报表生成 mTLS 证书 |
| `m-subadmin` | sub-admin | — | 子 CA 管理员（CA=true, CertSign, `--scope` 写入 OID 扩展） |

**示例：**
```bash
varwof issue --ca "Issuing CA" --as admin --cn "Alice Admin" --out alice.pem
varwof issue --ca "Issuing CA" --as auto-renew --cn "k8s-renewer" --out renew-bot.pem
varwof issue --ca "Issuing CA" --profile m-subadmin --scope "Agent CA" --cn "Agent CA Admin" --out agent-admin.pem
```

---

## 6. 密钥类型支持矩阵

| 操作 | ecdsa-p256 | ecdsa-p384 | rsa-2048 | rsa-4096 | ed25519 |
|------|:----------:|:----------:|:--------:|:--------:|:-------:|
| 密钥生成 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 证书签发 | ✓ | ✓ | ✓ | ✓ | ✓ |
| PKCS#7 签名 | ✓ | ✓ | ✓ | ✓ | ✓ |
| PKCS#7 验证 | ✓ | ✓ | ✓ | ✓ | ✓ |
| OCSP 签名 | ✓ | ✓ | ✓ | ✓ | ✓ |
| TSA 签名 | ✓ | ✓ | ✓ | ✓ | ✓ |
| PFX 导出 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 哈希 | SHA-256 | SHA-384 | SHA-256/384 | SHA-384 | 无预哈希 |

---

## 7. 配置说明

### 7.1 配置搜索顺序

1. `./pki.json`（当前目录）
2. `~/.config/pki/pki.json`
3. `/etc/varwof/core/pki.json`（Linux）或 `%PROGRAMDATA%\varwof\core\pki.json`（Windows）

可通过 `--config <路径>` 强制指定。

### 7.2 完整配置结构

```jsonc
{
  "db": "/var/lib/pki/pki.db",
  "cas": {
    "root":    { "cert": "...", "key": "..." },
    "issuing": { "cert": "...", "key": "...", "chain": "..." },
    "tsa":     { "cert": "...", "key": "..." },
    "codesign":{ "cert": "...", "key": "..." }
  },
  "tsa": {
    "signer_cert": "...",
    "signer_key":  "...",
    "chain":       "...",
    "tsa_policy":  "2.16.840.1.113733.1.9.2",
    "ordering":    false,
    "accuracy_seconds": 1,
    "accuracy_millis": 0,
    "accuracy_micros": 0
  },
  "ocsp": {
    "signer_cert": "...",
    "signer_key":  "..."
  },
  "serve": {
    "addr":     ":4430",
    "tls_addr": ":4433",
    "tls_cert": "...",
    "tls_key":  "..."
  },
  "defaults": {
    "ca":       "issuing",
    "profile":  "tls-server",
    "key_type": "ecdsa-p256",
    "hash":     "sha256",
    "ocsp_url":   "http://pki.example.com/ocsp",
    "issuer_url": "http://pki.example.com/ca.pem",
    "issuer_alt_names":   [],
    "subject_info_access": [],
    "policy_oids":        []
  },
  "crl": {
    "validity_days": 30,
    "output_dir":    "/etc/varwof/core/crls",
    "crl_base_url":  "http://pki.example.com/api/v1/crl",
    "auto_renew":    true
  },
  "webhook": {
    "url":    "https://hooks.example.com/pki",
    "events": ["issue", "revoke", "expiry"]
  },
  "ct": {
    "enabled": true,
    "logs": [{"url": "https://ct.example.com/2025", "key": "base64key..."}]
  },
  "rbac": {
    "enabled": true,
    "jwt_secret": "CHANGE_ME"
  },
  "ra": {
    "required_approvals": 2,
    "default_ca": "issuing",
    "default_profile": "tls-server"
  },
  "pbes2_passphrase": "CHANGE_ME",
  "key_escrow": {
    "admin_public_key": "/etc/varwof/core/escrow/admin.pub.pem"
  }
}
```

### 7.3 合并规则

`DefaultConfig()` → `SearchConfigPath()` → `CLI --config` → 子命令 `--config`，每次使用 `MergeConfig(base, override)` 深度合并，非空字段覆盖。

---

## 8. 跨平台支持

### Windows
- 服务管理：`varwof serve --install` / `--uninstall`
- `serve_windows.go` 使用 `golang.org/x/sys/windows/svc`
- 服务名：`pki`，自动启动，使用 `%PROGRAMDATA%` 路径

### Unix
- `serve_unix.go` 使用 `signal.Notify` 监听 SIGINT/SIGTERM/SIGHUP
- `atomic.Pointer` 安全交换 config/DB/TSA/OCSP handler

---

## 9. DB 迁移历史

| 版本 | 新增内容 |
|------|----------|
| v1 | 初始 schema: `ca_meta`, `certificates` |
| v2 | `users` 表 + `serial_counter` |
| v3 | `api_tokens` 表 |
| v4 | `audit_log` 表 |
| v5 | `certificates` 增加 `escrow_data` 列 |
| v6 | `ra_requests`, `ra_approvals` 表 |
| v7 | `audit_log` 增加 `entry_hash`, `prev_hash` 列 |
| v9 | `certificates` 增加 `invalidity_date` 列（RFC 5280 InvalidityDate CRL 扩展） |

---

## 10. E2E 验证状态

| 验证项 | 方法 | 状态 |
|--------|------|------|
| init-ca root | `openssl verify` | ✓ |
| init-ca sub-ca | `openssl verify -CAfile root.pem sub.pem` | ✓ |
| TSA reply | `openssl ts -reply` / `-verify` | ✓ |
| OCSP good | `openssl ocsp -issuer ... -cert ...` | ✓ |
| OCSP revoked | 吊销后查询状态 | ✓ |
| CRL | HTTP API 返回有效 DER | ✓ |
| Issue + chain | `openssl verify -CAfile ... -untrusted ...` | ✓ |
| CodeSign PKCS#7 | Go VerifyDetached / VerifyEmbedded | ✓ |
| CodeSign openssl | `openssl cms -verify` | ✓ |
| CAdES-T (real TSA) | CMS 含 `id-aa-signatureTimeStampToken` unsigned attribute | ✓ |
| PAdES-B PDF 签名 | Adobe Reader / Go 验证 PDF 签名域 | ✓ |
| PFX 导出 | `pkcs12.DecodeChain` 纯 Go | ✓ |
| SCEP | Go test (GetCACert + GetNextCACert + PKCSReq) | ✓ |
| RBAC | Bearer/Basic 认证 + 角色鉴权 | ✓ |
| LDAP 集成 | 签发时自动填充 Subject | ✓ |
| 限流 | 429 Too Many Requests | ✓ |
| OCSP 缓存 | 缓存命中/过期 | ✓ |
| RA 审批 | 提交 → M/N 审批 → 自动签发 | ✓ |
| 审计完整性 | `varwof audit verify` 全链验证 | ✓ |
| 私钥加密 | `varwof key encrypt/decrypt` 往返 | ✓ |
| DB 备份 | VACUUM INTO 一致性快照 | ✓ |
| 配置热重载 | `varwof serve --reload` mtime 检测 | ✓ |
| Windows 交叉编译 | `GOOS=windows` 编译 | ✓ |
| RFC 5280 序列号 20B | `openssl x509 -serial` 长度 40 hex 字符 | ✓ |
| AIA caIssuers | `openssl x509 -text -certopt ext` 检查 AIA | ✓ |
| Name Constraints 全形式 | `openssl x509 -text` DNS/Email/URI/IP | ✓ |
| CRL InvalidityDate | `openssl crl -text` per-entry 扩展 | ✓ |
| IssuerAltName | `openssl x509 -text` Issuer Alt Name | ✓ |
| SubjectInfoAccess | `openssl x509 -text` Subject Info Access | ✓ |
| CertificatePolicies | `openssl x509 -text` Policies | ✓ |

---

## 11. 测试覆盖（总计 ~500+ 用例，35 测试文件，覆盖 72.6%）

| 包 | 测试数 | 覆盖内容 |
|----|--------|----------|
| root CLI | 16 | sign/export/init-ca/revoke/issue/crl + 错误路径 |
| `internal/ca` | 16 | 创建根/子 CA、签发、CRL、吊销、5 种密钥类型 |
| `internal/db` | 15 | cert CRUD、ca_meta CRUD |
| `internal/serve` | 16 | 路由分发、JSON API、MIME 分发、WebUI |
| `internal/pkcs7` | 14 | BuildSignedData、WithChain、CAdES-T、各种 OID |
| `internal/signer` | 10 | sign/verify detached/embedded/chain/tamper |
| `internal/tsa` | 8 | 解析、TSTInfo、Policy QIs |
| `internal/ocsp` | 4 | 缓存、Good、Unknown、BadRequest |
| `internal/pkcs12` | 5 | 基本/密码/链 |
| `internal/config` | 6 | 默认配置、加载、合并 |
| `internal/scep` | 3 | GetCACert、GetNextCACert、PKCSReq |
| `internal/ca` (ldap) | 1 | nil cfg 安全路径 |
| `internal/pades` | 4 | BuildByteRange、BuildSignatureDictionary、SignPDF（含错误路径） |

**全部通过** `go vet ./...` 和 `go test -count=1 ./...`

## 16. 国际化（i18n）

系统支持中英文双语，通过 HTTP `Accept-Language` 头自动协商语言。

**语言检测优先级：**
1. 配置文件 `locale` 字段（如 `"locale": "zh"`）
2. HTTP 请求头 `Accept-Language`  
3. 默认 `en`

**覆盖范围：**
| 领域 | 支持语言 | 说明 |
|------|---------|------|
| CLI 输出 | EN/ZH | 错误消息、提示信息 |
| Web UI | EN/ZH | 登录页、导航、仪表盘、签发表单、管理面板 |
| API 错误 | EN | 当前仅英文 |

**翻译文件：** `internal/i18n/locales/{en,zh}.json`，JSON 键值对格式。

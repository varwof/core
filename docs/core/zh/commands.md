# CLI 命令参考

二进制文件名：`pki`（或 `varwof`）

全局标志：
- `--config <path>` — 配置文件路径（覆盖自动发现）
- `-v, --verbose` — 启用调试日志

## 证书颁发机构

### `varwof ca init`

初始化新的 CA（根 CA 或中间 CA）。

```bash
varwof ca init \
  --name "My CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert ca.pem \
  --out-key ca.key
```

| 标志 | 描述 |
|------|------|
| `--name` | CA 名称（唯一标识符） |
| `--profile` | CA 配置文件：`root-ca`、`sub-ca` |
| `--parent` | 父 CA 名称（用于子 CA） |
| `--parent-key` | 父 CA 私钥路径 |
| `--key-type` | `ecdsa-p256`、`ecdsa-p384`、`rsa-2048`、`rsa-4096` |
| `--validity` | 有效期（例如 `3650d`、`87600h`） |
| `--out-cert` | 输出证书路径 |
| `--out-key` | 输出私钥路径 |
| `--password` | 使用密码加密私钥 |
| `--org` | 组织名称 |
| `--country` | 国家代码 |
| `--permitted-dns` | 名称约束：允许的 DNS |
| `--excluded-dns` | 名称约束：排除的 DNS |

### `varwof ca list`

列出数据库中的所有 CA。

### `varwof ca info`

显示 CA 详情。

```bash
varwof ca info --name "My CA"
```

### `varwof ca offline-sign`

离线签署子 CA 证书（气隙操作）。

```bash
varwof ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

### `varwof ca cold-backup`

创建 CA 密钥的加密冷备份。

```bash
varwof ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json
```

## 证书生命周期

### `varwof issue`

签发证书（从 CSR 或自动生成密钥）。

```bash
varwof issue \
  --ca "Issuing CA" \
  --cn server.example.com \
  --san DNS:server.example.com \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --out-dir certs/ \
  --out-name server
```

| 标志 | 描述 |
|------|------|
| `--ca` | 签发 CA 名称 |
| `--cn` | 通用名称 |
| `--san` | 主体备用名称（`DNS:`、`IP:`、`URI:`、`email:`） |
| `--profile` | 证书配置文件 |
| `--key-type` | 自动生成密钥的类型 |
| `--validity` | 证书有效期 |
| `--csr` | 内联 CSR（PEM） |
| `--csr-file` | CSR 文件路径 |
| `--out-dir` | 输出目录 |
| `--out-name` | 输出文件基础名称 |
| `--encrypt` | 加密私钥 |
| `--encrypt-password` | 密钥加密密码 |
| `--no-store-key` | 不在数据库中存储私钥 |
| `--must-staple` | 添加 OCSP must-staple 扩展 |

SAN 格式示例：
```
--san DNS:example.com,DNS:www.example.com,IP:10.0.0.1,email:user@example.com
```

### `varwof renew`

续期证书。

```bash
varwof renew --serial <serial> --ca "Issuing CA" --validity 365d
```

| 标志 | 描述 |
|------|------|
| `--serial` | 证书序列号 |
| `--cert` | 证书文件路径（--serial 的替代方式） |
| `--ca` | CA 名称 |
| `--validity` | 新的有效期 |
| `--keep-key` | 重用现有私钥 |
| `--key-type` | 新的密钥类型 |

### `varwof revoke`

吊销证书。

```bash
varwof revoke --serial <serial> --ca "Issuing CA" --reason key-compromise
```

吊销原因：`unspecified`、`key-compromise`、`ca-compromise`、`affiliation-changed`、`superseded`、`cessation-of-operation`、`certificate-hold`、`remove-from-crl`、`privilege-withdrawn`、`aa-compromise`。

### `varwof list`

列出证书。

```bash
varwof list --ca "Issuing CA" --status valid --format table
varwof list --cn server --format json --limit 10
```

### `varwof view`

查看证书详情。

```bash
varwof view --serial <serial> --ca "Issuing CA"
```

## 批量操作

### `varwof batch`

从 CSV 批量签发证书。

```bash
varwof batch --ca "Issuing CA" --csv hosts.csv --out-dir certs/
```

CSV 格式：
```csv
cn,san,profile
server1.example.com,DNS:server1.example.com,tls-server
server2.example.com,DNS:server2.example.com,tls-server
```

## PKCS#7 签名

### `varwof sign`

使用 PKCS#7 签署文件。

```bash
# Detached signature
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --sig document.pdf.p7s

# Embedded signature
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --embed --sig document.pdf.p7s

# CAdES-T (timestamped)
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --cades --sig document.pdf.p7s
```

### `varwof verify`

验证 PKCS#7 签名。

```bash
varwof verify --sig document.pdf.p7s --in document.pdf
varwof verify --embed document-signed.pdf
```

### `varwof run`

验证二进制文件的分离签名，然后执行。

```bash
varwof run --run-ca "CodeSign CA" --sig tool.bin.p7s tool.bin
```

## 导入/导出

### `varwof import`

从 OpenSSL 格式或 PKCS#12 导入证书。

```bash
# From OpenSSL index.txt
varwof import --ca "My CA" --index index.txt --cert-dir certs/

# From PKCS#12
varwof import --ca "My CA" --pfx bundle.p12 --password "secret"
```

### `varwof export`

将证书导出为 PKCS#12。

```bash
varwof export --cert cert.pem --key key.pem --chain ca-chain.pem \
  --pfx out.p12 --pfx-password "secret"
```

## 密钥管理

### `varwof key encrypt` / `varwof key decrypt`

加密/解密私钥。

```bash
varwof key encrypt --in plain.key --out encrypted.key --password "secret"
varwof key decrypt --in encrypted.key --out plain.key --password "secret"
```

### `varwof recover`

恢复托管的私钥。

```bash
varwof recover --serial <serial> --ca "My CA" --admin-key admin.key --out recovered.key
```

## 服务器

### `varwof serve`

启动所有 PKI 服务（TSA + OCSP + Web + API）。

```bash
varwof serve --config pki.json
```

| 标志 | 描述 |
|------|------|
| `--config` | 配置文件路径 |
| `--reload` | 启用配置热重载 |
| `--install` | 安装为 Windows 服务 |
| `--uninstall` | 卸载 Windows 服务 |

### `varwof serve tsa`

仅启动 TSA（独立运行）。

### `varwof serve ocsp`

仅启动 OCSP 响应器（独立运行）。

### `varwof serve crl`

启动 CRL 生成 + 分发。

### `varwof serve api`

仅启动 REST API + Web UI。

### `varwof serve dns`

启动 DNS 服务器（ACME DNS-01 + CERT + SRV 记录）。

## 用户与 RBAC 管理

### `varwof user add`

```bash
varwof user add --username admin --password secret --role admin
varwof user add --username operator1 --password secret --role operator
```

角色：`admin`、`operator`、`auditor`、`readonly`

### `varwof user bind-operator-cert`

将操作员证书绑定到用户（用于基于 mTLS 的 CA 作用域）。

```bash
varwof user bind-operator-cert --username operator1 --cert operator.pem
```

### `varwof token create`

```bash
varwof token create --username admin --description "CI token" --expires 720h
```

## 信任联邦

### `varwof trust bridge issue`

交叉签署 CA 以建立信任桥。

### `varwof trust bridge list`

列出已有的信任桥。

### `varwof trust import`

导入信任锚点。

## 注册机构

### `varwof ra submit`

提交 CSR 以供审批。

```bash
varwof ra submit --cn server.example.com --san DNS:server.example.com --profile tls-server
```

### `varwof ra approve` / `varwof ra reject`

批准或拒绝待处理的请求。

```bash
varwof ra approve --id <request-id>
varwof ra reject --id <request-id> --reason "insufficient documentation"
```

## 实用工具

### `varwof version`

打印版本和构建信息。

### `varwof init-full`

创建完整的 PKI 层级（根 CA + 8 个子 CA）。

```bash
varwof init-full \
  --root-name "TestCorp Root CA" \
  --org "TestCorp" \
  --country CN \
  --base-dir /opt/pki
```

### `varwof init-config`

将示例配置打印到标准输出。

### `varwof db init`

初始化数据库（创建 + 迁移到最新 schema）。

### `varwof db migrate`

将 schema 迁移到目标版本。

```bash
varwof db migrate --to 2 --dry-run
```

### `varwof db backup`

备份数据库。

```bash
varwof db backup --out backup.db
```

### `varwof benchmark`

基准测试哈希和签名算法性能。

### `varwof report`

生成合规报告 PDF。

```bash
varwof report --type soc2 --out report.pdf
```

### `varwof cpcps`

生成 CP/CPS 合规文档（RFC 3647）。

```bash
varwof cpcps --out-dir docs/ --separate-cp
```

### `varwof completion`

生成 shell 补全。

```bash
varwof completion bash > /etc/bash_completion.d/pki
varwof completion zsh > ~/.zfunc/_pki
varwof completion fish > ~/.config/fish/completions/pki.fish
```

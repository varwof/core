# varwof-cli（客户端）

varwof PKI 核心系统的 CLI 管理客户端。通过 mTLS 或 HTTP+token 连接到核心 CA API，执行证书生命周期管理。

**模块**：`github.com/varwof/client`
**许可证**：Apache-2.0
**状态**：预览版

## 功能特性

- 完整的证书生命周期：签发、吊销、续期、重新签名、查询
- AIC（Agent Identity Certificate）签发，支持委托授权
- 批量证书签发（支持 JSON/CSV）
- 策略文件 PKCS#7 签名（authz.json / routes.json）
- 自检：闭环健康验证
- 证书扩展检查（AIC / PrincipalAuthorization OID）
- 加密私钥支持（PBES2/PBKDF2-SHA256/AES-256-CBC）
- SPIFFE ID 集成
- 交互式 REPL 模式
- 跨平台支持（Linux、macOS、Windows）

## 安装

```bash
go install github.com/varwof/client@latest
```

或从源码构建：

```bash
git clone https://github.com/varwof/client.git
cd client
go build -o varwof-cli .
```

## 快速开始

### 1. 创建配置文件

```json
{
  "server": "https://varwof-core:4433",
  "ca_cert": "/etc/varwof/core/root/ca.pem",
  "client_cert": "/etc/varwof/core/keys/superadmin.pem",
  "client_key": "/etc/varwof/core/keys/superadmin-key.pem"
}
```

保存为 `cli-config.json`。

### 2. 签发证书

```bash
varwof-cli cli-config.json issue \
  --cn server.example.com \
  --san DNS:server.example.com,DNS:www.example.com \
  --ca tls \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out certs/
```

### 3. 列出证书

```bash
varwof-cli cli-config.json list --ca tls --status valid
```

### 4. 吊销证书

```bash
varwof-cli cli-config.json revoke --ca tls --serial AB12CD34 --reason keyCompromise
```

## 配置

```json
{
  "server": "https://varwof-core:4433",
  "ca_cert": "/path/to/ca.pem",
  "client_cert": "/path/to/client.pem",
  "client_key": "/path/to/client-key.pem",
  "key_password": "optional-password",
  "token": "optional-api-token"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `server` | string | 是 | 核心服务 URL |
| `ca_cert` | string | 是（mTLS） | 用于服务器验证的 CA 证书 |
| `client_cert` | string | 是（mTLS） | 客户端证书 |
| `client_key` | string | 是（mTLS） | 客户端私钥 |
| `key_password` | string | 否 | 私钥密码 |
| `token` | string | 是（HTTP） | 普通 HTTP 模式下的 Bearer token |

**认证模式：**
- **mTLS**（`https://`）：需要 `ca_cert`、`client_cert`、`client_key`
- **Token**（`http://`）：仅需要 `token`

**密码解析优先级：**
1. 配置文件中的 `key_password` 字段
2. `PKI_KEY_PASSWORD` 环境变量
3. 交互式终端提示输入

## 命令

### 证书生命周期

| 命令 | 说明 | 示例 |
|------|------|------|
| `issue` | 签发证书 | `issue --cn server.example.com --ca tls --profile tls-server` |
| `revoke` | 吊销证书 | `revoke --ca tls --serial AB12 --reason keyCompromise` |
| `renew` | 续期证书 | `renew --ca tls --serial AB12` |
| `re-sign` | 使用原始密钥重新签名 | `re-sign --ca tls --serial AB12 --target-ca tls` |
| `list` | 列出证书 | `list --ca tls --status valid --json` |
| `cas` | 列出 CA 或显示信息 | `cas --ca tls --info --pem` |
| `find-by-key` | 按公钥哈希查找 | `find-by-key --hash abc123` |

### 批量操作

| 命令 | 说明 | 示例 |
|------|------|------|
| `batch` | 从 JSON/CSV 批量签发 | `batch --requests batch.json --fast` |
| `revoke-all` | 吊销所有用户证书 | `revoke-all --reason keyCompromise` |
| `revoke-by-principal` | 按主体 UID 吊销 | `revoke-by-principal --principal-uid varwof:alice:` |
| `revoke-subca` | 吊销子 CA 下所有证书 | `revoke-subca --sub-ca tls --reason keyCompromise` |

### AIC（Agent Identity Certificate）

| 命令 | 说明 | 示例 |
|------|------|------|
| `aic issue` | 签发 AIC（带委托） | `aic issue --user-cert user.pem --user-key user.key --agent agent-1 --caps "http:read"` |
| `aic batch` | 批量签发 AIC | `aic batch --config users.json --ca tls` |
| `aic list` | 列出批量配置中的用户 | `aic list --config users.json` |

### 工具命令

| 命令 | 说明 | 示例 |
|------|------|------|
| `cert show` | 解码 varwof 扩展 | `cert show --cert cert.pem` |
| `policy sign` | 签名策略文件（PKCS#7） | `policy sign --file authz.json --cert admin.pem --key admin.key` |
| `selfcheck` | PKI 冒烟测试 | `selfcheck --ca tls` |
| `repl` | 交互式 REPL | `repl` |

## 命令详情

### `issue`

签发新证书。

```bash
varwof-cli config.json issue \
  --cn server.example.com \
  --san DNS:server.example.com,IP:10.0.0.1 \
  --ca tls \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out certs/
```

| 参数 | 说明 |
|------|------|
| `--cn` | 通用名称（必填） |
| `--san` | 主题备用名称 |
| `--ca` | CA 名称 |
| `--profile` | 证书配置文件 |
| `--key-type` | 密钥类型 |
| `--validity` | 有效期（天） |
| `--ca-scope` | 管理证书的 CA 作用域 |
| `--pa` | 主体授权（`scheme:cap ...`） |
| `--out` | 输出目录 |
| `--subject` | 主体 DN |

### `aic issue`

签发带委托授权的 Agent Identity Certificate。

```bash
varwof-cli config.json aic issue \
  --user-cert user.pem \
  --user-key user.key \
  --agent agent-1 \
  --caps "http:read,http:write" \
  --ca tls \
  --ou gateway:ops \
  --out certs/ \
  --spiffe \
  --spiffe-domain example.com
```

| 参数 | 说明 |
|------|------|
| `--user-cert` | 用户证书（必填） |
| `--user-key` | 用户私钥（必填） |
| `--agent` | 代理标识符（必填） |
| `--caps` | 能力列表（`scheme:cap ...`）（必填） |
| `--ca` | CA 名称 |
| `--ou` | 组织单元（角色） |
| `--out` | 输出目录 |
| `--constraints` | 会话约束（`scheme:cap[:jsonparams] ...`） |
| `--spiffe` | 生成 SPIFFE ID |
| `--spiffe-domain` | SPIFFE 信任域 |
| `--json` | JSON 格式输出 |

### `selfcheck`

闭环健康验证：

1. 探测 `/healthz`（数据库、TSA 签名器、CRL 新鲜度）
2. 若出现降级，自动修复 CRL
3. 签发测试证书
4. 验证证书链
5. 吊销测试证书
6. 生成 CRL
7. 下载并解析 CRL

```bash
varwof-cli config.json selfcheck --ca tls
```

### `policy sign`

使用 PKCS#7 分离签名对策略文件进行签名。

```bash
varwof-cli config.json policy sign \
  --file authz.json \
  --cert admin.pem \
  --key admin.key \
  --out authz.json.sig
```

签名需要 admin-OU 证书。签名后会自动进行验证。

### `repl`

交互式 REPL 模式。密码仅需输入一次，所有命令均可交互式使用。

```bash
varwof-cli config.json repl
```

## 安全特性

- **CL2**：阻止跨主机 HTTP 重定向（防止 mTLS 凭据泄露）
- **CL4**：配置文件不得对所有用户可读
- **CL5**：使用普通 HTTP 连接非回环服务器时触发警告
- **CL6**：AIC 证书/密钥写入失败时显式报错（不静默丢弃）

## 支持的配置文件

`tls-server`、`tls-client`、`code-signing`、`smime`、`ocsp-signing`、`timestamping`、`sub-ca`、`agent-proxy`、`cmp`

## 支持的密钥类型

`ecdsa-p256`、`ecdsa-p384`、`rsa-2048`、`rsa-4096`、`ed25519`

## 支持的吊销原因

`unspecified`、`keyCompromise`、`cACompromise`、`affiliationChanged`、`superseded`、`cessationOfOperation`

# 端到端零信任网关演示

本指南演示 pki 核心 + pki-gateway 的完整链路：**签发证书 → 网关执行策略 → 审计追溯**。

## 系统架构

```
┌──────────────────────────────────────────────────────────┐
│  管理员                   AI Agent                        │
│  varwof issue                pki-agent (待开发)              │
└─────────┬──────────────────────┬──────────────────────────┘
          │ 签发证书含 OU 角色     │ API 调用
┌─────────▼──────────────────────▼──────────────────────────┐
│  pki 核心 (CA)                                           │
│  • 签发 agent-proxy 临时证书 (≤1h)                        │
│  • OU 必填: gateway:<role>  →  证书绑定权限               │
│  • CRL 发布：吊销后实时生效                                │
└─────────────────────────┬──────────────────────────────────┘
                          │ 证书 + CRL
┌─────────────────────────▼──────────────────────────────────┐
│  pki-gateway (零信任网关)                                  │
│  1. mTLS 握手 → 验证证书链                                 │
│  2. CRL 检查 → 拒绝已吊销证书                              │
│  3. OU 角色提取 → 与 allow_roles 比对                     │
│  4. 审计日志 → TSA 签名固化                                │
│  5. 端口转发 → 连接目标服务                                │
└─────────────────────────┬──────────────────────────────────┘
                          │ mTLS 隧道
┌─────────────────────────▼──────────────────────────────────┐
│  目标服务 (MySQL / Redis / SSH / HTTP API)                │
└────────────────────────────────────────────────────────────┘
```

## 前提条件

- Go 1.21+
- openssl CLI（验证证书用）
- 编译产物：`pki`、`pki-gateway`

```bash
# 编译
go build -o pki ./cmd/pki/
go build -o pki-gateway /path/to/pki-gateway/
```

## 步骤

### 1. 创建 CA 层级

```bash
# Root CA
varwof init-ca --name "Demo Root CA" --key-type ecdsa-p256 \
  --ca-type root --org "Demo" --country "CN" --out ./ca

# Issuing CA
varwof init-ca --name "Demo Issuing CA" --key-type ecdsa-p256 \
  --ca-type sub --parent-ca ./ca/demo-root-ca \
  --org "Demo" --country "CN" --out ./ca
```

### 2. 签发网关客户端证书

使用 `agent-proxy` profile——强制 OU 必填、有效期 ≤1 小时：

```bash
varwof issue --ca ./ca/demo-issuing-ca --profile agent-proxy \
  --cn "mysql-agent" \
  --subject "/CN=mysql-agent/OU=gateway:mysql-prod" \
  --out ./certs --name mysql-agent
```

验证证书：

```bash
openssl x509 -in ./certs/mysql-agent.pem -noout -subject
# → subject=CN=mysql-agent, OU=gateway:mysql-prod, ...

openssl x509 -in ./certs/mysql-agent.pem -noout -ext keyUsage,extendedKeyUsage
# → X509v3 Key Usage: Digital Signature
# → X509v3 Extended Key Usage: TLS Web Client Authentication
```

### 3. 配置并启动网关

```json
{
  "mappings": [
    {
      "name": "mysql-prod",
      "listen": "127.0.0.1:9443",
      "target": "127.0.0.1:3306",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "./ca/demo-issuing-ca/ca.pem",
        "cert_file": "./ca/demo-issuing-ca/ca.pem",
        "key_file": "./ca/demo-issuing-ca/ca-key.pem",
        "crl_url": "http://crl.internal:8080/demo-issuing-ca.crl",
        "allow_roles": ["gateway:mysql-prod"],
        "audit_file": "/var/log/pki-gateway/audit.log"
      }
    }
  ]
}
```

```bash
pki-gateway server -config ./gw.json
```

### 4. 客户端连接

```bash
# 通过网关访问 MySQL（不需要知道 MySQL 真实地址）
mysql -h 127.0.0.1 -P 9443 -u app_user -p \
  --ssl-cert ./certs/mysql-agent.pem \
  --ssl-key ./certs/mysql-agent-key.pem \
  --ssl-ca ./ca/demo-issuing-ca/ca.pem
```

### 5. 越权尝试被拦截

用 `gateway:readonly` 角色的证书尝试连接 `allow_roles: ["gateway:mysql-prod"]` 的 mapping：

```bash
# 签发 read-only 证书
varwof issue --ca ./ca/demo-issuing-ca --profile agent-proxy \
  --cn "readonly-agent" \
  --subject "/CN=readonly-agent/OU=gateway:readonly" \
  --out ./certs --name readonly-agent

# 连接被网关拒绝
mysql -h 127.0.0.1 -P 9443 ... --ssl-cert ./certs/readonly-agent.pem ...
# → ERROR 2013 (HY000): Lost connection to MySQL server
```

网关日志：
```
denied: src=10.0.0.5 mapping=mysql-prod reason="unauthorized role" roles=["gateway:readonly"]
```

### 6. 吊销证书

```bash
# 吊销
varwof revoke --ca ./ca/demo-issuing-ca --cert ./certs/mysql-agent.pem
varwof crl --ca ./ca/demo-issuing-ca --out ./crl/demo-issuing-ca.crl

# 网关热加载 CRL
kill -HUP $(pgrep pki-gateway)
# 或
curl -X POST https://admin:9443/api/v1/gateway/crl-reload \
  --cert admin.pem --key admin-key.pem
```

已吊销证书的连接立即被拒绝。

### 7. 查看审计日志

```bash
# 管理 API 查询审计
curl --cert admin.pem --key admin-key.pem \
  https://admin:9443/api/v1/gateway/audit?since=2026-07-05T00:00:00Z
```

审计日志每行包含：
```json
{"entry":{"time":"2026-07-05T12:34:56.123456789Z","action":"connected","client_cn":"mysql-agent","client_serial":"ABC123","roles":["gateway:mysql-prod"],"mapping":"mysql-prod","target":"127.0.0.1:3306"},"tst":"MIIF...TQ=="}
```

`tst` 字段是 RFC 3161 TSA 签名，用于证明日志不可篡改。

## 自动化测试

```bash
bash deploy/test-gateway-e2e.sh
```

该脚本自动完成：
1. 创建 CA 层级
2. 签发 agent-proxy 证书
3. 启动 Echo 测试服务器
4. 启动网关
5. 测试角色认证
6. 测试越权拒绝
7. 测试吊销拦截
8. 验证审计日志

## 常见问题

**Q: 签发提示"requires at least one OU"？**
A: `agent-proxy` profile 必须指定 OU，格式：
```bash
--subject "/CN=<name>/OU=gateway:<role>"
```

**Q: 证书有效期太长被截断？**
A: `agent-proxy` 强制最长 1 小时。如需临时延长时间，使用 `tls-client` profile 手动指定 `--ttl`。

**Q: Windows 配置路径？**
A: 默认路径 `%ProgramData%\varwof\pki-gateway\pki-gateway.json`。

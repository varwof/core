# PKI 快速搭建与全功能验证指南

> 版本: 1.0  
> 日期: 2026-07-24  
> 目标: 从零搭建三层/四层 PKI 体系，5 分钟内完成企业级证书签发

---

## 一、命令速查

### 初始化

| 命令 | 作用 |
|------|------|
| `varwof init-full -out-dir ./pki -org MyCorp -domain mycorp.com -hierarchy simple -root-validity 7300` | 从零搭建三层 PKI（Root → Sub CA → 实体） |
| `varwof init-full -out-dir ./pki -org MyCorp -domain mycorp.com -hierarchy enterprise -root-validity 7300` | 从零搭建四层 PKI（Root → Policy → Sub CA → 实体） |
| `varwof init-ca -name "My CA" -profile sub-ca -parent "My Root CA"` | 单独创建一张 CA 证书 |
| `varwof init-config --out pki.json` | 生成示例配置文件 |

### 证书签发

| 命令 | 作用 |
|------|------|
| `varwof issue --ca "MyCorp TLS CA" --cn web.example.com --san "DNS:web.example.com,IP:10.0.0.1,email:admin@example.com" --profile tls-server` | 签发 TLS 服务器证书（含 SAN：DNS/IP/email） |
| `varwof issue --ca "MyCorp TLS CA" --cn user@example.com --profile tls-client` | 签发 TLS 客户端证书 |
| `varwof issue --ca "MyCorp VPN CA" --cn vpn.example.com --profile vpn-server` | 签发 VPN 服务器证书 |
| `varwof issue --ca "MyCorp VPN CA" --cn mobile-user --profile vpn-client` | 签发 VPN 客户端证书 |
| `varwof issue --ca "MyCorp CodeSign CA" --cn dev@example.com --profile codesigning` | 签发代码签名证书 |
| `varwof issue --ca "MyCorp TSA CA" --cn tsa.example.com --profile timestamp` | 签发时间戳签名证书 |
| `varwof issue --ca "MyCorp TLS CA" --cn ocsp.example.com --profile ocsp-signer` | 签发 OCSP 响应者证书 |
| `varwof issue --ca "MyCorp Management CA" --cn admin@example.com --profile m-admin` | 签发管理员证书 |
| `varwof batch --csv batch.csv` | 批量签发（CSV 格式） |

### 证书生命周期

| 命令 | 作用 |
|------|------|
| `varwof list --ca "MyCorp TLS CA"` | 列出 CA 下所有证书 |
| `varwof renew --cert path/to/cert.pem` | 续签证书 |
| `varwof revoke --ca "MyCorp TLS CA" --serial <HEX> --reason keyCompromise` | 吊销证书 |
| `varwof crl --ca "MyCorp TLS CA" --out myca.crl` | 生成 CRL |
| `varwof crl-verify -in myca.crl -cacert ca.pem` | 验证 CRL 签名 |
| `varwof export --cert cert.pem --key key.pem --pfx cert.pfx` | 导出 PFX（PKCS#12） |
| `varwof auto-renew --once` | 自动续签一次 |

### 密钥管理

| 命令 | 作用 |
|------|------|
| `varwof key encrypt --in key.pem --out key.enc` | 加密私钥（PBKDF2 + AES-256-CBC） |
| `varwof key decrypt --in key.enc --out key.pem` | 解密私钥 |

### PKCS#7 签名

| 命令 | 作用 |
|------|------|
| `varwof sign --ca "MyCorp CodeSign CA" --in file.bin --out file.bin.p7s` | PKCS#7 分离签名 |
| `varwof sign --embed --ca "MyCorp CodeSign CA" --in file.bin` | PKCS#7 嵌入式签名 |
| `varwof sign --verify --in file.bin --sig file.bin.p7s` | 验证分离签名 |
| `varwof verify --embed --in file.bin` | 验证嵌入式签名 |

### RBAC 与用户

| 命令 | 作用 |
|------|------|
| `varwof user add --name alice --password <pass> --role admin` | 添加用户 |
| `varwof user list` | 列出用户 |
| `varwof user passwd --name alice` | 修改密码 |
| `varwof rbac mode -enterprise` | 切换 RBAC 企业模式 |
| `varwof rbac scope --list` | 查看 RBAC 范围 |

### 信任锚

| 命令 | 作用 |
|------|------|
| `varwof trust import --file root-ca.pem` | 导入信任锚 |
| `varwof trust list` | 列出信任锚 |
| `varwof trust info --hash <hash>` | 信任锚详情 |
| `varwof trust trust/untrust --hash <hash>` | 标记信任/不信任 |

### 交叉证书

| 命令 | 作用 |
|------|------|
| `varwof cross-cert issue --issuer "MyCorp Root CA" --subject "Their Root CA"` | 签发交叉证书 |
| `varwof cross-cert list` | 列出交叉证书 |
| `varwof trust-bridge issue --ca "MyCorp Root CA"` | 建立信任桥 |

### 服务

| 命令 | 作用 |
|------|------|
| `varwof serve` | 启动全服务（API+TSA+OCSP+Web） |
| `varwof serve api` | 启动 API + Web UI 独立服务（HTTP） |
| `varwof serve tsa` | 启动 TSA 时间戳服务（HTTP, port :3180） |
| `varwof serve ocsp` | 启动 OCSP 响应服务（HTTP, port :9080） |
| `varwof serve crl` | 启动 CRL 分发服务（HTTP, port :8081） |

### 工具

| 命令 | 作用 |
|------|------|
| `varwof version` | 版本信息 |
| `varwof db backup --out backup.db` | 在线备份数据库 |
| `varwof db migrate` | 数据库迁移 |
| `varwof report --template soc2 --out report.pdf` | 生成 SOC2 合规报告 |
| `varwof init-config` | 生成示例配置 |
| `varwof ca list` | 列出所有 CA |
| `varwof ca info --name "MyCorp Root CA"` | CA 详情 |

---

## 二、三层 PKI 从零搭建

### 2.1 初始化

```bash
mkdir -p /opt/pki && cd /opt/pki
varwof init-full \
  -out-dir /opt/pki \
  -org ExampleCorp \
  -domain example.com \
  -hierarchy simple \
  -root-validity 7300 \
  -root ecdsa-p384 \
  -default-key-type ecdsa-p256
```

生成结构：

```
/opt/pki/
├── pki.json              # 配置文件
├── pki.db                # SQLite 数据库
├── root/                 # Root CA（20年）
│   ├── certs/ca.pem
│   └── private/ca.key
├── management/           # 管理子 CA（10年）
│   ├── certs/ca.pem
│   ├── private/ca.key
│   └── users/certs/      # 管理员证书（5张）
│       ├── admin.pem
│       ├── operator.pem
│       ├── auditor.pem
│       ├── readonly.pem
│       └── auto-renew.pem
├── tls/                  # TLS 子 CA（10年）
│   ├── certs/ca.pem
│   └── private/ca.key
│   └── api/certs/api.pem         # 网关证书
│   └── gateway/certs/gateway.pem # 服务证书
│   └── ocsp/certs/ocsp.pem       # OCSP 响应者
├── agent/                # Agent 子 CA
├── codesign/             # 代码签名子 CA
├── tsa/                  # 时间戳子 CA
│   └── tsa/certs/tsa-signer.pem
├── hr/                   # HR 子 CA
├── vpn/                  # VPN 子 CA
└── acme/                 # ACME 自动注册子 CA
```

### 2.2 层级关系

```
ExampleCorp Root CA (无 pathLen 限制, ECDSA P-384, 20年)
  │
  ├── ExampleCorp Management CA (pathLen=1, ECDSA P-256, 10年)
  │   ├── admin@example.com      (m-admin, clientAuth)
  │   ├── operator@example.com   (m-operator, clientAuth)
  │   ├── auditor@example.com    (m-auditor, clientAuth)
  │   ├── readonly@example.com   (m-readonly, clientAuth)
  │   └── auto-renew@example.com (m-auto-renew, clientAuth)
  │
  ├── ExampleCorp TLS CA (pathLen=1, ECDSA P-256, 10年)
  │   ├── api.example.com          (tls-server, serverAuth+clientAuth)
  │   ├── gateway.example.com      (tls-server, serverAuth+clientAuth)
  │   ├── ocsp.example.com         (ocsp-signer, OCSP Signing)
  │   └── 可签发任意 TLS 客户端/服务器证书
  │
  ├── ExampleCorp Agent CA (pathLen=1, ECDSA P-256, 10年)
  ├── ExampleCorp CodeSign CA (pathLen=1, RSA 4096, 10年)
  ├── ExampleCorp TSA CA (pathLen=1, RSA 4096, 10年)
  ├── ExampleCorp HR CA (pathLen=1, ECDSA P-256, 10年)
  ├── ExampleCorp VPN CA (pathLen=1, ECDSA P-256, 10年)
  └── ExampleCorp ACME CA (pathLen=1, ECDSA P-256, 10年)
```

### 2.3 签发企业需要的证书

```bash
# 1) TLS 服务证书（Web 服务器）
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "www.example.com" \
  --san "DNS:www.example.com,DNS:api.example.com,IP:10.0.0.1" \
  --profile tls-server \
  --out /opt/pki/certs/www.pem

# 2) 微服务证书（内部 mTLS）
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "svc-order.internal" \
  --san "DNS:svc-order.internal,DNS:localhost" \
  --profile tls-server \
  --out /opt/pki/certs/svc-order.pem

# 3) 开发人员客户端证书
varwof issue --ca "ExampleCorp Management CA" \
  --cn "zhangsan@example.com" \
  --profile m-admin \
  --out /opt/pki/certs/zhangsan.pem

# 4) 运维人员客户端证书
varwof issue --ca "ExampleCorp Management CA" \
  --cn "lisi@example.com" \
  --profile m-operator \
  --out /opt/pki/certs/lisi.pem

# 5) 审计人员证书
varwof issue --ca "ExampleCorp Management CA" \
  --cn "auditor@example.com" \
  --profile m-auditor \
  --out /opt/pki/certs/auditor.pem

# 6) VPN 客户端
varwof issue --ca "ExampleCorp VPN CA" \
  --cn "mobile-user-1" \
  --profile vpn-client \
  --out /opt/pki/certs/vpn-user1.pem

# 7) VPN 服务器
varwof issue --ca "ExampleCorp VPN CA" \
  --cn "vpn.example.com" \
  --profile vpn-server \
  --out /opt/pki/certs/vpn-server.pem

# 8) 代码签名
varwof issue --ca "ExampleCorp CodeSign CA" \
  --cn "devops@example.com" \
  --profile codesigning \
  --out /opt/pki/certs/codesign.pem

# 9) S/MIME 邮件证书
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "user@example.com" \
  --san "email:user@example.com" \
  --profile email \
  --out /opt/pki/certs/smime.pem
```

---

## 三、四层 PKI 从零搭建

### 3.1 初始化

```bash
mkdir -p /opt/pki-enterprise && cd /opt/pki-enterprise
varwof init-full \
  -out-dir /opt/pki-enterprise \
  -org BigCorp \
  -domain bigcorp.com \
  -hierarchy enterprise \
  -root-validity 7300 \
  -root ecdsa-p384
```

### 3.2 层级关系

```
BigCorp Root CA (无 pathLen 限制, ECDSA P-384, 20年)
  │
  └── BigCorp Policy CA (pathLen=2, ECDSA P-384, 10年)  ← 策略缓冲层
        │
        ├── BigCorp Management CA (pathLen=1, ECDSA P-256, 5年)
        ├── BigCorp TLS CA       (pathLen=1)
        ├── BigCorp Agent CA     (pathLen=1)
        ├── BigCorp CodeSign CA  (pathLen=1)
        ├── BigCorp TSA CA       (pathLen=1)
        ├── BigCorp HR CA        (pathLen=1)
        ├── BigCorp VPN CA       (pathLen=1)
        └── BigCorp ACME CA      (pathLen=1)
```

Policy CA 是四层 vs 三层的唯一区别——它是策略缓冲层：Root CA 离线保存后，Policy CA 可在不触碰 Root 的前提下调整子 CA 策略。

### 3.3 签发证书（与三层相同）

```bash
# 注意：--ca 参数填写子 CA 名称，路径会增加 policy 层级
varwof issue --ca "BigCorp TLS CA" \
  --cn "web.bigcorp.com" \
  --san "DNS:web.bigcorp.com,IP:10.10.0.1" \
  --profile tls-server \
  --out /opt/pki-enterprise/certs/web.pem

# 链验证需要完整传递
openssl verify \
  -CAfile /opt/pki-enterprise/root/certs/ca.pem \
  -untrusted /opt/pki-enterprise/policy/certs/ca.pem \
  -untrusted /opt/pki-enterprise/tls/certs/ca.pem \
  /opt/pki-enterprise/certs/web.pem
```

---

## 四、证书验证速查

### OpenSSL

```bash
# 链验证（三层）
openssl verify -CAfile root/certs/ca.pem \
  -untrusted tls/certs/ca.pem \
  certs/server.pem

# 链验证（四层）
openssl verify -CAfile root/certs/ca.pem \
  -untrusted policy/certs/ca.pem \
  -untrusted tls/certs/ca.pem \
  certs/server.pem

# 查看证书详情
openssl x509 -in cert.pem -noout -text \
  | grep -E "Subject:|Issuer:|Not Before|Not After|CA:|AIA|CRL|SAN|EKU|Key Usage"

# CRL 签名验证
openssl crl -CAfile ca.pem -in crl.crl -noout -verify

# TSA 时间戳验证
openssl ts -verify -data file.txt -in response.tsr \
  -CAfile root/certs/ca.pem \
  -untrusted tsa/certs/ca.pem

# OCSP 查询
openssl ocsp -issuer tls/certs/ca.pem \
  -cert certs/server.pem \
  -url http://127.0.0.1:9080/ocsp \
  -verify_other tls/ocsp/certs/ocsp.pem \
  -CAfile tls/certs/ca.pem -trust_other
```

### Java Keytool

```bash
# 导入信任链
keytool -importcert -trustcacerts -alias root \
  -file root/certs/ca.pem \
  -keystore truststore.jks -storepass changeit -noprompt

keytool -importcert -trustcacerts -alias sub \
  -file tls/certs/ca.pem \
  -keystore truststore.jks -storepass changeit -noprompt

# 查看证书
keytool -printcert -file cert.pem
```

### NSS certutil

```bash
# 创建 NSS DB
mkdir -p /tmp/nssdb
certutil -d sql:/tmp/nssdb -N --empty-password

# 导入信任链
certutil -d sql:/tmp/nssdb -A -t "CT,CT,CT" -n "Root CA" -i root/certs/ca.pem
certutil -d sql:/tmp/nssdb -A -t "CT,CT,CT" -n "Sub CA" -i tls/certs/ca.pem

# 验证服务器证书
certutil -d sql:/tmp/nssdb -A -t "u,u,u" -n "server" -i cert.pem
certutil -d sql:/tmp/nssdb -V -n "server" -u "V"

# 验证客户端证书
certutil -d sql:/tmp/nssdb -V -n "client" -u "C"
```

---

## 五、架构选型建议

| 场景 | 推荐层级 | 理由 |
|------|----------|------|
| 创业公司 (<50 人) | 三层 (simple) | 简单、Root CA 直接签子 CA |
| 中小企业 (50-500 人) | 三层 (simple) | 足够 |
| 大型企业 (>500 人) | 四层 (enterprise) | Policy CA 策略缓冲，Root CA 可离线 |
| 金融机构 / 监管 | 四层 (enterprise) | 合规要求，审计追溯，策略隔离 |
| 多数据中心 / 跨国 | 四层 (enterprise) | 每个区域独立 Policy CA |

### Key Size 建议

| 用途 | 推荐算法 | 有效期 |
|------|----------|--------|
| Root CA | ECDSA P-384 | 20 年 |
| Policy CA（企业级） | ECDSA P-384 | 10 年 |
| 子 CA | ECDSA P-256 | 5-10 年 |
| TLS 服务证书 | ECDSA P-256 | 1 年 |
| 管理员证书 | ECDSA P-256 | 1 年 |
| 代码签名 | RSA 4096 | 3 年 |
| TSA 签名者 | RSA 4096 | 5 年 |

---

## 六、服务部署

### 启动全部服务

```bash
# 编辑配置，确认端口
vim pki.json
# serve.addr: ":4430"        # HTTP API
# serve.tls_addr: ":4433"    # HTTPS mTLS API
# tsa.addr: ":3180"          # TSA
# ocsp.addr: "127.0.0.1:9080" # OCSP
# crl.addr: ":8081"          # CRL 分发

# 启动
varwof serve
```

### 分离部署（推荐）

```bash
# API + Web UI（对外）
varwof serve api

# TSA 时间戳（单独端口）
varwof serve tsa

# OCSP 响应器（内部）
varwof serve ocsp

# CRL 分发（纯 HTTP）
varwof serve crl
```

### nginx 反向代理示例

```nginx
server {
    listen 80;
    server_name pki.example.com;

    # CRL 分发 - 纯 HTTP
    location /crl/ {
        proxy_pass http://127.0.0.1:8081;
    }

    # OCSP 响应
    location /ocsp/ {
        proxy_pass http://127.0.0.1:9080;
    }
}

server {
    listen 443 ssl;
    server_name pki.example.com;

    ssl_certificate /opt/pki/tls/api/certs/api.pem;
    ssl_certificate_key /opt/pki/tls/api/private/api.key;

    # mTLS 管理 API（管理员证书）
    location /api/ {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

---

## 七、常见问题

### Q: CRL 为什么不走 HTTPS？

CRL 分发使用纯 HTTP 以兼容所有客户端。RFC 5280 允许 CRL 通过 HTTP 分发。CRL 本身有签名，防篡改不依赖传输层。

### Q: 证书中的 AIA/CRLDP 地址是什么？

签发的证书自动嵌入：
- **OCSP URL**：`http://ocsp.域名/ocsp` — 在线吊销查询
- **Issuer URL**：`http://域名/pki` — 签发者证书下载
- **CRL DP**：`http://域名/crl/子CA名称.crl` — CRL 下载地址

均使用 HTTP 以确保兼容性。

### Q: 过期证书在哪？

数据库永久保留。CRL 只包含过期但未到期（`not_after >= now`）的已吊销证书。过期证书不在 CRL 中，但在 `varwof list` 可查。

### Q: Root CA pathLen 为什么无限制？

根据 X.509 规范，Root CA 不设 pathLen 限制（CA:TRUE 即可，无 pathlen 约束），由 Policy CA / 子 CA 逐级限制。

### Q: 如何离线保存 Root CA 密钥？

```bash
varwof ca cold-backup backup \
  --key /opt/pki/root/private/ca.key \
  --out /backup/root-key.enc
```

详情见 `dev-docs/RootKeySecurity_CN.md`。

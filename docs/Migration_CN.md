# PKI 迁移报告：pn41 OpenSSL → pki 工具 + varwof.org → varwof.com

> **日期：** 2026-07-01
> **源：** OpenSSL 手工 CA（`/etc/pki/`，域 `*.varwof.org`）
> **目标：** `pki` 工具管理（`/etc/pki-new/`，域 `*.varwof.com`）

## 背景

pn41 承载全部内网 PKI 基础设施——邮件、DNS、Web、SVN、Syncthing、NAS、OCSP、TSA。原有 PKI 基于 OpenSSL 手工签发，3 个 CA（Root / Issuing / TSA）+ 9 份服务证书，域名后缀 `varwof.org`。

问题：
- CRL 更新需手动 shell 脚本
- OCSP 用 `openssl ocsp` 命令（重启才刷新 index.txt、HTTP 头解析脆弱）
- TSA 用 Python 包装 `openssl ts -reply`
- 签发靠 `issue-cert.sh` 脚本，无数据库审计追踪
- 域名 varwof.org 与 CoreDNS 区 varwof.com 不一致

## 迁移步骤

### 1. 调研现有 PKI

```bash
# 读取全部 CA 证书信息
ssh pn41 "sudo cat /etc/pki/root/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"
ssh pn41 "sudo cat /etc/pki/issuing/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"
ssh pn41 "sudo cat /etc/pki/tsa/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"

# 列出全部服务证书和私钥
ssh pn41 "sudo find /etc -name '*.pem' -o -name '*.key' | grep -v usr/share | grep -v ca-certificates"

# 读取 nginx/Postfix/Dovecot/Syncthing 配置中的证书路径
ssh pn41 "sudo cat /etc/nginx/sites-enabled/www-varwof"
ssh pn41 "sudo cat /etc/nginx/sites-enabled/svn-varwof"
ssh pn41 "sudo grep 'smtpd_tls_cert\|ssl_server_cert' /etc/postfix/main.cf /etc/dovecot/conf.d/10-ssl.conf"
```

> 发现：CoreDNS 区是 `varwof.com`，但证书主题是 `varwof.org`——DNS 与 PKI 域名不一致。

### 2. 搭建新 PKI（本地生成）

```bash
# 建目录
mkdir -p /tmp/pki-migration/pki/{root,issuing,tsa,ocsp,tsa-signer,www,svn,syncthing,nas,coredns}/{certs,private}
mkdir -p /tmp/pki-migration/pki/www/pki/crl

# 建配置（含 default_org / default_country）
cat > /tmp/pki-migration/pki.json << 'EOF'
{ "db": "/tmp/pki-migration/pki.db",
  "defaults": { "ca": "issuing", "profile": "tls-server",
    "default_org": "Varwof", "default_country": "CN" },
  "cas": {
    "Varwof Root CA": {"cert":"pki/root/certs/ca.pem","key":"pki/root/private/ca.key"},
    "Varwof Issuing CA": {"cert":"pki/issuing/certs/ca.pem","key":"pki/issuing/private/ca.key"},
    "Varwof TSA CA": {"cert":"pki/tsa/certs/ca.pem","key":"pki/tsa/private/ca.key"}
  },
  "ca": {"crl_url":"http://www.varwof.com/pki/crl/issuing.crl",
         "ocsp_url":"http://ocsp.varwof.com:9080",
         "issuer_url":"http://www.varwof.com/pki/issuing.pem" },
  "serve": {"addr":":4431"} }
EOF

# Root CA（P-384, 20年）
./varwof init-ca -config pki.json -name "Varwof Root CA" \
  -key-type ecdsa-p384 -validity 7300 -profile root-ca \
  -out-cert pki/root/certs/ca.pem -out-key pki/root/private/ca.key

# Issuing CA（P-384, 10年, 由 Root 签署）
./varwof init-ca -config pki.json -name "Varwof Issuing CA" \
  -parent "Varwof Root CA" -parent-key pki/root/private/ca.key \
  -key-type ecdsa-p384 -validity 3650 -profile sub-ca \
  -permitted-dns "varwof.com,varwof.org" \
  -out-cert pki/issuing/certs/ca.pem -out-key pki/issuing/private/ca.key

# TSA CA（P-384, 10年, 由 Root 签署）
./varwof init-ca -config pki.json -name "Varwof TSA CA" \
  -parent "Varwof Root CA" -parent-key pki/root/private/ca.key \
  -key-type ecdsa-p384 -validity 3650 -profile sub-ca \
  -out-cert pki/tsa/certs/ca.pem -out-key pki/tsa/private/ca.key
```

#### 问题 1：Root CA 的 O=example.com

`init-ca` 第一次生成时用了 O=example.com，因为配置字段名不对。

**解决：** 配置里的组织字段是 `default_org` 和 `default_country`（非 `org`/`country`）。修正配置后重建 DB 重新生成。

```json
"defaults": {
    "default_org": "Varwof",
    "default_country": "CN"
}
```

### 3. 签发服务证书

```bash
# OCSP 签名证书（Issuing CA, 5年, EKU=OCSPSigning）
./varwof issue -config pki.json -ca "Varwof Issuing CA" \
  -cn "Varwof OCSP Responder" -profile ocsp-signer -validity 1825 \
  -subject "/C=CN/O=Varwof/OU=OCSP Responder/CN=Varwof OCSP Responder" \
  -out pki/ocsp/certs/ocsp.pem -out-key pki/ocsp/private/ocsp.key

# TSA 签名证书（TSA CA, 5年, EKU=timeStamping）
./varwof issue -config pki.json -ca "Varwof TSA CA" \
  -cn "Varwof TSA" -profile timestamp -validity 1825 \
  -subject "/C=CN/O=Varwof/OU=Time Stamping Authority/CN=Varwof TSA" \
  -out pki/tsa-signer/certs/tsa-signer.pem -out-key pki/tsa-signer/private/tsa-signer.key

# 全部服务证书（Issuing CA, P-256, 2年）
PROF="tls-server -validity 730"
SUBJ="/C=CN/O=Varwof/OU=Services/CN="
CA="Varwof Issuing CA"

# dns
./varwof issue -config pki.json -ca "$CA" -cn "dns.varwof.com" -profile $PROF \
  -subject "${SUBJ}dns.varwof.com" \
  -san "DNS:ns1.varwof.com,IP:TAILSCALE_IP_1,IP:INTERNAL_IP" \
  -out pki/coredns/certs/varwof.pem -out-key pki/coredns/private/varwof.key

# mail
./varwof issue -config pki.json -ca "$CA" -cn "mail.varwof.com" -profile $PROF \
  -subject "${SUBJ}mail.varwof.com" \
  -san "DNS:mail.varwof.com,DNS:smtp.varwof.com,DNS:imap.varwof.com,DNS:autoconfig.varwof.com,DNS:autodiscover.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2" \
  -out pki/mail.pem -out-key pki/mail.key

# www
./varwof issue -config pki.json -ca "$CA" -cn "www.varwof.com" -profile $PROF \
  -subject "${SUBJ}www.varwof.com" \
  -san "DNS:www.varwof.com,DNS:varwof.com" \
  -out pki/www/certs/www.varwof.com.pem -out-key pki/www/private/www.varwof.com.key

# svn
./varwof issue -config pki.json -ca "$CA" -cn "svn.varwof.com" -profile $PROF \
  -subject "${SUBJ}svn.varwof.com" \
  -san "DNS:svn.varwof.com" \
  -out pki/svn/certs/svn.varwof.com.pem -out-key pki/svn/private/svn.varwof.com.key

# syncthing
./varwof issue -config pki.json -ca "$CA" -cn "syncthing.varwof.com" -profile $PROF \
  -subject "${SUBJ}syncthing.varwof.com" \
  -san "DNS:syncthing.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2,IP:127.0.0.1" \
  -out pki/syncthing/certs/syncthing.varwof.com.pem -out-key pki/syncthing/private/syncthing.varwof.com.key

# nas1
./varwof issue -config pki.json -ca "$CA" -cn "nas1.varwof.com" -profile $PROF \
  -subject "${SUBJ}nas1.varwof.com" \
  -san "DNS:nas1.varwof.com,IP:192.168.6.6" \
  -out pki/nas/certs/nas1.varwof.com.pem -out-key pki/nas/private/nas1.varwof.com.key

# nas2
./varwof issue -config pki.json -ca "$CA" -cn "nas2.varwof.com" -profile $PROF \
  -subject "${SUBJ}nas2.varwof.com" \
  -san "DNS:nas2.varwof.com,IP:192.168.6.7" \
  -out pki/nas/certs/nas2.varwof.com.pem -out-key pki/nas/private/nas2.varwof.com.key
```

#### 问题 2：通配符 SAN DNS:* 不被接受

签发 DNS 证书时加了 `DNS:*.varwof.com`：

```
sign: parse SANs: invalid DNS SAN: DNS:*.varwof.com
```

**原因：** `pki` 的 SAN 解析器做了语法严格校验，通配符前缀 `*.` 不被接受。

**解决：** 已修复 `internal/ca/sign.go:548` 正则 `validDNS`，增加 `^(\*\.)?` 前缀支持合法通配符。迁移时手工绕过（改用明确 SAN 列表 `DNS:ns1.varwof.com,IP:TAILSCALE_IP_1,IP:INTERNAL_IP`），修复后 `--san "DNS:*.varwof.com"` 可直接使用。

#### 问题 3：CA 名称不在配置中

```
CA "Varwof Issuing CA" not found in config
```

**原因：** `varwof init-ca` 把 CA 存入了数据库，但 `varwof issue` 从配置文件的 `cas` 段查找 CA 文件路径（非数据库查找）。

**解决：** 在 `pki.json` 中加入 `cas` 段：

```json
"cas": {
  "Varwof Root CA": {"cert": "pki/root/certs/ca.pem", "key": "pki/root/private/ca.key"},
  "Varwof Issuing CA": {"cert": "pki/issuing/certs/ca.pem", "key": "pki/issuing/private/ca.key"},
  "Varwof TSA CA": {"cert": "pki/tsa/certs/ca.pem", "key": "pki/tsa/private/ca.key"}
}
```

#### 问题 4：通配符 DNS SAN 违反 Name Constraints

syncthing 证书的第一个版本包含了 SAN `syncthing`（裸主机名，无域名后缀）：

```
openssl verify ... syncthing.varwof.com.pem
error 47 at 0 depth lookup: permitted subtree violation
```

**原因：** Issuing CA 设置了 `-permitted-dns "varwof.com,varwof.org"` Name Constraints，SAN `syncthing`（不带 `.`）不在许可子树内。

**解决：**
1. 从 SAN 中移除裸主机名 `syncthing`
2. 撤销旧版本证书
3. 重新签发（因 `issue` 命令有重复 CN 检测，需先 `revoke`）

```bash
./varwof revoke -config pki.json -ca "Varwof Issuing CA" -serial <旧串号>
./varwof issue ... -san "DNS:syncthing.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2,IP:127.0.0.1"
```

#### 问题 5：重复 CN 阻止重新签发

```
sign: insert cert to db: duplicate CN "syncthing.varwof.com": active cert ... already exists
```

**原因：** `issue` 命令检查 DB 中是否有相同 CN 的有效（`status='V'`）证书。

**解决：** 先 revoke 再 issue。

### 4. 导入旧 PKI 作为信任锚

```bash
# 从 pn41 获取旧 CA 证书
ssh pn41 "sudo cat /etc/pki/root/certs/ca.pem" > /tmp/pki-migration/old-root.pem
ssh pn41 "sudo cat /etc/pki/issuing/certs/ca.pem" > /tmp/pki-migration/old-issuing.pem
ssh pn41 "sudo cat /etc/pki/tsa/certs/ca.pem" > /tmp/pki-migration/old-tsa.pem

# 导入 DB
./pki trust import -config pki.json -file old-root.pem
./pki trust import -config pki.json -file old-issuing.pem
./pki trust import -config pki.json -file old-tsa.pem
```

> 只有旧 Root CA（自签名）被导入。Issuing CA 和 TSA CA 非自签名，`trust import` 自动跳过。

### 5. 制作链文件

```bash
cat pki/mail.pem pki/issuing/certs/ca.pem > pki/mail.chain.pem
cat pki/www/certs/www.varwof.com.pem pki/issuing/certs/ca.pem > pki/www/certs/www.varwof.com.fullchain.pem
cat pki/svn/certs/svn.varwof.com.pem pki/issuing/certs/ca.pem > pki/svn/certs/svn.varwof.com.fullchain.pem
cat pki/syncthing/certs/syncthing.varwof.com.pem pki/issuing/certs/ca.pem > pki/syncthing/certs/syncthing.varwof.com.fullchain.pem
```

### 6. 部署到 pn41

```bash
# 跨平台编译
GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false go build -o pki-linux-amd64 ./cmd/pki/

# 复制文件
scp pki-linux-amd64 pn41:/tmp/pki-new
ssh pn41 sudo mv /tmp/pki-new /usr/local/bin/pki-new
ssh pn41 sudo chmod 755 /usr/local/bin/pki-new

# 建目录
ssh pn41 sudo mkdir -p /etc/pki-new/pki/{root,issuing,tsa,ocsp,tsa-signer,www,svn,syncthing,nas,coredns}/{certs,private}
ssh pn41 sudo mkdir -p /etc/pki-new/pki/www/pki/crl

# 复制全部 PEM 和 KEY 文件 + config + DB
scp pki-new.json pn41:/tmp/ && ssh pn41 sudo mv /tmp/pki-new.json /etc/pki-new/pki.json
# ... 逐个复制所有 cert/key/db 文件
```

### 7. 更新 Nginx 配置

```nginx
server {
    listen 443 ssl;
    server_name www.varwof.com varwof.com www.varwof.org varwof.org;
    ssl_certificate     /etc/pki-new/pki/www/certs/www.varwof.com.fullchain.pem;
    ssl_certificate_key /etc/pki-new/pki/www/private/www.varwof.com.key;
    ssl_trusted_certificate /etc/pki-new/pki/www/pki/issuing.pem;
    ...
}
```

旧配置引用的是 `/etc/pki/www/` 下的 `varwof.org` 文件，需将域名和路径同时更新。

### 8. 替换 OCSP/TSA 服务

旧服务（OpenSSL-based）：

```ini
# ocsp-responder.service
ExecStart=/usr/bin/openssl ocsp -port 9080 -index /etc/pki/issuing/index.txt -CA ...

# tsa-responder.service
# Python 包装 openssl ts -reply
```

新服务（pki）：

```ini
# pki-ocsp.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json serve ocsp

# pki-tsa.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json serve tsa
```

#### 问题 6：旧 OCSP 因 HTTP 头解析崩溃

```
ocsp: cannot parse HTTP header: missing end of line
```

旧 `openssl ocsp` 命令的已知问题——HTTP 请求头解析脆弱。迁到 `varwof serve ocsp` 后不再出现。

### 9. 配置 CRL 自动化

```ini
# pki-crl.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json crl

# pki-crl.timer
OnCalendar=daily
```

系统默认的 `varwof crl` 命令从 DB 生成 CRL，不再依赖 OpenSSL index.txt。

### 10. 验证清单

```bash
# 链验证（所有证书）
for cert in pki/coredns/certs/varwof.pem pki/mail.pem pki/www/certs/www.varwof.com.pem ...; do
  openssl verify -CAfile root.pem -untrusted issuing.pem "$cert"
done

# TLS 握手
echo "Q" | openssl s_client -connect host:port -starttls smtp -CAfile root.pem -servername sn

# OCSP 查询
openssl ocsp -issuer issuing.pem -cert mail.pem -url http://...:9080 -CAfile root.pem

# TSA 查询
echo "test" | openssl ts -query -data /dev/stdin -no_nonce -sha256 | \
  curl -s -H "Content-Type: application/timestamp-query" --data-binary @- http://...:3180 | \
  openssl ts -reply -in /dev/stdin -text
```

## 迁移后架构

```
/usr/local/bin/pki-new          # 单二进制
/etc/pki-new/                   # 配置 + DB + 全部证书
├── pki.json                    # 主配置
├── pki.db                      # SQLite（含 CA 元数据、签发记录、审计日志）
└── pki/
    ├── root/certs/ca.pem       # Root CA（公钥分发）
    ├── issuing/certs/ca.pem    # Issuing CA
    ├── tsa/certs/ca.pem        # TSA CA
    ├── www/pki/                # HTTP 可访问的 PKI 文件
    ├── ocsp/certs/ocsp.pem     # OCSP 签名证书
    └── tsa-signer/certs/*.pem  # TSA 签名证书

systemd 服务：
  pki-ocsp.service   :9080     # OCSP 响应器
  pki-tsa.service    :3180     # TSA 时间戳
  pki-crl.timer                # 每日 CRL 生成
```

## 问题汇总

| # | 问题 | 根因 | 解决 |
|---|---|---|---|
| 1 | Root CA 的 O=example.com | 配置字段 `default_org` 非 `org` | 修正配置字段名 |
| 2 | 通配符 SAN `DNS:*` 不合法 | SAN 解析器不支持通配符 | 修复 `internal/ca/sign.go` 正则（`^(\*\.)?`），已合入源码 |
| 3 | CA not found in config | issue 从配置找 CA 路径，不从 DB | 添加 `cas` 配置段 |
| 4 | Name Constraints 违反 | 裸主机名 SAN 不在许可 DNS 子树 | 移除裸 SAN |
| 5 | 重复 CN 阻止签发 | 重复 CN 检测 | 先 revoke 再 issue |
| 6 | 旧 OCSP HTTP 解析崩溃 | `openssl ocsp` 脆弱 | 换 `varwof serve ocsp` |
| 7 | 跨平台 `--config` 参数用 `-` 而非 `--` | 忘记双横线 | 文档提示 |

## 后续

- NAS 证书通过 Web 界面上传
- 客户端安装 Root CA `/etc/pki-new/pki/root/certs/ca.pem`
- 部署 `varwof serve api` 提供 REST API
- Root CA 密钥离线冷备

# PKI 层级设置

本指南介绍如何设置完整的 PKI 层级，包括根 CA 和业务子 CA。

## 快速设置（init-full）

创建完整 PKI 的最快方式：

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --root-key-type ecdsa-p256 \
  --root-validity 8760d \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki \
  --encrypt-keys
```

这将创建：

```
/opt/pki/
├── root/
│   ├── certs/ca.pem          根 CA 证书
│   └── private/ca.key        根 CA 私钥
├── management/
│   ├── certs/ca.pem          管理 CA
│   └── private/ca.key
├── tls/
│   ├── certs/ca.pem          TLS 服务器 CA
│   └── private/ca.key
├── people/
│   ├── certs/ca.pem          People/用户 CA
│   └── private/ca.key
├── codesign/
│   ├── certs/ca.pem          代码签名 CA
│   └── private/ca.key
├── tsa/
│   ├── certs/ca.pem          TSA CA
│   └── private/ca.key
├── hr/
│   ├── certs/ca.pem          HR CA
│   └── private/ca.key
├── vpn/
│   ├── certs/ca.pem          VPN CA
│   └── private/ca.key
├── acme/
│   ├── certs/ca.pem          ACME CA
│   └── private/ca.key
├── server.pem                服务器 TLS 证书
├── server.key                服务器 TLS 私钥
└── pki.json                  配置文件
```

## 手动设置

### 第 1 步：初始化根 CA

```bash
pki ca init \
  --name "Root CA" \
  --key-type ecdsa-p256 \
  --validity 8760d \
  --out-cert root/ca.pem \
  --out-key root/ca.key
```

### 第 2 步：初始化子 CA

```bash
# TLS 服务器 CA
pki ca init \
  --name "TLS CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert tls/ca.pem \
  --out-key tls/ca.key \
  --permitted-dns "*.example.com"

# People CA
pki ca init \
  --name "People CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert people/ca.pem \
  --out-key people/ca.key

# 代码签名 CA
pki ca init \
  --name "CodeSign CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type rsa-4096 \
  --validity 3650d \
  --out-cert codesign/ca.pem \
  --out-key codesign/ca.key
```

### 第 3 步：配置 `pki.json`

```json
{
  "cas": {
    "root": {
      "cert": "/opt/pki/root/certs/ca.pem",
      "key": "/opt/pki/root/private/ca.key"
    },
    "tls": {
      "cert": "/opt/pki/tls/certs/ca.pem",
      "key": "/opt/pki/tls/private/ca.key"
    },
    "people": {
      "cert": "/opt/pki/people/certs/ca.pem",
      "key": "/opt/pki/people/private/ca.key"
    },
    "codesign": {
      "cert": "/opt/pki/codesign/certs/ca.pem",
      "key": "/opt/pki/codesign/private/ca.key"
    }
  },
  "defaults": {
    "ca": "tls",
    "profile": "tls-server"
  }
}
```

### 第 4 步：启动服务器

```bash
pki serve --config pki.json
```

## CA 角色和用途

| CA | 用途 | 密钥类型 | 有效期 |
|----|------|---------|--------|
| Root CA | 信任锚点，签署子 CA | ECDSA P-256 | 10 年 |
| TLS CA | 服务器/客户端 TLS 证书 | ECDSA P-256 | 5 年 |
| People CA | 用户/员工证书 | ECDSA P-256 | 5 年 |
| CodeSign CA | 代码签名证书 | RSA-4096 | 5 年 |
| TSA CA | 时间戳权威机构 | ECDSA P-256 | 5 年 |
| HR CA | HR 专用证书 | ECDSA P-256 | 5 年 |
| VPN CA | VPN 客户端证书 | ECDSA P-256 | 5 年 |
| ACME CA | 自动证书 | ECDSA P-256 | 5 年 |

## 证书配置文件

| 配置文件 | 用途 | 扩展 |
|---------|------|------|
| `tls-server` | Web 服务器、API | Server Auth EKU |
| `tls-client` | 客户端认证 | Client Auth EKU |
| `codesigning` | 代码签名 | Code Signing EKU |
| `ocsp-signer` | OCSP 响应器 | OCSP Signing EKU |
| `timestamp` | TSA 签名 | Time Stamping EKU |
| `email` | S/MIME | Email Protection EKU |
| `document` | 文档签名 | Document Signing EKU |
| `identity-user` | 身份证书 | 从身份源自动填充 |

## 名称约束

将子 CA 限制为特定域名：

```bash
pki ca init \
  --name "Web CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --permitted-dns "*.example.com" \
  --excluded-dns "*.internal.example.com" \
  --permitted-emails "@example.com" \
  --out-cert web/ca.pem \
  --out-key web/ca.key
```

## CA 密钥轮换

在到期前轮换 CA 主密钥：

```bash
# 检查轮换状态
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/tls/rotation

# 执行轮换
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/tls/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

轮换是原子的，带有双签名过渡期。

## 离线根 CA

为获得最高安全性，请保持根 CA 离线：

1. 在气隙机器上初始化根 CA
2. 仅将根 CA 证书复制到在线服务器
3. 在离线机器上使用 `pki ca offline-sign` 签署子 CA CSR
4. 将签署的子 CA 证书复制回在线服务器

```bash
# 在离线机器上
pki ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

## 冷备份

创建 CA 密钥的加密备份：

```bash
# 创建备份
pki ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json

# 验证备份
pki ca cold-backup verify \
  --backup backup.json \
  --password "backup-secret"
```

## 交叉认证

在独立 CA 之间建立信任：

```bash
# 签发交叉证书
pki cross-cert issue \
  --issuer-ca "External Root" \
  --subject-ca "My Root" \
  --validity 3650d

# 列出交叉证书
pki cross-cert list
```

## 信任桥联邦

跨组织联邦信任锚点：

```bash
# 导入信任锚点
pki trust import \
  --cert partner-ca.pem \
  --name "Partner CA"

# 列出信任锚点
pki trust list

# 建立信任桥
pki trust bridge issue \
  --ca "My Root" \
  --partner "Partner CA"
```

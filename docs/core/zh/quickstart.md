# 快速开始

本指南将引导您安装 Varwof Core、初始化 CA 并签发第一张证书。

## 前置条件

- Go 1.26+（从源码构建时需要）
- SQLite（内嵌，零配置）或 PostgreSQL/MySQL（可选）

## 安装

### 从源码构建

```bash
git clone https://github.com/varwof/core.git
cd core
go build -o pki ./cmd/pki/
```

### 通过 go install

```bash
go install github.com/varwof/core/cmd/pki@latest
```

### 验证

```bash
pki version
# varwof 1.1.1 linux/amd64 go1.26.x
```

## 生成配置

```bash
pki init-config > pki.json
```

编辑 `pki.json` 以设置组织名称、域名和数据库路径。默认数据库为 SQLite，路径为 `/etc/varwof/core/pki.db`。

需要修改的关键字段：

```json
{
  "db": "/etc/varwof/core/pki.db",
  "serve": {
    "addr": ":8443"
  },
  "defaults": {
    "ca": "Root CA",
    "org": "My Organization",
    "country": "US"
  }
}
```

## 初始化根 CA

```bash
pki ca init \
  --name "Root CA" \
  --key-type ecdsa-p256 \
  --validity 8760d \
  --out-cert root/ca.pem \
  --out-key root/ca.key
```

这将创建：
- `root/ca.pem` — 根 CA 证书（公钥）
- `root/ca.key` — 根 CA 私钥（请离线保存！）

## 初始化签发 CA

```bash
pki ca init \
  --name "Issuing CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert issuing/ca.pem \
  --out-key issuing/ca.key \
  --permitted-dns "*.example.com"
```

## 启动服务器

```bash
pki serve --config pki.json
```

服务器默认在 `:8443` 上启动。验证方式：

```bash
curl http://localhost:8443/healthz
```

## 签发证书

```bash
pki issue \
  --ca "Issuing CA" \
  --cn server.example.com \
  --san DNS:server.example.com,DNS:www.example.com \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --out-dir certs/ \
  --out-name server
```

这将创建：
- `certs/server.pem` — 证书
- `certs/server.key` — 私钥

验证证书：

```bash
openssl x509 -in certs/server.pem -text -noout
```

## 使用私钥加密签发

```bash
pki issue \
  --ca "Issuing CA" \
  --cn client.example.com \
  --san DNS:client.example.com \
  --profile tls-client \
  --encrypt \
  --encrypt-password "my-secret" \
  --out-dir certs/ \
  --out-name client
```

私钥使用 PBES2 (PKCS#8) 加密。

## 吊销证书

```bash
pki revoke --serial <serial> --ca "Issuing CA" --reason key-compromise
```

## 生成 CRL

```bash
pki crl --ca "Issuing CA" --out crl.pem
```

## 后续步骤

- [配置参考](configuration.md) — 所有配置选项
- [CLI 命令](commands.md) — 完整的命令参考
- [API 参考](api.md) — REST API 端点
- [部署指南](deployment.md) — 生产部署
- [PKI 层级](pki-hierarchy.md) — 包含 8 个子 CA 的完整 PKI 设置
- [架构](architecture.md) — 系统设计

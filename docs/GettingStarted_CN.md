# varwof 快速开始

## 1. 安装

```bash
go install github.com/varwof/core@latest
# 或从源码编译：
cd /home/varwof/src/go/pki
go build -o /usr/local/bin/pki ./cmd/pki/
```

验证：

```bash
varwof version
# varwof 1.0.0 linux/amd64 go1.26.2 (rev unknown, unknown)
```

---

## 2. 生成配置

```bash
varwof init-config > pki.json
```

替换示例域名为真实域名：

```bash
# sed -i 's|example\.com|mycompany.com|' pki.json
```

放入默认路径：

```bash
sudo mkdir -p /etc/pki
sudo cp pki.json /etc/varwof/core/
```

---

## 3. 初始化根 CA

```bash
sudo varwof init-ca \
  --name root \
  --profile root-ca \
  --key-type ecdsa-p256 \
  --validity 3650 \
  --out-cert /etc/varwof/core/root/certs/ca.pem \
  --out-key /etc/varwof/core/root/private/ca.key
```

---

## 4. 初始化签发 CA

```bash
sudo varwof init-ca \
  --name issuing \
  --profile sub-ca \
  --parent root \
  --key-type ecdsa-p256 \
  --validity 1825 \
  --out-cert /etc/varwof/core/issuing/certs/ca.pem \
  --out-key /etc/varwof/core/issuing/private/ca.key \
  --permitted-dns "varwof.com"
```

---

## 5. 启动服务器

```bash
sudo varwof serve --config /etc/varwof/core/pki.json
```

默认监听 `:8443`，验证：

```bash
curl http://localhost:8443/healthz
# {"status":"ok","version":"pki/1.0","db":"ok"}
```

---

## 6. 签发证书

```bash
varwof issue \
  --cn "server.varwof.com" \
  --profile tls-server \
  --ca issuing \
  --san "server.varwof.com" \
  --out-cert /tmp/server.pem \
  --out-key /tmp/server.key
```

用 openssl 验证：

```bash
openssl x509 -in /tmp/server.pem -text -noout | head -20
```

---

## 7. 后续

- **ACME** — 配置文件启用 `acme.enable: true`，自动签发证书
- **SCEP** — 启用 SCEP 支持路由器等网络设备入网
- **OCSP** — `:8443` 启动在线证书状态查询
- **TSA** — `:8443` 启动时间戳服务
- **Web 界面** — 访问 `http://localhost:8443/`
- **详细配置** — 参见 `docs/Configuration_CN.md`

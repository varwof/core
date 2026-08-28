# Varwof Core — PKI 基础设施

单个 Go 二进制文件的一体化 PKI 基础设施。用一个统一的系统替代 OpenSSL 封装、Python 服务和分散的工具链。

## 功能概览

- **完整的 PKI 层级**：一条命令创建根 CA + 8 个业务子 CA
- **ACME v2**（RFC 8555）：HTTP-01/DNS-01 验证、EAB、ARI 续期信息
- **SCEP**（RFC 8894）：企业环境设备注册
- **OCSP 响应器**（RFC 6960）：内存和磁盘后端缓存
- **TSA**（RFC 3161）：时间戳权威机构，支持自动续期
- **PKCS#7 签名**：分离式、嵌入式、CAdES-T 时间戳
- **证书透明度**：日志提交与 SCT 验证
- **RBAC**：简单/企业模式，按 CA 作用域划分，操作员证书绑定
- **注册机构**：多方审批工作流
- **LDAP 集成**：从目录自动填充主体 DN
- **密钥托管/恢复**：管理员 RSA 公钥加密
- **自动续期**：一次性或守护进程模式
- **信任桥联邦**：跨 CA 信任建立
- **远程 HSM 签名器**：可插拔密钥后端
- **内存引擎**：高吞吐量读写，异步批量持久化
- **合规报告**：SOC 2、PCI DSS、NIST、ISO PDF 报告
- **CP/CPS 生成**：RFC 3647 格式
- **Webhook/SMTP 通知**：证书生命周期事件
- **配置热重载**：SIGHUP 或轮询，原子处理程序切换
- **Web UI**：仪表板、证书管理、RA 工作流、拓扑视图
- **Windows 服务**：安装/卸载支持
- **国际化**：中文和英文

## 快速开始

```bash
# Install
go install github.com/varwof/core/cmd/pki@latest

# Generate config
pki init-config > pki.json

# Initialize root CA
pki ca init --name "Root CA" --key-type ecdsa-p256 --validity 8760d \
  --out-cert root/ca.pem --out-key root/ca.key

# Issue a certificate
pki issue --ca "Root CA" --cn server.example.com \
  --san DNS:server.example.com --profile tls-server \
  --out-dir certs/ --out-name server

# Start the server
pki serve --config pki.json
```

## 文档

| 文档 | 描述 |
|------|------|
| [快速开始](quickstart.md) | 安装、第一个 CA、第一张证书 |
| [命令参考](commands.md) | 完整的 CLI 命令参考 |
| [配置](configuration.md) | 所有配置选项 |
| [架构](architecture.md) | 系统设计和组件概览 |
| [API 参考](api.md) | REST API 端点 |
| [部署](deployment.md) | 生产部署指南 |
| [PKI 层级](pki-hierarchy.md) | 设置完整的 PKI 层级 |

## 项目结构

```
core/
├── cmd/pki/              CLI 入口点 (main.go)
├── internal/
│   ├── ca/               CA 签发引擎
│   ├── serve/            HTTP API 服务器
│   ├── config.go         配置结构体
│   ├── acme/             ACME v2 (RFC 8555)
│   ├── ocsp/             OCSP 响应器 (RFC 6960)
│   ├── tsa/              TSA 时间戳 (RFC 3161)
│   ├── dns/              DNS 服务器 (ACME DNS-01)
│   ├── pkcs7/            PKCS#7 代码签名
│   ├── pkcs12/           PFX 导出
│   ├── notifier/         Webhook 通知
│   ├── provisioner/      认证 (mTLS/Token/OIDC/Basic)
│   ├── routing/          路由规则引擎
│   ├── i18n/             国际化
│   ├── engine/           内存引擎
│   ├── secrets/          CA 密钥密码解析
│   ├── capregistry/      能力方案注册表
│   └── remotesigner/     HSM/远程签名器委托
├── auth/                 RBAC 策略、策略签名
├── deploy/               部署脚本
└── docs/                 文档
```

## 卫星项目

| 项目 | 描述 |
|------|------|
| varwof-gateway-{tcp,http,udp} | 三层安全网关 |
| varwof-protocols | EST/SCEP/CMP 协议 |
| pki-dns-server | DNS 服务器 |
| bridge-ldap | LDAP 桥接 |
| pki-pades | PAdES PDF 签名 |
| pki-deploy | 部署工具 |
| pki-webhook | Webhook 推送 |
| varwof-cli | CLI 管理工具 |
| user-signer | 远程签名服务 |
| pki-hsm-proxy | HSM 适配器 |
| console | Web 控制台 |

## 许可证

AGPL-3.0

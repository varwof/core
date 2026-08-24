# core 参考手册

> **本文档内容已整合到以下文档中：**

- **API 端点**: [API.md](API.md) / [openapi.yaml](openapi.yaml)
- **配置字段**: [Configuration_CN.md](Configuration_CN.md)
- **功能特性**: [FeatureOverview_CN.md](FeatureOverview_CN.md)
- **RFC 偏差**: [RFC_DEVIATIONS.md](RFC_DEVIATIONS.md)

## 架构概览

```
core (单二进制)
├── cmd/pki/          — CLI 入口
├── internal/
│   ├── ca/          — CA 签发引擎
│   ├── serve/       — HTTP API 服务器
│   ├── db/          — 数据库抽象（SQLite/PG/MySQL）
│   ├── acme/        — ACME v2 (RFC 8555)
│   ├── ocsp/        — OCSP 响应器 (RFC 6960)
│   ├── tsa/         — TSA 时间戳 (RFC 3161)
│   ├── dns/         — DNS 服务器
│   ├── pkcs7/       — PKCS#7 代码签名
│   ├── pkcs12/      — PFX 导出
│   ├── notifier/    — Webhook 通知
│   ├── provisioner/ — 认证方式（mTLS/Token/OIDC）
│   ├── routing/     — 路由规则引擎
│   └── i18n/        — 国际化
├── auth/            — RBAC 策略
└── deploy/          — 部署脚本
```

## 卫星项目

| 卫星 | 说明 |
|------|------|
| pki-gateway-{tcp,http,udp} | 三层安全网关 |
| pki-protocols | EST/SCEP/CMP 协议 |
| pki-dns-server | DNS 服务器 |
| pki-ldap-bridge | LDAP 桥接 |
| pki-pades | PAdES 签名 |
| pki-deploy | 部署工具 |
| pki-webhook | Webhook 推送 |
| varwof-cli | CLI 管理工具 |
| pki-signer | 远程签名服务 |
| pki-hsm-proxy | HSM 适配器 |
| pki-web-console | Web 控制台 |

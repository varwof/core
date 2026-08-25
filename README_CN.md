# pki · 内网 PKI 瑞士军刀

> ⚠️ **技术预览版** — 核心加密原语已通过 OpenSSL 互操作性验证，正持续进行 RFC 合规补全。

[![License](https://img.shields.io/badge/license-AGPL%203.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/core)](https://pkg.go.dev/github.com/varwof/core)

**单二进制，纯 Go，一分钟跑起你的私有 CA。**

[English](README.md)

> **纯 Go 实现**：全部功能均为纯 Go 实现，无需任何外部依赖。
> **系统要求**：无特殊要求。仅需一个 Go 编译的单一二进制文件。
> **目标用户**：个人开发者、小团队、K8s 开发集群。

## 快速开始

```bash
go build -o /usr/local/bin/pki ./cmd/pki/
pki init-ca --name root --profile root-ca --out-dir /etc/varwof/core/root
pki init-ca --name issuing --profile sub-ca --parent root --parent-key /etc/varwof/core/root/private/ca.key
pki serve
pki issue --cn server.example.com --san "DNS:server.example.com,IP:10.0.0.1" --profile tls-server
```

## 安装

```bash
go build -o /usr/local/bin/pki ./cmd/pki/
```

## 文档

| 文档 | 链接 |
|------|------|
| 快速开始 | [`docs/GettingStarted_CN.md`](docs/GettingStarted_CN.md) |
| 配置参考 | [`docs/Configuration_CN.md`](docs/Configuration_CN.md) |
| API 参考 | [`docs/API.md`](docs/API.md) |
| OpenAPI Spec | [`docs/openapi.yaml`](docs/openapi.yaml) |

core 是 varwof 生态的**核心 CA 引擎**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | AGPL-3.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |

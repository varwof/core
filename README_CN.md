# Varwof PKI

> ⚠️ **技术预览版** — 核心加密原语已通过 OpenSSL 互操作性验证，正持续进行 RFC 合规补全。
> **不可用于生产环境**。API 和功能可能在正式发布前发生变更。

[![License](https://img.shields.io/badge/license-AGPL%203.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/core)](https://pkg.go.dev/github.com/varwof/core)

**单二进制，纯 Go，一分钟跑起你的私有 CA。**

[English](README.md)

> **纯 Go 实现**：全部功能均为纯 Go 实现，无需任何外部依赖。
> **系统要求**：无特殊要求。仅需一个 Go 编译的单一二进制文件。
> **目标用户**：个人开发者、小团队、K8s 开发集群。

**语言**: Go 1.26 — **数据库**: SQLite（推荐，纯 Go）

## 性能

| 指标 | 结果 |
|---|---|
| 签名吞吐 | ~11,000 req/s（受签名计算限制的上限） |
| 企业负载 | 稳定支撑 833 AIC/s，p99 **5 ms**，内存约 800 MB 稳定，无背压、无 503 |

完整基准报告：[基准与测试](docs/bench/README_CN.md)。

## 快速开始

```bash
go build -o /usr/local/bin/varwof ./cmd/pki/
varwof init-ca --name root --profile root-ca --out-dir /etc/varwof/core/root
varwof init-ca --name issuing --profile sub-ca --parent root --parent-key /etc/varwof/core/root/private/ca.key
varwof serve
varwof issue --cn server.example.com --san "DNS:server.example.com,IP:10.0.0.1" --profile tls-server
```

## 安装

```bash
go build -o /usr/local/bin/varwof ./cmd/pki/
```

## 文档

| 文档 | 链接 |
|------|------|
| 快速开始 | [`docs/core/zh/quickstart.md`](docs/core/zh/quickstart.md) |
| 配置参考 | [`docs/core/zh/configuration.md`](docs/core/zh/configuration.md) |
| 部署 | [`docs/core/zh/deployment.md`](docs/core/zh/deployment.md) |
| 命令参考 | [`docs/core/zh/commands.md`](docs/core/zh/commands.md) |
| API 参考 | [`docs/core/zh/api.md`](docs/core/zh/api.md) |
| OpenAPI Spec | [`docs/openapi.yaml`](docs/openapi.yaml) |
| 基准与性能 | [`docs/bench/README_CN.md`](docs/bench/README_CN.md) |

core 是 varwof 生态的**核心 CA 引擎**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 许可证与商业使用

`varwof-core` 采用 [AGPL-3.0](LICENSE) 许可。不便采用 AGPL 的组织可申请**商业许可**。

Varwof 目前是独立个人项目。生态建设期（目标 1–2 年）内，商业许可**免费并按年授权**（每期 1 年，许可费 0；续签由 Varwof 决定，免费期内续签免费）。使用不受限制：不限实例/用户/签发量，可嵌入产品与 SaaS。若将来收费，提前 6 个月通知，被许可方可回退 AGPL-3.0。**排除区域：EU/EEA/英国/瑞士不提供商业许可。** 软件按“现状”提供，不承担任何担保与责任。

联系：**pki@varwof.com** | https://varwof.com

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | AGPL-3.0 / 商业许可 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |

## 社区

问题、反馈与移植状态：[AIC Discussions](https://github.com/varwof/aic-jwt/discussions)

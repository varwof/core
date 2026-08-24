# core 使用指南

> **本文档内容已整合到以下文档中：**

- **CLI 命令详解**: [GettingStarted_CN.md](GettingStarted_CN.md) § CLI 命令
- **配置使用**: [Configuration_CN.md](Configuration_CN.md)
- **API 调用**: [API.md](API.md)
- **部署使用**: [Deployment_CN.md](Deployment_CN.md)
- **端到端演示**: [EndToEndDemo_CN.md](EndToEndDemo_CN.md)

## 核心操作速查

| 操作 | CLI 命令 | API 端点 |
|------|---------|---------|
| 初始化 CA | `varwof init-ca` | — |
| 签发证书 | `varwof issue` | `POST /api/v1/certs` |
| 吊销证书 | `varwof revoke` | `POST /api/v1/certs/revoke` |
| 续签证书 | `varwof renew` | `POST /api/v1/certs/renew` |
| 生成 CRL | `varwof crl`（`--delta --since` 生成增量 CRL） | `POST /api/v1/crl/{ca}/generate`（`?delta=1&since=`） |
| 列出 CA | `varwof ca-list` | `GET /api/v1/ca` |
| 查看 CA | `varwof ca-info` | `GET /api/v1/ca/{name}` |
| 启动服务 | `varwof serve` | — |
| 批量签发 | `varwof batch` | `POST /api/v1/certs/batch` |
| 查询证书 | `varwof list` | `GET /api/v1/certs` |

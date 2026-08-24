# core 函数参考

> **本文档内容已整合到：[API.md](API.md) / [openapi.yaml](openapi.yaml)**

完整的 REST API 端点、请求/响应格式、错误码详见上述文档。

## CLI 命令参考

| 命令 | 说明 | 详见 |
|------|------|------|
| `varwof init-ca` | 初始化根 CA | GettingStarted_CN.md |
| `varwof issue` | 签发证书 | GettingStarted_CN.md |
| `varwof batch` | 批量签发 | GettingStarted_CN.md |
| `varwof renew` | 续签证书 | GettingStarted_CN.md |
| `varwof revoke` | 吊销证书 | GettingStarted_CN.md |
| `varwof crl` | 生成/查看 CRL | GettingStarted_CN.md |
| `varwof db` | 数据库操作 | GettingStarted_CN.md |
| `varwof csr` | 生成 CSR | GettingStarted_CN.md |
| `varwof sign` | 签名文件（PKCS#7 分离/嵌入/CAdES-T） | GettingStarted_CN.md |
| `varwof verify` | 验证 PKCS#7 签名（分离/嵌入） | GettingStarted_CN.md |
| `varwof verify-path` | 证书路径构建/验证引擎（含 RFC 5280 §6.1 策略处理，Policy Mappings / Constraints / Inhibit anyPolicy） | GettingStarted_CN.md |
| `varwof run` | 验证二进制分离签名后执行（自验证加载器） | GettingStarted_CN.md |
| `varwof import` | 导入证书/CA | GettingStarted_CN.md |
| `varwof export` | 导出证书 | GettingStarted_CN.md |
| `varwof user` | 用户管理 | GettingStarted_CN.md |
| `varwof token` | Token 管理 | GettingStarted_CN.md |
| `varwof serve` | 启动服务 | Deployment_CN.md |
| `varwof ct` | CT 日志操作 | GettingStarted_CN.md |
| `varwof notify` | 通知管理 | GettingStarted_CN.md |
| `varwof recover` | 密钥恢复 | GettingStarted_CN.md |
| `varwof report` | 合规报告 | GettingStarted_CN.md |
| `varwof policy` | 策略管理 | GettingStarted_CN.md |
| `varwof cpcps` | 生成 CP/CPS 合规文档（RFC 3647，含版本历史、--out-dir 发布目录、--separate 分离 CP） | Configuration_CN.md |
| `varwof sub-ca create/list/info` | 业务子 CA 管理（签发/列表/详情） | GettingStarted_CN.md |

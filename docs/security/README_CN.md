# 安全与权限（Security & RBAC）

本目录记录 varwof-core 的权限安全模型与授权验证结果，供安全审计与合规检查使用。

## 文档清单

| 文档 | 说明 |
|------|------|
| [RBAC 安全模型（证书优先）](zh/rbac-security-model.md) | 权限权威来源、非证书认证局限、管理子 CA 门禁、CA 作用域、路由 fail-closed、角色权限矩阵、审计入口 |
| [RBAC 授权验证报告 2026-08-28](zh/rbac-verification-2026-08-28.md) | 简单/企业双模式 × 378 项授权矩阵 + P0 安全断言的完整实测数据与复现方法 |
| [部署加固](zh/deployment-hardening.md) | 生产部署预检/维护清单（授权、TLS、密钥、限额、审计、运维） |
| [私钥卫生](zh/private-key-hygiene.md) | 密钥分类、权限规则、证书≠密钥陷阱、静态加密、轮换、备份恢复、反模式检查表 |
| [威胁模型与风险登记](zh/threat-model.md) | 资产/信任边界/攻击面，已修复与已接受风险的 R-编号登记，STRIDE 映射 |
| [审计日志与合规](zh/audit-compliance.md) | 审计模型与入口、Merkle 链完整性、PII 掩码、SOC2/PCI/NIST/ISO 证据生成 |

## 阅读路径

1. 先读 **安全模型**：理解"superadmin 仅证书 / 账号恒 operator / 管理子 CA 硬排除"三项权威规则。
2. 再读 **验证报告**：查看 378×2 项矩阵与 P0 探针的实测 HTTP 码与结论。
3. 需要改动权限时，编辑 `routes.json` 与 `internal/serve/routes_default.json`（保持一致），并运行 `scripts/verify-rbac-api.sh` 回归。
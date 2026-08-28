# 威胁模型与风险登记

> 版本：2026-08-28（与 commit `f7355b2` / `117e35b` / `cc46b20` / `d81c053` 对齐）
> 配套：`rbac-security-model.md`（防护机制）、`rbac-verification-2026-08-28.md`（验证证据）、
> `deployment-hardening.md`（部署侧控制）、`private-key-hygiene.md`（密钥控制）

本文档登记资产的信任边界、攻击面与**已修复/已接受的已知风险**，供审计人员
按 `R-编号` 跟踪，新增风险请沿用编号追加。

## 1. 资产清单

| 资产 | 关键性 | 存放 |
|------|--------|------|
| 根 CA / 签发 CA 私钥 | 最高 | 离线库房 / `keys/*/private/`（0600），或 `key_backend`(HSM) |
| 管理（m-*）证书私钥 + 对应证书 | 高（=superadmin 权威） | `management/users/private/`（0600） |
| 服务端 TLS 私钥 | 高 | `keys/server.key` |
| 数据库（含证书、审计链、密钥摘要） | 高 | `pki.db` / PostgreSQL |
| 路由表 `routes.json` / 角色策略 `authz.json` | 高（授权裁决） | 配置目录 + `policy_signing` 签名 |
| 授权/审计日志链 | 中-高 | 数据库 `audit_log`（Merkle 链） |
| 会话 / token / 账号哈希 | 中 | 数据库 |

## 2. 信任边界与假设

1. **授权信任根 = CA 私有签名密钥**：任何持有有效管理证书的实体视为可信主体，
   其角色/权限向量由证书 OU/PA/作用域决定（证书优先）。账号类凭据**不可达** superadmin。
2. TLS 强制 `RequireAndVerifyClientCert`（配置 CA 信任池时）：无证书即无法建立 TLS 会话。
3. 服务器与受信 CA 池由部署者控制；根私钥离线保管是最高前提。
4. 策略文件（routes/authz）以 PKCS#7 签名锁定（`policy_signing.require=true`），默认严格表。
5. **配置正确性属于部署责任**：`init-config` 示例仅为占位（其默认 `auth_password` 为
   `changeme`，上线前必须覆盖）——所有部署控制见 `deployment-hardening.md`。

## 3. 攻击面

| 面 | 暴露 | 防护 |
|----|------|------|
| TLS API（mTLS） | 证书优先授权 | 证书链校验、PA 权限、作用域解析 |
| HTTP API（admin） | Basic / token（恒 operator） | 仅内网，部署清单 B |
| ACME / OCSP / TSA 协议端点 | 公共路径 | 认证明文 + 部署白名单 |
| CLI 与配置/策略文件 | 本地|动作者 | `policy_signing`、fail-closed 加载 |
| 部署脚本链条 | 密钥/证书落盘 | 0600 校验、`helpers.py` cert↔key 配对 |
| 备份介质 | 含密钥、审计链 | 加密备份、`cold-backup` |
| 数据库直连 | 记录篡改 | 审计 Merkle 链 + `pki audit verify` |

## 4. 风险登记

| 编号 | 等级 | 风险 | 缓解 | 状态 |
|------|------|------|------|------|
| R-001 | P0 | operator 证书可签发 `m-superadmin`（OU=SuperAdmin 提权），越权管理子 CA | 管理子 CA 硬排除：`m-*` 仅 superadmin 角色 + mTLS 在场（`401/403` 门禁） | ✅ 已修复 `117e35b` |
| R-002 | P0 | `resolveBasicAuth`/`resolveAPIToken` 返回 DB 真实角色 —— superadmin 用户名+密码无证书即提权 | 非证书认证恒 `operator`，scope 不注入；mTLS 在场硬校验 | ✅ 已修复 `cc46b20` |
| R-003 | P1 | `routes_file` 加载失败回退宽松内嵌表 | fail-closed：启动 panic / reload 保留旧表 | ✅ 已修复 `117e35b` |
| R-004 | P1 | 默认内嵌路由表过宽（basic 即 operator 全岗） | 严格最小权限默认表 + 部署漂移断言 | ✅ 已修复 `117e35b` |
| R-005 | P2 | `m-revoker` 默认 profile 权限过大；certs/ 与 private/ 路径混淆令公开证书可被当私钥 | `ProfileMRevoker` 收敛、文档与脚本 0600 强制、cert↔key 配对 | ✅ 已修复 `f7355b2` / `d81c053` |
| R-006 | 接受 | 账号密码委托仅具备 operator 能力（不可达 superadmin） | 设计使然；审计以代登录行仅职责归属 | 已接受（安全边界） |
| R-007 | 接受 | 公共协议端点（ACME/OCSP/TSA）暴露面 | 由部署白名单控制（清单 B）；协议内 min 化信息 | 已接受（部署责任） |
| R-008 | 接受 | HTTP admin 监听若暴露网络 | 部署清单 B 强制内网/不暴露 | 已接受（部署责任） |
| R-009 | 开放 | 示例配置默认弱口令（`auth_password: "changeme"`） | 部署清单 A/F 要求启动前覆盖；文档醒目标注 | 部署责任 |

## 5. 威胁 → 控制映射（STRIDE）

| 威胁 | 对应控制 |
|------|----------|
| S 欺骗（伪造主体） | mTLS 强校验 + CA 链；账号恒 operator；策略文件签名 |
| T 篡改（记录/表） | 审计 Merkle 链 + 周期校验 `AuditVerify`/`pki audit verify`；`policy_signing` |
| R 抵赖 | 审计日志（含用户名/IP/路径）+ 链完整性 + `pki report` 证据 |
| I 信息泄露 | 私钥 0600；审计 PII 每日 salt 掩码；证书≠密钥 |
| D 拒绝服务 | 限流、体积上限、`engine` 背压（503）、`readyz` |
| E 特权提升 | 证书优先授权、管理子 CA 门禁、fail-closed 路由 |

## 6. 验证闭环

- 自动化：`scripts/verify-rbac-api.sh`（378×2 矩阵 + P0 探针），结果归档
  `rbac-verification-2026-08-28.md`。
- 每次改动权限表/认证链后：重跑验证 → 更新验证报告 → 更新本节 R-编号状态。

## 7. 变更纪律

- 新增风险：追加 `R-010…`，注明等级、缓解、验证方式。
- 风险升级/降级：更新本表并同步 `deployment-hardening.md` 对应清单项。
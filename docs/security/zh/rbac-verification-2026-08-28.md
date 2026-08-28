# RBAC 授权验证报告

> 日期：2026-08-28
> 覆盖 commit：`cc46b20`（superadmin 仅证书）/ `117e35b`（管理子 CA 硬排除、路由 fail-closed、严格默认表）/ `f7355b2`（证书作用域贯通）
> 验证环境：本机 `--deploy` 部署于 `https://127.0.0.1:18443`（HTTP API `http://127.0.0.1:18080`），二进制为本地构建 `cmd/pki`
> 一键复现：`scripts/verify-rbac-api.sh --deploy`（首次）→ `scripts/verify-rbac-api.sh`

## 1. 结论

| 运行模式 | 断言数 | 通过 | 失败 | 结果 |
|----------|--------|------|------|------|
| simple（简单模式） | 378 | 378 | 0 | ✅ 全绿 |
| enterprise（企业模式，强制 CA 作用域） | 378 | 378 | 0 | ✅ 全绿 |

**378 = 9 个角色 × 42 个受保护端点**（由路由表计划生成）。
企业模式下 217 项断言为"拒绝"（含无作用域必须 fail-closed），161 项为"允许"。

## 2. 矩阵数据（enterprise 模式，`/tmp/pki-rbac/matrix.tsv`）

| 角色 | 断言 | 允许 | 拒绝 | 备注 |
|------|------|------|------|------|
| superadmin | 42 | — | — | 全量读写 |
| admin | 42 | — | — | 无 ca:create/delete、user 管理、config:write |
| operator | 42 | — | — | 证书/CRL/日志 |
| revoker | 42 | — | — | 仅吊销 |
| auditor | 42 | — | — | 只读日志/报告 |
| readonly | 42 | — | — | 最小只读 |
| auto-renew | 42 | — | — | 仅续期 |
| reporter | 42 | — | — | 报告 |
| console | 42 | — | — | 控制台 |

（各角色细分 allow/deny 分布以每次运行生成的 `matrix.tsv` 为准；上表标注"该角色核心能力"。）

## 3. 关键安全断言（P0 探针 + 行为 sanity）

| 探针 | 期望 | 实测 | 结论 |
|------|------|------|------|
| operator 证书 签发 `m-superadmin` 管理证书 | 403 | 403 | ✅ 管理子 CA 硬排除 |
| superadmin 证书（无账号）签发 `m-revoker` | 200 | 200 | ✅ 证书即权威，无需账号 |
| operator 证书 + **superadmin 账户密码** 签发管理证书 | 403 | 403 | ✅ 密码无法提升权限 |
| operator 证书 + **superadmin 账户密码** `PUT /api/v1/admin/config` | 403 | 403 | ✅ 密码无法触达 superadmin 端点 |
| superadmin `POST /api/v1/certs`（普通签发） | 2xx | 200 | ✅ |
| operator `POST /api/v1/certs`（普通签发） | 2xx | 200 | ✅ |
| auditor `POST /api/v1/certs` | 403 | 403 | ✅ |
| admin `PUT /api/v1/admin/config` | 403 | 403 | ✅ 仅 superadmin |
| 无证书 Basic 认证请求 | 拒 | TLS 层拒 | ✅ mTLS 强制（RequireAndVerifyClientCert） |
| 路由表漂移（routes.json vs 活动表） | 无 | 无 | ✅ 每轮部署断言 |

## 4. 本报告对应的已修复问题

| 等级 | 问题 | 状态 | 修复 |
|------|------|------|------|
| P0 | operator 证书可签发 `m-superadmin`（OU=SuperAdmin 提权） | 已修复 | `117e35b`：按角色硬排除管理子 CA |
| P0 | `resolveBasicAuth`/`resolveAPIToken` 返回 DB 真实角色——**superadmin 用户名+密码无证书即可提权** | 已修复 | `cc46b20`：非证书认证恒 `operator`，scope 不注入 |
| P1 | routes_file 加载失败回退宽松内嵌表 | 已修复 | `117e35b`：fail-closed（panic/保留旧表） |
| P1 | 默认内嵌表过宽 | 已修复 | `117e35b`：同步严格默认表 |
| P2 | `m-revoker` 默认 profile 权限过大 / 私钥与证书路径混淆 | 已修复 | `f7355b2`：`ProfileMRevoker`、部署脚本 `0600` 保护私钥 |

## 5. 复现方法

```bash
cd core
go build -o /tmp/varwof ./cmd/pki
bash scripts/verify-rbac-api.sh --deploy   # 一键部署：初始化 CA、建 9 角色证书、建 superadmin 账号 alice、锁私钥 0600、启动 serve
bash scripts/verify-rbac-api.sh            # 默认 simple 模式矩阵 + P0 + 漂移断言
bash scripts/verify-rbac-api.sh --set-mode enterprise   # 切企业模式
bash scripts/verify-rbac-api.sh --restart  # 重载配置
bash scripts/verify-rbac-api.sh            # 企业模式矩阵 + P0 + 漂移断言
```

产物：
- `/tmp/pki-rbac/matrix.tsv`：378 项（role,method,path,permission,want）
- `/tmp/pki-rbac/verify.log`：完整运行日志
- 报告为**快照**：日后改动权限表/修复后请重新生成并更新本节数据。

## 6. 范围界定

- 覆盖：HTTP API 端点授权、管理子 CA 签发门禁、证书作用域解析、路由表漂移、公共路径最小集。
- 未覆盖（需另行审计）：ACME/SCEP/OCSP/TSA 协议内部授权、多租户命名空间、Web UI 会话。
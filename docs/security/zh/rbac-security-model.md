# RBAC 安全模型（证书优先，Cert-First）

> 版本：2026-08-28（对齐 commit `cc46b20` / `117e35b` / `f7355b2`）
> 适用范围：所有采用 `rbac.enabled=true` 的部署

本文档是 varwof-core 权限系统的**权威安全模型**，回答三个审计核心问题：
**谁的授权可信、什么凭据能达到什么角色、边界在哪。**

## 1. 权威来源：只有证书发卡，账号永不发卡

授权（角色 + 权限向量）**只**来自 mTLS 管理证书内嵌的声明：

- 角色 ← 证书 OrganizationalUnit（OU）→ 映射到 `superadmin / admin / operator / auditor / readonly / revoker / auto-renew / reporter` 等。
- 权限向量 ← 证书 PrincipalAuthorization（PA）扩展（原则上仅证书，`user.HasPerm` 基于 PA 判定）。
- CA 作用域 ← 证书 SAN URI `urn:pki:ca:<scope>` 或 OID `1.3.6.1.4.1.66257.1.5.1`。

所有的"人"凭据（用户名/密码、API Token、Cookie）都**不参与**角色与权限的权威计算。

## 2. 认证输入 → 实际角色映射

| 认证输入 | 最终角色 | 权限/作用域来源 |
|----------|----------|------------------|
| mTLS 管理证书 | OU → 角色（最高可达 superadmin） | 证书 PA、证书 SAN/OID |
| `Authorization: Basic`（用户名+密码） | **恒 `operator`** | operator 默认权限；作用域仅从绑定操作员证书派生 |
| `X-Auth-Token` / `Bearer` / Cookie | **恒 `operator`** | 同上 |
| AIC 证书（委托代理） | `权限 = PA ∩ AIC 能力` | 受限交集 |
| 可信网关委托头（B1/B2） | 经 `trusted_gateway_ous` 校验后按证书 | 证书声明 |

关键实现点（实现于 `cmd/pki/serve.go`）：

```
resolveAPIToken / resolveBasicAuth:
    Role        → 固定 "operator"
    Permissions → getRolePerms("operator")
    CAScopes    → nil（不注入；作用域在认证时由绑定操作员证书推导）
```

## 3. superadmin 仅证书（最高权威的门禁）

管理（`m-*`）证书只能由 **superadmin 角色 + mTLS 客户端证书在场** 签发：

```
POST /api/v1/certs  { profile: "m-*" }
  ├─ 请求无 mTLS 客户端证书（TLS.PeerCertificates 为空）
  │     → 401 api.auth_required   （没有证书，连问都不问）
  ├─ 证书角色 != superadmin
  │     → 403 api.management_mint_denied （operator 等对管理子 CA 硬排除）
  └─ 角色 = superadmin → 放行（签发 m-*，可配 ca_scope）
```

- **operator 及其他角色对管理子 CA 硬排除**：即使持 operator 证书也无法签发 `m-*`。
- **operator 的管理签发能力已标记废弃（planned removal）**，此门禁作第一道 fail-closed 防线。
- 证书是签发方（CA 侧 `scope` 写入）而非请求方自报。

## 4. 用户名 / 密码的局限性（审计必读）

这是设计使然的**安全边界**，也是所有账号类凭据的硬限制：

1. **DB 里的角色字段不再授权**。即使账户在 `rbac_users.role` 中被配置为 `superadmin`，
   通过 Basic / Token 认证得到的实际角色仍是 `operator`。
2. **账户密码无法提升任何权限**。实测：operator 证书 + superadmin 账户密码
   （`alice:VarwofAdmin#2026!`）请求管理签发 → `403`；请求 superadmin 专属端点
   （`PUT /api/v1/admin/config`）→ `403`。
3. **作用域不随账号注入**。账号声明的 CA 作用域不会作为授权依据进入；只有绑定操作员证书派生。
4. 密码的合法用途仅限：**身份归属、审计线索、操作员证书绑定匹配**。

后果与运维建议：

- 想给某个人 operator 以上的权限，**必须签发对应管理证书**，密码做不到。
- 审计时发现账号表出现"超级管理员"角色名，**不代表**该账号拥有 superadmin 能力。
- 证书私钥（`management/users/private/`）才是真正的敏感物，部署脚本已 `chmod 600`。
  `management/users/certs/*.pem` 是公开证书，**绝不能当作私钥使用**。

## 5. CA 作用域

- 作用域仅信任证书来源（SAN URI / OID 1.3.6.1.4.1.66257.1.5.1），由 CA 侧 `scope` 参数写入证书。
- 企业模式无作用域 → 拒绝（fail-closed）；简单模式无作用域 → 允许。
- 非证书认证解析器不注入 `cas:scope:*` 权限（`resolveAPIToken` 已移除该注入）。

## 6. 路由级授权 fail-closed

- `routes.json` 配置了但加载失败：**启动 panic**（无旧规则时）或**保留上一张表**（reload 时），
  绝不回退到宽松内嵌表。
- 默认内嵌表（`internal/serve/routes_default.json`）为严格最小权限表，与仓库 `routes.json` 保持同步；
  启动剧本会断言"无漂移"。
- 公共路径（免认证）最小集：`/healthz /readyz /metrics /tsa /ocsp /acme/ /api/v1/users/login|info|logout /api/v1/session /api/v1/version`。

## 7. 角色与权限矩阵（核心）

| 角色 | ca:create/delete | cert:issue/revoke/renew | user:manage | config:write | webhook:manage | log:read/report |
|------|------------------|-------------------------|-------------|--------------|----------------|-----------------|
| superadmin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| admin | — | issue/revoke/renew | — | — | ✓ | ✓ |
| operator | — | issue/revoke/renew | — | — | — | ✓ |
| revoker | — | revoke | — | — | — | ✓ |
| auditor | — | — | — | — | — | read |
| readonly | — | — | — | — | — | — |
| auto-renew | — | renew | — | — | — | ✓ |
| reporter | — | — | — | — | — | view |

完整端点级矩阵见 `routes.json`（每轮部署会与内嵌默认表做漂移校验）。

## 8. 审计指引

- 一键重放授权矩阵与 P0 断言：`scripts/verify-rbac-api.sh`（含 `--deploy` 一键部署）。
- 结果归档：`docs/security/zh/rbac-verification-2026-08-28.md`。
- 涉及本次安全边界的提交：`f7355b2`（证书作用域贯通）、`117e35b`（管理子 CA 硬排除 + 路由 fail-closed + 严格默认表）、`cc46b20`（superadmin 仅证书，账号恒 operator）。

## 9. 信任边界

- TLS 层强制 `RequireAndVerifyClientCert` + 配置 CA 信任池（无证书即无法建立请求）。
- 管理证书由本 PKI 签发、启停状态可查（数据库记录 + CRL），`ExtractAdminScope` 全链路生效。
- 信任假设：CA 根私钥安全保管；`management/users/private/` 0600；策略表（routes/authz）由 `policy_signing` 签名保护（启用时缺失签名拒绝加载）。
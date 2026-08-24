# pki-core 架构审查报告

日期：2026-07-31
范围：全模块代码审查（架构 + 逻辑 Bug + 配置 + 路由 + 测试质量）
审查者：自动化静态分析

---

## 摘要

pki-core 是一个功能完善的 PKI 系统（~26,650 行非测试源码，~36,400 行测试代码，go vet 零问题）。核心设计决策（auth/ 单一事实来源、atomic.Pointer 热重载、provisioner.Provisioner 接口）可靠。

本次审查发现 **8 个关键 Bug**（其中 4 个涉及安全/权限），以及 **5 个架构债务**。

---

## 🔴 关键 Bug

### B01：硬编码路由回退权限不匹配 ✅ 已修复

| 路由 | routes.json 期望 | 硬编码回退实际 | 严重性 |
|------|-----------------|---------------|--------|
| `POST /api/v1/certs/upload` | `cert:issue` | `cert:list`（落入 `/api/certs` catch-all） | 🔴 **安全**：有 cert:list 的用户可签发证书 |
| `GET /api/v1/reports/compliance` | `report:view` | `PermReportGenerate` | 🟡 可用性：读报告需要签发权限 |
| `GET /api/v1/admin/config` | `config:read` | `PermConfigWrite` | 🟡 可用性：读配置需要写权限 |
| `POST /api/v1/trust` | `trust:import` | `PermTrustList` | 🟡 安全：导入信任锚只需列表权限 |

**修复**（2026-07-31）：
- 硬编码回退和 publicOnly 同步修正：4 条路由均按 HTTP method 区分权限
- 新增 `/api/v1/certs/upload` 分支使用 `PermCertIssue`
- 文件：`internal/serve/mux.go`

**根因**：三套路由系统独立维护（routes.json / publicOnly / 硬编码 switch），路由变更时必须三处同步。无编译器保障。

---

### B02：AIC 扩展签发无声失败 ✅ 已修复

`internal/ca/sign.go:608-611` `applyProfile()` 中：

```go
if sc.AIC != nil {
    ext, err := BuildAIC(*sc.AIC)
    if err == nil {     // ← 错误被静默吞掉，证书继续签发
        tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
    }
}
```

**后果**：证书签发成功但不含 AIC 扩展 → pki-core 认为正常到期，网关侧 `CheckAdmission()` 因缺少 AIC 扩展拒绝。用户无任何报错。

**同类问题共 3 处**：

| 位置 | 问题 | 后果 |
|------|------|------|
| `sign.go:608` | `BuildAIC` 错误静默 | 证书缺 AIC 扩展 |
| `sign.go:639` | `BuildPrincipalAuthorizationExtension` 错误静默 | 证书缺 PA 扩展 |
| `sign.go:283,289` | SKI/AKI 计算 `x509.MarshalPKIXPublicKey` 失败静默 | SubjectKeyId / AuthorityKeyId 为空 |

**修复**（2026-07-31）：全部 3 处改为 `if err != nil { return fmt.Errorf(...) }`，错误传播到 `Sign()` 调用者。文件：`internal/ca/sign.go:604-606, 635-637, 280-288`

---

### B03：CertRecord 不填充 agent_id / principal_uid ✅ 已修复（审查前已修复）

DB v22 迁移添加了 `certificates` 表的 `principal_uid` 和 `agent_id` 列（并通过回填填充存量），但 `Sign()` 构建 `db.CertRecord` 时**从未从 `sc.AIC` 读取**：

```go
record := &db.CertRecord{
    SerialNumber: serialHex,
    ...
    PrincipalUid: principalUid,  // ← 代码库中已存在
    AgentId:      agentId,       // ← 代码库中已存在
}
```

**修复**：审查报告生成时代码库已包含 `principalUid` / `agentId` 提取与填充逻辑（`sign.go:329-336, 358-359`），审查时未注意到。

---

### B04：AIC 扩展写库失败不阻止签发 ✅ 不适用

审查报告中引用的 `insertAICExtension` 函数在当前代码库中不存在。相关逻辑已被 refactor 淘汰。`aic_extensions` 表通过 `AICExtension` 结构体在 `db/aic.go` 管理，但签发流程不显式调用插入。

---

### B05：PA 自动派生多 OU 短路 ✅ 已修复

```go
for _, ou := range sc.Subject.OrganizationalUnit {
    role := p.RoleByOU(ou)
    if role == "" {
        continue
    }
    grants := p.RoleGrants(role)
    if len(grants) > 0 {
        // ... 设置 PA
    }
    break  // ← 有 grants 或无 grants 都 break
}
```

**后果**：第一个 OU 匹配到角色但 grants 为空时，PA 不设置且不继续检查第二 OU。多 OU 证书可能静默缺失授权。

**修复**（2026-07-31）：`break` 移至 `if len(grants) > 0 { ... }` 块内，仅在有权限时停止循环。文件：`internal/ca/sign.go:628`

---

### B06：/pki/* 公共路径通配符在 routes.json 下失效 ✅ 已修复

`routing/rules.go` `IsPublic()` 使用精确字符串匹配：

```go
rr.public = make(map[string]bool, len(rr.PublicPaths))
for _, p := range rr.PublicPaths {
    rr.public[p] = true
}
```

**修复**（2026-07-31）：`IsPublic` 新增 glob 前缀匹配，`/*` 后缀模式正确匹配子路径。文件：`internal/routing/rules.go:108-120`

---

### B07：TSA 管理端点在 routes.json 中缺失 ✅ 已修复

5 条路由在硬编码回退中有定义（受 `PermConfigWrite` 保护），但**不在 routes.json 中**：

- `GET /api/tsa/cert`
- `POST /api/tsa/cert/renew`
- `POST /api/tsa/cert/rotate`
- `GET /api/tsa/ca`
- `POST /api/tsa/ca/renew`

**修复**（2026-07-31）：5 条 TSA 管理路由添加至 `routes.json`，受 `config:write` 权限 + `superadmin`/`admin` 角色保护。

---

### B08：publicOnly 块 3 处重复死代码 ✅ 已修复

`internal/serve/mux.go` publicOnly 区块中，3 组 case 分支被定义了两次：

| 行号 | 重复内容 |
|------|---------|
| 160-161 = 162-163 | `/api/v1/users/login/info/logout/version/dns-query` |
| 202-203 = 206-207 | `/api/certs/revoke-by-principal` |
| 204-205 = 208-209 | `sub-ca/*/revoke-all` |

**修复**（2026-07-31）：移除重复 case 分支，保留各一组。文件：`internal/serve/mux.go`

---

## 🟡 架构债务

### A01：三套独立路由系统（重复维护）

三个代码路径维护同一组路由定义：

| 系统 | 位置 | 行数 | 特性 |
|------|------|------|------|
| routes.json | `routes.json` | 43+ 条规则 | 声明式，通配符路径匹配，支持角色/权限/CA scope/AIC 校验 |
| publicOnly | `mux.go:156-237` | ~80 行 | 公共路径的硬编码 switch |
| 硬编码回退 | `mux.go:265-354` | ~90 行 | 保护路径的硬编码 switch，routes.json 未加载时触底 |

**问题**：
- routes.json 一旦加载，未列出的路径返回 404（故障关闭），无增量迁移路径
- 路由变更需要在 3 处同步修改（B01/B07/B08 都源于此）
- hardcoded fallback 缺少 6 条 routes.json 中定义的路由

**现状**：B01/B07/B08 已修复使三系统权限对齐。routes.json 作为主控，hardcoded 和 publicOnly 为 fallback 安全网。完整归并参见远期建议 #9。

---

### A02：MergeConfig 遗漏 12 字段 ✅ 已修复

`MergeConfig()` 补充 12 个遗漏字段（2026-07-31）：

**5 个完整顶层字段**：

| 字段 | 子字段数 | 状态 |
|------|---------|------|
| `PG` | 7 (Host/Port/User/Password/DBName/SSLMode/DSN) | ✅ 已补充 |
| `RBAC` | 3 (Enabled/PermissionMode/CAScopes) | ✅ 已补充 |
| `Hierarchy` | 1 (string) | ✅ 已补充 |
| `Persist` | 5 (Mode/BatchSize/BatchInterval/QueueSize/BufferDB) | ✅ 已补充 |
| `Aggregator` | 4 (WindowMs/BatchMax/Threshold/BufferSize) | ✅ 已补充 |

**7 个嵌套子字段**：

| 结构体 | 缺失字段 | 状态 |
|--------|---------|------|
| `DefaultsConfig` | `IssuerAltNames`、`SubjectInfoAccess`、`PolicyOIDs`、`ReportMaxRows` | ✅ 已补充 |
| `CRLConfig` | `Addr`、`RenewInterval` | ✅ 已补充 |
| `CTLogConfig` | `Logs` | ✅ 已补充 |

**遗留问题已修复**：布尔值/零值不可覆盖 → 11 个 MergeConfig 布尔字段改为 `*bool` 指针（见下）。

### A02b：MergeConfig 布尔值不可覆盖 ✅ 已修复

11 个 `if override.X {` 模式布尔字段改为 `*bool`，热重载 PUT 可任意开/关：

| 结构体 | 字段 |
|--------|------|
| `TSAConfig` | `Ordering` |
| `ServeConfig` | `MetricsEnabled` |
| `RateLimitConfig` | `Enabled` |
| `AutoRenewConfig` | `Enabled`、`NotifyOnly` |
| `ArchiveConfig` | `Enabled`、`ArchiveExpired`、`ArchiveRevoked` |
| `SMTPConfig` | `TLS`、`InsecureSkipVerify` |
| `RBACConfig` | `Enabled` |

- `MergeConfig` 改为 `override.X != nil` 判断；读取点统一走导出的 `BoolOr(b, def)`（nil → 默认值），`DefaultConfig` 用导出的 `BoolPtr()` 设置显式默认（`ArchiveExpired=true` 保持默认语义）
- JSON 兼容：`true`/`false`/缺省 均正确映射，`nil` 指针被 `omitempty` 省略，round-trip 后仍可再次覆盖
- 回归测试：`TestMergeConfigBoolOverride`（默认关→开、默认开→关）+ `TestMergeConfigBoolRoundTrip`（PUT round-trip 后再翻转）

---

### A03：Validate() 覆盖严重不足 ✅ 已修复

2026-07-31 已补充（`config.go:285-431`）：

- 密钥类型枚举 ✓ / 哈希算法枚举 ✓ / 时间格式解析（14 字段）✓ / 端口格式（6 字段）✓
- **枚举值** ✓ — Hierarchy / Locale / LogFormat / RBAC.PermissionMode / KeyBackend.Type / Persist.Mode / PG.SSLMode
- **URL 格式** ✓ — CTLog.URL / Webhook.URL / TSA.CoreURL / KeyBackend.URL / OCSPURL / IssuerURL / CRLBaseURL / CTLog.Logs[i] / LDAP.URL（ldap/ldaps scheme）
- **数值范围** ✓ — SMTP.Port / RateLimit.Rate/Burst / RA.RequiredApprovals / CRL.ValidityDays / ReportMaxRows / AutoRenew.WindowDays/DefaultValidity / Archive.RetentionDays / PG.Port / Persist.BatchSize/QueueSize / Aggregator.*
- **嵌套结构体** ✓ — PG / LDAP / Persist / Aggregator 全部纳入检查（0 → 4 结构体）
- **监听器冲突** ✓ — 同进程监听器 `serve.addr` vs `serve.tls_addr` 必须互斥；模块化独立监听器（tsa/ocsp/crl/api）仅对用户显式（非默认）地址检测碰撞（默认配置故意共享 :8443，不误报）
- **文件路径存在性** ✓ — 19 个路径字段 + 每个 CA 的 cert/key/chain 均校验；仅校验用户显式配置（非空且 ≠ 编译期默认值），未部署的默认布局不误报；`remote_hsm` 模式下跳过 CA 私钥校验（密钥存于远程签名器）

覆盖率从 ~1% 提升至约 **90% 配置面**。

**遗留说明**：配置校验依赖 `DefaultConfig()` 与用户显式值的对比来区分"默认路径"与"用户路径"，属启发式——用户若显式写出与默认相同的路径将跳过校验（可接受）。

---

### A04：sign.go 上帝函数 ✅ 已修复

`internal/ca/sign.go` — 1,331 行，19 路 profile 分支。

**具体问题**：

1. **`m-*` 8 个 profile 结构完全重复**（`m-superadmin` / `m-admin` / `m-operator` / `m-auditor` / `m-readonly` / `m-console` / `m-auto-renew` / `m-reporter`）— 仅 OU 不同，KU/EKU 完全一致，12 行/个 × 8 = 96 行可合并为 1 个通用分支

2. **10 次重试循环浪费**：`randomSerial` → `buildCertTemplate` → x509.CreateCertificate → DB INSERT → `DuplicateSerial` → 全部重来。签名（~217μs）比 DB insert 轻得多，但重试时仍需重签。可在循环外构建模板，循环内只重试 `randomSerial` + DB 操作

**修复（2026-07-31）**：

1. 新增 `managementProfileOU map[Profile]string` + `applyManagementProfile(tmpl, sc)` 辅助函数 — 8 个 m-* profile 统一注入 OU + `BasicConstraintsValid` + `KeyUsage=DigitalSignature` + `ExtKeyUsage=[ClientAuth]` + `addCRLDP` + `addAIA`，删除 96 行重复
2. 重试循环重构：serial 无关操作（policy 加载 / `CheckPolicy` / AIC PrincipalAuthorization 校验）提升到循环外；循环内仅 `randomSerial` → `buildCertTemplate` → sign → INSERT（`addCRLDP` partition 依赖 serial，模板需逐次重建）

---

### A05：覆盖测试填充

`internal/serve/` 中存在 ~70 个测试函数 / ~2,000 行弱断言测试：

| 模式 | 测试函数数 | 代表文件 |
|------|-----------|---------|
| `_ = resp.StatusCode`（丢弃结果） | ~50 | `coverage_boost5_test.go`、`api_coverage_boost4_test.go` |
| `"expected 200 or 500"`（通吃） | ~13 | `coverage_boost6_test.go`、`coverage_boost7_test.go` |
| `"Should not panic"` / `_ = err` | ~6 | `coverage_boost4_test.go`、`coverage_boost9_test.go` |
| 死代码变量声明 | 11 行 | `api_coverage_boost4_test.go:859-868` |

**影响**：声称的 82.1% 覆盖率被抬高 ~2-3 个百分点。更严重的是 "200 or 500" 模式 — 回归不会被测试捕获。

**修复（2026-07-31）**：

1. **17 处 `"expected 200 or 500"` + 3 处 `"Should not panic"` 全部改为精确断言**（`api_coverage_boost_test.go` / `api_coverage_test.go` / `coverage_boost3/6/8/9_test.go`），并逐一定性根因：幂等删除→200、吊销不存在证书→500、RA 审批不存在请求→500、`ra_requests.csr_der` NOT NULL→500
2. **49 处丢弃的 `resp.StatusCode` 改为确定性断言**（`api_coverage_boost4_test.go` / `coverage_boost5_test.go`），经两轮全量采集确认非 flaky 后逐一固化
3. **测试重写**（原本方法用错导致 405/404 被弱断言掩盖）：`TestAPIWebhooks_MethodNotAllowed`（POST→PUT）、`TestAPIDNSACME_Set/BadJSON`（POST→PUT）、`TestAPIExportCert_NotFoundV2`（GET→POST）
4. **`coverage_boost3_test.go`** metrics 断言改用 `prometheus/testutil.ToFloat64` 真实值校验
5. **附带修复真实产品 bug**：`web.go` `statusRecorder` 未实现 `http.Flusher`，SSE（`/dashboard/events`、`/stats/events`）经 access-log 中间件后返回 500 "streaming not supported"；已补 `Flush()` 方法
6. 残留弱断言模式全仓清零（`rg "_ = resp.StatusCode|GOTCODE|expected 200 or 500|Should not panic"` 无匹配），全量 `go build` / `go vet` / `go test -short ./internal/... ./auth/... ./cmd/...` 17 包全部通过
7. **2026-08-01 正式关闭**：`GOTCODE` 插桩再次确认全仓 0 匹配；弱断言仅剩 4 处注释字样（`cmd/pki/serve_unix_test.go:88`、`notify_test.go:84/119/130`，非断言代码）；`./scripts/cover.sh pki-core` 模块级 62.2% + 包级 `-cover` 17 包全通过，算术均值 74.6%，已刷新 `dev-docs/pki-core/reports/coverage-report.md`

---

## 修复状态总览（2026-07-31）

| 编号 | 问题 | 风险 | 状态 | 文件变更 |
|------|------|------|------|---------|
| B01 | 硬编码路由权限不匹配 | 🔴 安全 | ✅ 已修复 | `mux.go` |
| B02 | AIC/PA/SKI 无声吞错 | 🔴 数据不一致 | ✅ 已修复 | `sign.go` |
| B03 | CertRecord 缺 AIC 字段 | 🔴 功能缺陷 | ✅ 审查前已修复 | — |
| B04 | AIC 扩展写库失败 | 🔴 数据不一致 | ✅ 不适用（代码已重构） | — |
| B05 | PA 多 OU 短路 | 🟡 功能缺陷 | ✅ 已修复 | `sign.go` |
| B06 | /pki/* 通配符失效 | 🟡 可用性 | ✅ 已修复 | `rules.go` |
| B07 | TSA 路由遗漏 | 🟡 可用性 | ✅ 已修复 | `routes.json` |
| B08 | publicOnly 死代码 | 🟢 整洁 | ✅ 已修复 | `mux.go` |
| A01 | 三套路由系统重复维护 | 🟢 维护成本 | 🟡 部分（B01/B07/B08 已修，完整归并见远期 #9） | `mux.go` / `routes.json` |
| A02 | MergeConfig 缺字段 | 🟡 热重载 | ✅ 已修复 | `config.go` |
| A02b | MergeConfig 布尔值不可覆盖 | 🟢 热重载 | ✅ 已修复 | `config.go` |
| A03 | Validate() 覆盖不足 | 🟡 配置安全 | ✅ 已修复（嵌套结构/监听器冲突/文件路径全部补齐） | `config.go` |
| A04 | sign.go 上帝函数 | 🟢 可维护性 | ✅ 已修复 | `sign.go` |
| A05 | 覆盖测试填充 | 🟢 测试质量 | ✅ 已修复 | 见上文 |

## 剩余工作

| # | 项目 | 风险等级 | 预估工作量 |
|---|------|---------|-----------|
| 1 | 三套路由归并为 routes.json 唯一来源 | 🟢 维护成本 | 3d |

## 相关文件索引

| 文件 | 行数 | 关联问题 |
|------|------|---------|
| `internal/serve/mux.go` | 421 | B01, B08, A01 |
| `internal/ca/sign.go` | 1,331 | B02, B03, B04, B05, A04 |
| `internal/config.go` | 889 | A02, A03 |
| `internal/routing/rules.go` | 297 | B06 |
| `routes.json` | 76 | B07, A01 |
| `internal/serve/aic_api.go` | 172 | B04 |
| `internal/serve/coverage_boost*.go` | ~5,500 | A05 |
| `internal/serve/api_coverage_boost*.go` | ~2,100 | A05 |

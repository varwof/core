# RFC 已知偏差清单

与相关 RFC 标准已知不一致（含主动设计决策和待修复 bug），供集成方评估兼容性。

---

## 一、RFC 5280 — 证书与 CRL

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | serialNumber 可能为负（首位 bit 未清 0） | **bug** | `crypto/rand` 20 字节全随机，缺少 `buf[0] & 0x7f`，违反 §4.1.2.2 "正整数" |
| 2 | CRL thisUpdate 未做单调性保证 | **bug** | 未 `Round(time.Second)` + `max(lastThisUpdate, now)`，时钟回拨可导致 thisUpdate 倒退 |
| 3 | CRL nextUpdate 只用 thisUpdate + validityDays | **低** | 未考虑签发延迟 |
| 4 | Critical 标记依赖 profile 模板 | **可用性** | `keyUsage`/`basicConstraints`/`eku` 等扩展的 critical 标记在各 profile 中手工定义，未统一校验 RFC 5280 要求（§4.2.1.3-9 要求部分扩展必须 critical） |
| 5 | Policy Mappings 未实现 | **主动放弃** | 仅 CA 间使用，无业务场景 |
| 6 | Name Constraints 已实现但路径验证未集成 | **阶段** | 扩展已嵌入子 CA 证书，但 Go `x509.Verify` 不自动校验（需自定义验证器） |
| 7 | Subject Directory Attributes 未实现 | **主动放弃** | 极少使用 |
| 8 | CRL Issuer Alternative Name 未实现 | **主动放弃** | CRL 中不常用 |
| 9 | Delta CRL / Freshest CRL 未实现 | **主动放弃** | 部署复杂，小规模场景无必要 |
| 10 | Issuing Distribution Point 未实现 | **主动放弃** | 仅分区 CRL 需要 |
| 11 | CRL 间接 CRL Certificate Issuer 未实现 | **主动放弃** | 仅间接 CRL 需要 |

## 二、RFC 3161 — TSA 时间戳协议

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | 响应包含完整 CA 链而非仅 TSA 签名证书 | **bug** | 违反 §2.4.2 响应最小化原则，过大的响应可能被网关拒绝 |
| 2 | Email/File/Socket 传输未实现 | **主动放弃** | 仅实现 HTTP（§3.4），其他传输无实际需求 |
| 3 | systemFailure 错误返回 HTTP 500 而非 PKIFailureInfo | **低** | RFC 优于 HTTP 错误码，但实践兼容 |
| 4 | badDataFormat / timeNotAvailable / addInfoNotAvailable 失败码未实现 | **主动放弃** | 场景未触发 |

## 三、RFC 6960 — OCSP

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | Nonce 未按请求长度等长回显（可能填充/截断） | **bug** | 违反 §4.4.1 "回显请求中相同的值" — 应逐字节复制 |
| 2 | responseExtensions 未填充 | **阻塞** | Go `x/crypto/ocsp` 未导出 `ResponseExtensions` 字段，需 fork |
| 3 | singleExtensions 仅 Nonce，无其他扩展 | **低** | 仅 Nonce 有实际需求 |
| 4 | Archive Cutoff 未实现 | **主动放弃** | 可选扩展 |
| 5 | CRL 引用未实现 | **主动放弃** | 响应本身即为实时状态 |
| 6 | 签名请求验证未实现 | **主动放弃** | 部署中未强制 |
| 7 | OCSP responseStatus 仅 successful 被使用 | **低** | `malformedRequest`/`internalError`/`tryLater`/`sigRequired`/`unauthorized` 常量已定义但当前代码逻辑未触发 |

## 四、RFC 8555 — ACME

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | HTTPS 未强制（依赖反向代理） | **主动放弃** | 应用层不做 HTTPS 强制，部署文档说明需反向代理 TLS 终结 |
| 2 | Content-Type 未检查 | **低** | 接收端宽容策略 |
| 3 | Subproblems 数组未实现 | **主动放弃** | RFC 8555 §6.7.1 可选，无实际需求 |
| 4 | initialIp / createdAt 未记录 | **主动放弃** | 审计日志已有请求来源 IP |
| 5 | 公钥查找账户 URL 未实现 | **主动放弃** | RFC 8555 §7.3.1 推荐，非强制 |
| 6 | 预授权未实现 | **主动放弃** | 可通过 newOrder 替代 |
| 7 | 服务条款变更通知未实现 | **主动放弃** | 通知机制超出 ACL 范围 |
| 8 | tls-alpn-01 / device-attest-01 未实现 | **主动放弃** | 无实际需求 |

## 五、RFC 8894 — SCEP

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | GetNextCACert 返回相同 CA（无轮换） | **低** | CA 证书未更换时行为正确；更换后需手动更新 |
| 2 | PENDING 状态不支持，始终同步签发 | **设计决策** | RFC 8894 §4.4 允许同步模式 |
| 3 | GetCertInitial/GetCert/GetCRL 同步返回 | **设计决策** | 同 #2 |
| 4 | SCEP 吊销消息未实现 | **主动放弃** | 可通过 REST API 吊销 |

## 六、RFC 3628 — TSA 策略要求

| # | 偏差 | 类型 | 原因/说明 |
|---|------|------|----------|
| 1 | TSA 实践声明未发布 | **阶段** | v1.1 规划中 |
| 2 | TSA 密钥轮换未实现 | **阶段** | v1.2 规划中 |
| 3 | 无 HSM 支持 | **主动放弃** | 纯软件实现，HSM 可独立部署 |

---

## 严重性定义

| 等级 | 含义 | 处理原则 |
|------|------|----------|
| **bug** | 违反 RFC MUST/SHOULD，可能引起互操作问题 | P0-P1 修复目标 |
| **阻塞** | 已知但需上游修复后方可解决 | 建立 workaround 文档 |
| **低** | 违反 RFC MAY/可选条款，不影响主流互操作 | P2 或更低优先级 |
| **主动放弃** | 设计决策，明确不实现 | 不修复，说明理由 |
| **阶段** | 规划中，后续版本实现 | 标注预期版本 |
| **可用性** | 不违反 RFC 但损害可用性 | 最佳实践改进 |

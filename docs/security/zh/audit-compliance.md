# 审计日志与合规

> 版本：2026-08-28
> 配套：`threat-model.md`（R 编号）、`rbac-verification-2026-08-28.md`（证据）

本文档说明授权/操作审计的记录模型、查询与完整性校验、隐私掩码，以及
面向 SOC 2 / PCI DSS / NIST SP 800-53 / ISO 27001 的证据生成路径。

## 1. 审计模型

敏感与普通 API 操作写入审计链（实现于 `engine/db`）：

```
LogAudit(username, remote_ip, method, path, detail)   // username = 认证主体
```

覆盖示例：登录失败（`login_failed_user_not_found` / `login_failed_bad_password`）、
证书上传/签发、吊销理由、用户/令牌/RBAC 变更、OCSP 查询、恢复操作、审计自身删除等。

## 2. 查询入口

| 方式 | 说明 |
|------|------|
| CLI：`pki audit --limit 50 --offset 0` | 表格输出（ID, 时间, 用户, 方法, 路径, 明细） |
| CLI：`pki audit verify` | 重算并校验 Merkle 链完整性（断链报错并指出条目） |
| REST：`GET /api/v1/audit?limit=&offset=` | JSON 分页查询（superadmin / audit 权限） |

## 3. 完整性（AUTH-016）

- 审计条目以 **Merkle 哈希链**串接，链上任何删除/篡改可被检出。
- `audit_verify.enabled=true`（默认）周期校验，`interval` 默认 24h；发现断链记录
  warning 与首条异常条目 ID。
- 应对外部改库：备份介质中的审计块另行校验；恢复后执行 `pki audit verify`。

## 4. 隐私掩码（数据最小化）

- `audit_salt.enabled=true`（默认）：每个自然日生成随机 salt，对 PII 字段
  （username、远程 IP）做 **HMAC 掩码**后再存储并链入。
- `audit_salt.retention_days`（默认 365）：salt 保留窗口内的 day 可反解；
  过期 salt 被清除后，掩码身份**永久不可逆**，而链仍可校验。
- 关闭掩码（`enabled=false`）仅建议用于隔离/合规取证环境。

## 5. 合规证据

- **报告**：`pki report --template soc2|pci|nist|iso --out <file>` 输出 PDF，
  内嵌控制映射表（如 PCI DSS v4.0 的 2.2 配置基线、3.6 密钥管理、4.1 密钥变更、
  10.2 审计日志、10.6 日志复核；SOC 2 的 CC6 安全边界、CC7 监控；NIST CP/AU 家族；
  ISO 27001 A.8/A.12 控制项）。
- **CP/CPS**：`pki cpcps` 生成 RFC 3647 主张文档（CA 操作规程、证书生命周期、审计声明）。
- **授权矩阵证据**：`scripts/verify-rbac-api.sh` 的运行结果
  （`/tmp/pki-rbac/matrix.tsv` + `verify.log`）存档为
  `rbac-verification-2026-08-28.md`，可对审计出示（简单/企业 × 378、P0 断言）。

## 6. 与框架的对照速查

| 控制组 | 对应机制 |
|--------|----------|
| PCI DSS 10.2/10.6 / SOC2 CC7 | `LogAudit` 全量记录 + `pki audit` 复核流程 |
| PCI DSS 10.5/10.7 / NIST AU-9 | Merkle 链完整性 + `AuditVerify` 周期校验 |
| PCI DSS 3.x / SOC2 CC2.1 | `audit_salt` PII 掩码与保留期策略 |
| PCI DSS 6.4 / ISO A.8.25 | `policy_signing` 策略文件变更签名与复核 |
| NIST AC/IA / ISO A.8.2 | 证书优先 RBAC（`rbac-security-model.md`） |
| NIST CP-9 / ISO A.8.13 | 审计链与 DB 的加密备份与恢复演练 |

## 7. 运营建议

- 审计日志只增不改：对 DB 直连尝试做最小权限/只读账号 + 审计链校验告警。
- `pki audit verify` 纳入备份恢复演练 Step（恢复后必跑）。
- 定期（如每周）人工复核高风险动作：`m-*` 签发、`ca rotate`、用户/令牌变更、
  密钥恢复（`keys/recover`）。
- 保留策略：盐窗口决定 PII 可反解期；审计行按组织法规保留（默认随 DB 全保留）。
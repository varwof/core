# BUGS.md — varwof CLI 功能测试发现的问题清单

> 来源：对 `bin/varwof` 的实机功能测试（全部命令 + 参数成功路径，含 DB 与配置）。
> 环境：`--config /tmp/opencode/corecli/pki.json`，DB `/tmp/opencode/corecli/pki/pki.db`。
> 详细用例见各子任务报告：
> - `/tmp/opencode/corecli/work/subtask-subca/REPORT.md`
> - `/tmp/opencode/corecli/work/subtask-trustbridge/REPORT.md`
> - `/tmp/opencode/corecli/work/subtask-ops/REPORT.md`
> - `/tmp/opencode/corecli/work/subtask-docs/REPORT.md`

按严重程度排序。`[已修复]` 表示已修复并验证。

---

## 高 (HIGH) — 功能缺陷

### H1. `trust-bridge issue` 是静默无操作（no-op），却返回退出码 0 ✅ [已修复]

- **文件**：`cmd/pki/trustbridge.go:50-54`（构造 `TrustBridgePolicy` 时未设置 `Enabled`）
- **现象**：`trust-bridge issue <issuer> <subject> [days]` 打印 `null`，`msg="trust bridge established" count=0`，退出码 0，但实际一条 cross-cert 都没有签发（DB 无变化）。
- **根因**：`ca.TrustBridgePolicy.Enabled` 零值为 `false`，`internal/ca/trustbridge.go:63-65` 中 `if !b.Enabled { continue }` 跳过所有 bridge。CLI 构造 policy 时从不设置 `Enabled`，于是 `issue` 实际上永远不签发。
- **修复**：在 CLI 构造 policy 时设置 `Enabled: true`（`cmd/pki/trustbridge.go`）。已验证：`trust-bridge issue "CliTest TLS CA" "CliTest HR CA"` 现在实际签发 `count=1`，DB 中新增 `Status="V"` 的 cross-cert 记录。

### H2. `archive -ca` 过滤在归档（非 `--list`）模式下被忽略 ✅ [已修复]

- **文件**：`cmd/pki/archive.go`（`caName` 仅在 `--list` 分支使用；参见 :33）
- **现象**：`archive --revoked --retention 0 --ca "CliTest TLS CA"` 会归档整个 DB 所有符合条件的吊销证书，`-ca` 不起作用，与帮助文本"Filter by CA"矛盾。只有 `--list --ca` 会过滤。
- **修复**：给 `ca.ArchivePolicy` 新增 `IncludeCA` 字段，`ca.ArchiveCerts` 及 `archiveExpiredCerts`/`archiveRevokedCerts` 支持按 CA 过滤（`internal/ca/archive.go`），CLI 把 `-ca` 传入 policy（`cmd/pki/archive.go`）。已验证：`archive --revoked --ca "CliTest ACME CA" --retention 0` 只归档 ACME CA 的 1 条吊销证书，TLS CA 的吊销证书仍保留在主表。

---

## 低 (LOW) — 交互/UX 缺陷

### L1. `cross-cert --help` / 未知子命令打印 `%!s(MISSING)` 错误文本 ✅ [已修复]

- **文件**：`cmd/pki/cross-cert.go:32`（`ef("cli.err_unknown_subcmd", args[0])`）
- **现象**：
  - `cross-cert --help` → `unknown --help subcommand: %!s(MISSING)`，退出码 1
  - `cross-cert bogus` → `unknown bogus subcommand: %!s(MISSING)`（漏掉了实际的子命令名）
- **根因**：本地化模板 `cli.err_unknown_subcmd`（`"unknown %s subcommand: %s"`）有两个格式动词，但所有调用点只传一个参数（`args[0]`），第二个 `%s` 无参 → `%!s(MISSING)`。
- **修复**：修正所有 5 处调用点，传入命令名 + 子命令名两个参数（`cmd/pki/cross-cert.go`、`db.go`、`user.go`）。已验证：`cross-cert bogus` → `unknown cross-cert subcommand: bogus`；`user/key/db/token bogus` 均正确输出实际子命令名。

### L2. 顶层 `--help` 缺失，命令间帮助处理不一致 ✅ [已修复]

- **涉及命令**：
  - `cross-cert` 全部子命令 `--help`：要么报缺失参数（`issue`/`revoke`），要么被静默忽略（`list`），都不打印帮助。
  - `notify --help`、`policy --help`：报 `unknown <-cmd> subcommand: --help`（退出码 1）。
  - `trust-bridge --help`：报 `unknown subcommand: --help`（仅裸 `trust-bridge` 显示 usage）。
  - 对比：`sub-ca * --help`、`report --help`、`cpcps --help`、`ct submit --help` 都能正确打印 usage 并退出 0。
- **修复**：统一为 `--help`/`-h` 打印 usage 并退出 0：
  - `cmd/pki/cross-cert.go`：命令组及 `issue`/`list`/`revoke` 子命令新增 `--help` 处理。
  - `cmd/pki/notify.go`、`policy.go`：`--help`/`-h` 现在打印 usage 退出 0。
  - `cmd/pki/trustbridge.go`：`--help`/`-h` 打印 usage 退出 0。

### L3. `auto-renew --help` 无输出且退出 0（无 flag parser） ✅ [已修复]

- **文件**：`cmd/pki/autorenew.go`
- **现象**：`auto-renew --help` 不打印任何 usage，直接运行 once 模式，输出 `null` + `msg="auto-renew complete" checked=0 ...`，退出 0。
- **修复**：`cmdAutoRenew` 增加 `--help`/`-h`/`help` 处理，打印 usage 退出 0。已验证：`auto-renew --help` 打印 usage。

---

## 信息 (INFO) — 观感/提示

### I1. 空结果打印字面量 `null` 而不是 `[]` ✅ [已修复]

- **涉及**：`trust-bridge list`、`archive --list`（空）、`auto-renew`（空）在结果为空时用 Go `MarshalIndent` 把 nil slice 序列化为 `null`。
- **修复**：在 CLI 序列化前把 nil slice 归一化为空 slice（`cmd/pki/trustbridge.go`、`archive.go`、`autorenew.go`）。已验证：空时输出 `[]` 而非 `null`。

### I2. 部分 usage 使用遗留命令前缀 ✅ [已修复]

- `cross-cert` 无子命令时 usage 打印 `goca cross-cert ...`，前缀 `goca` 与实际命令名 `varwof` 不一致（观感问题）。
- **修复**：`cmd/pki/cross-cert.go`、`ra.go`、`renew.go` 的 usage/错误信息前缀 `goca` 改为 `pki`。（注：`cmd/pki/completion.go` 生成的 shell 补全脚本仍硬编码 `goca` 命令名，因与二进制调用方绑定，未在本轮改动。）

### I3. `cpcps` 相关说明（非代码 bug，语义需文档化）✅ [已处理]

- `cpcps -ca` 是按证书 **CN** 匹配，而非 config `cas` map 的 key。`-ca "CliTest Root CA"`（config key）报 "not found"，`-ca "Cli Root CA"`（证书 CN）正常。需在文档说明 `-ca` 使用 CN。
- `cpcps -out` 与 `-out-dir` 同时给出时，`-out` 被静默忽略，仅 `-out-dir` 生效，无警告。
- **处理**：
  - 在 `cmd/pki/cpcps.go` 中，`-out` 与 `-out-dir` 同给时打印 `WARN "cpcps: --out is ignored when --out-dir is set"`。
  - 在 `docs/core/en/commands.md` 与 `docs/core/zh/commands.md` 中补充两处语义说明（`-ca` 按 CN 匹配；`-out` 在 `-out-dir` 模式下被忽略）。

---

## 环境/配置差异（非代码 bug，供参考）

- `sub-ca create` 成功路径在本环境不可达：唯一 pathlen 无限（可签发子 CA）的根 CA，DB 中名称为 `Cli Root CA`，而 config 中名为 `CliTest Root CA`；其余已配置 CA 均为 `pathlen:0`。无一个父 CA 能同时通过 DB 与 config 查找。
- `recover` 完整成功路径未执行：共享 DB 无 escrowed 密钥、config 无 `key_escrow`（属于前置条件，非 bug；所有缺失路径均优雅报错）。
- `ct submit` 未能完成真实 SCT 提交：无 `ct_log` 配置且无可达 CT 日志；错误路径干净，提交管线验证到网络调用前均正常。
- `notify test-smtp`：config 未配 `smtp.host`，报清晰错误 `SMTP not configured`（预期错误路径，非 bug）。

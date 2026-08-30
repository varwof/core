# varwof-core 性能工程工作日志

- 日期: 2026-08-27
- 关联: [基准报告](benchmark-report-2026-08-27.md)（本文为其前置工程记录 §1–§4；
  基准报告的测量结论见基准报告 §1–§8）
- 范围: argon2 认证根因、DA nonce 批量写、User/Token 内存索引、MariaDB+engine
  写管线崩溃修复（R12）、瓶颈 prof + 锁分片 + 满缓冲 herd 修复（R4/R13）

> 纯写路径 14K/sec 溯源: `BenchmarkRecordBufferFlushBatch` (recordbuffer 包)
> = 100 条/批 `FlushAll`→SQLite 批量 insert, 本机 7.38ms/100 条 ≈ **13,600/s**。
> 该数字无 HTTP/签名/AIC, 是批落库纯吞吐, 不是端到端上限。

## §1 argon2 根因与批量写路径（PG/MariaDB 迁移 + engine 模式）

### bench 工具变更

- 新增 `-engine` 标志: 启用 `EnableEngine` (cfg.Engine MaxCerts=10M /
  MaxDANonces=20M / MaxNonces=20M, 内存即真相 + 异步批量落库; engine 内部
  StopRecordBuffer, 故不再叠加 record buffer 模式)。`WriteMaxPending` 复用
  `-maxpending`。
- 新增 `-cpuprofile/-memprofile`: `StopCPUProfile` 移至 `env.Run()` 之后、
  `Close()` 之前, 保证关停排空期 (AIC 拖尾 3× 时长) 不把 profile 截成 0 字节。
- **认证改为启动时一次 login 换 Bearer token** (见 argon2 根因)。

### 引擎模式三后端对比 (18 核 Intel Ultra 5 125H / 32 GB)

| 后端 | 场景 | 引擎 | agents | max_pending | certs/s | 失败 | p50 | 备注 |
|------|------|------|--------|-------------|---------|------|-----|------|
| PG | aic | 引擎 | 2500 | 20,000(默认) | 888 | **71% 503** | 123ms | 503=写管线 rb.IsFull() 背压 |
| SQLite | aic | 引擎 | 2500 | 20,000 | 542 | 9.6% (仅 HTTP0) | 3.6s | 单写锁争用无 503, 延迟飙 |
| PG | regular | 引擎 | 2500 | 200,000 | **2,570** | 0% | 1.5ms | — |
| MariaDB | regular | 引擎 | 2500 | — | ~398 | 崩 | — | **写管线瘫: 内存涨 21GB + connection reset by peer** |
| MariaDB | regular | record buffer | 2500 | — | 3,105 | 19% 503 | 1.7ms | record buffer 模式正常 |
| PG | regular | record buffer | 2500 | — | 3,790 | — | — | — |
| SQLite | regular | record buffer | 2500 | — | 5,626 | — | — | 批量落库上限 |

### argon2 根因 (决定性, 用户此前已预感 "上次就是它")

pprof (`/tmp/cpu-aic.pb.gz`): **argon2 ≈ 44% CPU**。调用链:

```
bench aicWorker (scenario.go:134)
 └ Server.authByBasic (rbac.go:566)
    └ db.HashPassword (engine db/rbac.go:71 → argon2.IDKey)
```

bench 每个请求都发 Basic Auth (admin/admin), 服务端 `authByBasic` 在
`BasicAuthVerified(cacheKey)` (5min TTL, key=username+salt+hash) 未命中时
**每请求重跑一次 Argon2id (~64MB 内存, 20-50ms)**。regular 与 AIC 两个 worker
都经 `doIssue` 的 SetBasicAuth, 故此前所有 bench 数字全部含此税。

**修复**: bench 启动时用 admin/admin POST `/api/v1/users/login` 一次 (单次
argon2), 之后每请求 `Authorization: Bearer <token>` (token 认证 = 纯 DB 查
询, 无哈希; 与生产 operator/agent 用 token/证书一致)。

### 修复后复测 (token 认证, 引擎 PG 25s)

| 场景 | 修复前 (BasicAuth, certs/s) | 修复后 (Bearer, certs/s) | Δ |
|------|------------------------------|---------------------------|-----|
| aic | 1,990 | **3,151–3,204** | **+58~61%** |
| regular | 2,570 | **4,134** (已达 4,167/s 注入上限) | +61% |

除 argon2 后的 CPU profile 热点是 **ECDSA 验签** (`ecdsa.VerifyASN1` ≈ 25%
CPU, 其中 `ca.VerifyDelegationAuthorization` DA 验签 49.7s + x509
`CreateCertificate` 的 CA 验签 24.7s) + syscalls 9% + GC。但 **这并非瓶颈**:
ECDSA 合计仅 ~3 核/18 核 (17%), 总 CPU 利用率只有 65% (11.7/18 核), 而
p50 延迟却高达 159ms —— CPU 远未打满却深度排队, 说明真正瓶颈是**每请求的
串行 DB 写**。

### AIC 剩余瓶颈实证 (pg_stat_activity 运行时采样)

**每请求一次同步单行 `INSERT INTO da_nonces`** 撑爆 PG WAL:
- 运行中近 200 条 DB 连接全部是 `INSERT INTO da_nonces (nonce) VALUES (...)`/
  `INSERT INTO certificates` 的池化语句, 时刻有 5-10 条并发在写;
- 高频出现 `LWLock: WALWrite / WALInsert / WALSync` 等待 —— 每一行 nonce 都
  同步过 WAL fsync;
- engine 在非 WAL 后端时 `StoreDANonce` 仍是**串行单行 INSERT**
  (engine/engine`writes.go:277`), AIC 每请求必走它。

→ **AIC @2500 的 3,200/s 天花板 = 同步 nonce INSERT + WAL fsync 延迟所致, 与
ECDSA/argon2 无关**。修复方向: `StoreDANonce` 改入 write pipeline 批量落库
(与证书同批), 使 DA nonce 在非 WAL 后端也走内存即真相 + 异步落盘; 或 PG 侧
`wal_sync_method=group_commit`/批处理。签名 (ECDSA) 3 核开销是协议固定成本,
非根因。

### engine 模式遗留问题 (待办)

1. `Engine.StoreDANonce` 在非 WAL 后端 (PG/MariaDB) 是 **同步单行 INSERT**
   (engine`writes.go:277`) → AIC 硬墙之一。
2. **MariaDB + engine 写管线瘫**: 内存暴涨至 21GB + connection reset by peer。
3. 引擎自带 `BenchmarkIssueCertMemory` 持续负载下 FAIL (写管线背压) + 单次
   积压 10 万行刷库 9s。
4. AIC 扩展仍逐条写入 (`BulkInsertAICExtensions` 未实现,
   engine/docs/NEXT_STEPS.md:62)。
5. 启动全量重建用 LIMIT/OFFSET 分页 (load.go, 1000 行/页), 大表 O(n²);
   引擎模式实测前需清空库 (bench_pg/bench_mysql 已 DROP/CREATE 前置)。

### 口径修正

- 首轮报告标题误标 "48 核"; 实际本机为 **18 核** (Intel Ultra 5 125H)。

## §2 引擎侧: DA nonce 批量写 + User/Token 内存索引

承接 "§1 engine 模式遗留问题": `StoreDANonce` 非 WAL 分支已从同步单行
INSERT 改为走 record buffer 批量落库 (`RecordBuffer.AddDANonce`, 满则强制
flush, 永不拒绝; 收敛经 `BulkStoreDANonces`)。p50 由 159ms 降至 ~47ms。复测
细节与本仓库文档 (RISKS/REQUIREMENTS/functions) 已同步。

用户在复检时追问 "select 不应该从内存中查找吗?" —— 证实 engine 的
user/token 没有内存索引, 且 core serve 每请求认证仍打 2 次 DB:

- `authByToken`: `GetToken` (`SELECT u.id,u.username,u.role FROM rbac_api_token
  JOIN rbac_users ...`) + `GetUserByUsername` (`SELECT id,username,password_hash,
  salt,role,COALESCE...`);
- `authByBasic` / `authFromAIC` / gateway 委托 / 路由规则同样每次
  `GetUserByUsername`。

**决策**: 采用"完整内存即真相" —— engine 新增 User 索引 (rbac_users 全行) +
Token 索引 (仅存 SHA-256 hash, 永不缓存明文 token; 读时校验 expiry + 用户
enabled, 语义等同 `db.GetToken` 的 JOIN+WHERE):

- 启动重建 `load()` 全量载入 users/tokens (表小, 单查询, 不分页);
- serve 侧新增 `getUserByUsername` / `getToken` 包装方法: **engine 优先, miss
  回退 DB** (与 `getCertStatus` 同模式, OOB 写入仍可见);
- 写路径写穿: 登录/建 token (`createAPIToken`) 先落 DB 再 `PutTokenHash` 进内
  存; 建/改/删用户 (`createUser` / `updateUserPassword` / `updateUserOperatorCert`
  / `deleteUser`) 与 `deleteTokenByID` / 密码轮换清 token (`DeleteTokensByUserID`)
  同步更新内存;
- 唯一权衡: OOB (CLI/第二实例) 创建的用户不在内存 → token 认证回退 DB (与证书
  OOB 行为一致), 已在测试中断言。

**复测 (PG engine, 25s, 2500 agents/users, maxpending=200000, Bearer)**:

| 阶段 | certs/s | p50 | p95 | error |
|------|---------|------|------|-------|
| BasicAuth (argon2) | 1,990 | 158ms | — | — |
| Bearer token 认证 | 3,204 | 158ms | — | — |
| + DA nonce 批量写 | 3,529 | 47ms | 394ms | 0.48% |
| + User/Token 内存索引 (600ms 间隔) | **4,111** | **2.7ms** | 22.1ms | 0.00% |
| + 同上 (100ms 间隔, 25k/s 注入) | 3,643 | 287ms | 850ms | 3.58% (503 背压) |

- **600ms 间隔 (注入上限 4,167/s): 命中天花板**, 4,111/s ≈ 上限; 认证从关键
  路径移除后 p50 降到 ms 级;
- **100ms 间隔把压力推到写管线**: 出现 503 (maxpending 背压), 真实墙 =
  record buffer 批量落库吞吐 ≈3.6-4.1K/s (与早期 "PG regular 4,134" 吻合),
  **与认证/ECDSA/argon2/nonce 均无关**;
- 运行时 `pg_stat_activity`: 仅存批量 `INSERT INTO certificates`, 卡 connections
  稳定 (采样 2), 无任何 user/token SELECT、无单行 da_nonce INSERT。

新增 engine 测试: `TestUserTokenLoadAndAuthLookups`,
`TestTokenIndexExpiryAndEnabled`, `TestUserIndexMutations`,
`TestTokenIndexLoadPutDelete`; core 新增 `rbac_engine_test.go`
(`TestEngineLoginTokenMemoryAuthoritative`, `TestEngineOutOfBandUserFallback`,
`TestEngineUpdateUserPasswordInvalidatesTokens`, `TestEngineUserWriteThroughAPI`,
race 全绿)。engine 全测试与 core `internal/serve` 全测试通过。

待办下一步: ① write pipeline 批量落库再提速 (如今是唯一墙); ② MariaDB+engine
写管线崩溃 (21GB/conn reset) 修复; ③ `BulkInsertAICExtensions` 落地; ④ 启动
LOAD 改分批 (替代 LIMIT/OFFSET)。

## §3 MariaDB+engine 写管线崩溃根因与修复 (R12)

承接上文 "§2 engine 模式遗留问题 ②"。**两层根因**:

1. **文档记录的 21GB = OOM 击杀** (`sudo dmesg` 实证): 原始崩溃轮
   `oom-kill: task=bench-smoke, anon-rss:~21GB` (两次)。"connection reset by
   peer" 是其下游表象。现版本 `MaxResidentBytes` 默认 2GiB 预算生效 (options.go
   :98-99), RSS 平台化, 已不再复现。
2. **当前代码的真实缺陷 = MariaDB 半开连接无读超时**: `bulkInsertChunk→Exec→
   mysqlConn.readPacket` 无 deadline 永久阻塞, flush 全程持有 `flushMu` →
   drain goroutine 卡死 → pending 钉在 maxPending (全请求 503) →
   `Stop()→FlushAll()` 死锁等待同一把锁 → 优雅停机挂死 (SIGQUIT dump 实证,
   goroutine 1 主栈 `FlushAll` 等 flushMu; recordbuffer run→drain→flushLocked→
   `BulkInsertCertRecords`→readPacket 卡读)。MariaDB 进程本身无异常 (processlist
   显示 INSERT 正常执行), 是客户端侧无超时导致的挂死。

**修复 (engine 仓, R12)**:
- `db/db.go`: mysql DSN 注入 `ensureMariaDBTimeouts` (`timeout=10s&readTimeout=30s&
  writeTimeout=30s`, 已有不覆盖, `@unix(` 跳过); 新增 `ExecContext`;
- `db/batch.go` / `db/da_nonces.go`: `BulkInsertCertRecordsCtx` /
  `BulkStoreDANoncesCtx` (旧入口委托 Background);
- `recordbuffer`: `flushLocked` / `replayWAL` 批量写包 `flushDBTimeout=2min`
  ctx 兜底 —— 半开连接至多拖 2 分钟即报错重试, 不再无限阻塞;
- 顺带: PG/MariaDB 批量分块 **39 → 500 行/条** (`certChunkSize`, SQLite 守 999
  变量上限), 写入往返次数降 ~13× —— 直接破除写管线墙一部分。

**复测 (本机 MariaDB 10.11 / PostgreSQL 15, 均 exit=0 且打印报告)**:

| 场景 | 修复前 | 修复后 |
|------|--------|--------|
| MariaDB regular @100ms (原崩溃场景) | ~398/s 崩 (21GB/conn reset) | **7,575 certs/s**, p50 80.7ms, 错误 35% (503 背压) |
| MariaDB AIC @100ms | 4,325/s | **6,034 certs/s**, p50 305.9ms, 错误 1.61% |
| MariaDB AIC @600ms | — | 4,114 certs/s, 错误 0.06% |
| PG AIC @600ms | 4,111/s | 4,054 certs/s (无回归, p50 2.9ms) |

> 说明: MariaDB regular @100ms 的错误率 35% 来自 maxpending 背压 (503), 属设计内
> 限流, 非故障; 关键是**不再崩溃/挂死, 停机干净退出**。高注入下停机会把积压
> (可达 ~200k) 以 MariaDB 写墙速度 (~2-4k/s) 同步排空, 故极端压测的关停排空期
> 需预留数分钟 (属预期, 非挂死; 期间 MariaDB 持续 INSERT)。

**验证**: `-race` 全绿 (db/recordbuffer/engine); 新单测
`TestEnsureMariaDBTimeouts` / `TestBulkInsertCertRecordsCtxCancelled` /
`TestBulkStoreDANoncesCtxCancelled`。engine `docs/RISKS.md` R12、`NEXT_STEPS.md`
已同步记录。

## §4 瓶颈 prof 分析 + 锁分片 + 满缓冲 herd 修复 (R4/R13)

**prof 结论 (AIC MariaDB @100ms, 18 核只用了 ~8 核)**: 此前 p50=锁排队、吞吐
受两处单锁 + ECDSA 限制、写管线已退为地板 (不再拖后腿)。用户对 nonce 的见解
正确并被采纳 —— DA nonce 有 timestamp+lifetime, 新鲜度检查 (skew 30s) 已限制
可用窗口, 内存留存只需 **skew + 3min 缓冲** (勿用 24h flat NonceTTL, 会存几亿
条)。

**本轮优化 (engine 仓)**:
- **DA nonce 短留存**: `StoreDANonce(nonce, exp)` 改签名, serve 侧
  `daNonceExpiry(ts, lifetime, skew, ttl)` 用 skew>0 → lifetime → ttl 取最短,
  下限 now+3min 缓冲。内存侧 40s 运行 RSS 峰值 3.04GB→1.86GB 且可回落。
- **NonceSet 16 片分片** (FNV-1a, count atomic, 满时 reclaimExpired 全片扫),
  **CertIndex 16 片分片** (R5, 单点操作单片锁, 跨片查询逐片 RLock 合并)。
- **bench 预生成 agent 密钥/CSR** (aicWorker 不再在计时窗内做服务端 keygen)。
- **R13 满缓冲 herd 修复** (见 engine RISKS.md): `AddDANonce` 满缓冲时不再同步
  `FlushAll()` (会打雷群涌入 flushMu 冻结全服务器), 改为 `waitForCapacity()`
  广播等待; 5s 无法腾出容量 → `ErrBackpressure` → HTTP 503。
- 顺带修复 R5 重写时引入的 `certAfterCursor` 游标逻辑反转 (分页测试回归)。

**复测 (本机 MariaDB 10.11, engine 模式, 2500 agents/2500 users, 均 exit=0)**:

| 场景 | 数值 |
|------|------|
| AIC @100ms 20s | 5.3–5.5k certs/s, p50 137–220ms (缓冲吸收突发) |
| AIC @100ms 40s (修复前 R5 前基线 3,160/s; R5 修复前 40s 塌缩至 ~108k 总量) | **~163k 成功 / 40s ≈ 4.1k certs/s 持续**, 无塌缩, 背压=干净 503 |
| MariaDB 批量插入独立上限 (500 行 chunk, 热) | ≈ 7.3k certs/s |

> 关键: **修复前的 40s 塌缩是 R13 的 flushMu herd** —— 缓冲 ~18s 填满后每个
> `AddDANonce` 同步 FlushAll, 2k+ goroutine 排在同一把锁后面, 服务器冻结
> (dump 实证); 修复后 40s 总量 163k 恰好 = MariaDB 批量插入持续上限 (含 DA nonce
> 约 8k records/s), 即吞吐已被后端写墙封顶, 剩余提升需减写 (见待办)。

验证: `-race` 全绿 (db/recordbuffer/engine); serve 相关用例绿; engine
`docs/RISKS.md` R13、`NEXT_STEPS.md` 已同步。

待办下一步: ① 吞吐已到 MariaDB 写墙 (~4k certs/s 持续), 想再上需减写:
   - AIC 场景每请求写 1 cert + 1 nonce = 2 条 DB 写; 可评估 DA nonce 是否必须
     批量落库 (重放防护在内存, DB 侧仅审计/恢复用途);
   ② `BulkInsertAICExtensions` 落地; ③ 启动 LOAD 改分批 (替代 LIMIT/OFFSET)。
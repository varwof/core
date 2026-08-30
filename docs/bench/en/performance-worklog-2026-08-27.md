# varwof-core Performance Engineering Work Log

- Date: 2026-08-27
- Related: [Benchmark Report](benchmark-report-2026-08-27.md) — this file is its
  prerequisite engineering record §1–§4; the report's measurement conclusions are in
  benchmark report §1–§8
- Scope: argon2 auth root cause, DA nonce batch writes, User/Token in-memory indexes,
  MariaDB+engine write-pipeline crash fix (R12), bottleneck prof + lock sharding +
  full-buffer herd fix (R4/R13)

> The 14K/sec pure-write-path trace comes from `BenchmarkRecordBufferFlushBatch`
> (recordbuffer package) = 100 records/batch `FlushAll`→SQLite bulk insert, 7.38ms/100
> records on this machine ≈ **13,600/s**. That number has no HTTP/signing/AIC — it's the
> pure batch-write ceiling, not an end-to-end limit.

## §1 argon2 root cause and batch write path (PG/MariaDB migration + engine mode)

### bench tool changes

- New `-engine` flag: enables `EnableEngine` (cfg.Engine MaxCerts=10M /
  MaxDANonces=20M / MaxNonces=20M; memory is truth + async batch persist; engine
  internally stops the record buffer, so record-buffer mode is not stacked).
  `WriteMaxPending` reuses `-maxpending`.
- New `-cpuprofile/-memprofile`: `StopCPUProfile` moved after `env.Run()`, before
  `Close()`, so the shutdown drain phase (AIC tail = 3× duration) is not truncated to a
  0-byte profile.
- **Auth changed to a one-time login at startup → Bearer token** (see argon2 root cause).

### Three backend comparison in engine mode (18-core Intel Ultra 5 125H / 32 GB)

| Backend | Scenario | Engine | agents | max_pending | certs/s | failures | p50 | Notes |
|---------|----------|--------|--------|-------------|---------|----------|-----|-------|
| PG | aic | engine | 2500 | 20,000 (default) | 888 | **71% 503** | 123ms | 503 = write-pipeline rb.IsFull() backpressure |
| SQLite | aic | engine | 2500 | 20,000 | 542 | 9.6% (HTTP0 only) | 3.6s | single-writer lock contention, no 503, latency spikes |
| PG | regular | engine | 2500 | 200,000 | **2,570** | 0% | 1.5ms | — |
| MariaDB | regular | engine | 2500 | — | ~398 | crash | — | **write pipeline gave up: memory +21GB + connection reset by peer** |
| MariaDB | regular | record buffer | 2500 | — | 3,105 | 19% 503 | 1.7ms | record-buffer mode is healthy |
| PG | regular | record buffer | 2500 | — | 3,790 | — | — | — |
| SQLite | regular | record buffer | 2500 | — | 5,626 | — | — | batch-write ceiling |

### argon2 root cause (decisive; the user already sensed "it was this last time")

pprof (`/tmp/cpu-aic.pb.gz`): **argon2 ≈ 44% CPU**. Call chain:

```
bench aicWorker (scenario.go:134)
 └ Server.authByBasic (rbac.go:566)
    └ db.HashPassword (engine db/rbac.go:71 → argon2.IDKey)
```

The bench sends Basic Auth (admin/admin) on every request; the server's `authByBasic`
reruns **Argon2id on every request** (~64MB memory, 20-50ms) whenever
`BasicAuthVerified(cacheKey)` (5min TTL, key=username+salt+hash) misses. Both the
regular and the AIC workers go through `doIssue`'s `SetBasicAuth`, so every previously
reported bench number includes this tax.

**Fix**: the bench POSTs `/api/v1/users/login` once at startup with admin/admin (a single
argon2 run), then sends `Authorization: Bearer <token>` on every request (token auth =
pure DB lookup, no hashing; matching production operators/agents which use tokens/certs).

### Re-measurement after fix (token auth, engine PG 25s)

| Scenario | Before (BasicAuth, certs/s) | After (Bearer, certs/s) | Δ |
|----------|----------------------------|-------------------------|-----|
| aic | 1,990 | **3,151–3,204** | **+58~61%** |
| regular | 2,570 | **4,134** (already at the 4,167/s injection ceiling) | +61% |

Post-argon2 CPU profile hotspots are **ECDSA verification** (`ecdsa.VerifyASN1` ≈ 25%
CPU, of which `ca.VerifyDelegationAuthorization` DA verification 49.7s + x509
`CreateCertificate` CA verification 24.7s) plus 9% syscalls + GC. But **this is not the
bottleneck**: ECDSA totals only ~3 of 18 cores (17%), overall CPU utilization is just
65% (11.7/18 cores), yet p50 latency is as high as 159ms — CPU is far from saturated
yet deeply queued, so the real bottleneck is the **serial DB write per request**.

### Remaining AIC bottleneck proof (pg_stat_activity live sampling)

**One synchronous single-row `INSERT INTO da_nonces` per request** saturates the PG WAL:
- During the run nearly 200 DB connections are all pooled statements for
  `INSERT INTO da_nonces (nonce) VALUES (...)` / `INSERT INTO certificates`, with 5-10
  concurrent writes at any time;
- Frequent `LWLock: WALWrite / WALInsert / WALSync` waits — every nonce row is
  synchronously fsynced through the WAL;
- On non-WAL backends the engine's `StoreDANonce` is still a **serial single-row INSERT**
  (`engine/engine/writes.go:277`); every AIC request goes through it.

→ **The AIC @2500 ~3,200/s ceiling = synchronous nonce INSERT + WAL fsync latency; it is
unrelated to ECDSA/argon2**. Fix directions: move `StoreDANonce` into the write pipeline
for batched persistence (same batch as certificates), so DA nonces also use
memory-is-truth + async flush on non-WAL backends; or PG-side
`wal_sync_method=group_commit`/batching. Signing (ECDSA) is a fixed 3-core protocol cost,
not the root cause.

### Engine-mode leftovers (to-do)

1. `Engine.StoreDANonce` on non-WAL backends (PG/MariaDB) is a **synchronous single-row
   INSERT** (`engine writes.go:277`) → one of the AIC hard walls.
2. **MariaDB + engine write pipeline collapses**: memory balloons to 21GB + connection
   reset by peer.
3. Engine's own `BenchmarkIssueCertMemory` FAILs under sustained load (write-pipeline
   backpressure) + a single 100k-row backlog flush takes 9s.
4. AIC extensions still written one-by-one (`BulkInsertAICExtensions` not implemented,
   engine/docs/NEXT_STEPS.md:62).
5. Startup full rebuild uses LIMIT/OFFSET pagination (load.go, 1000 rows/page) — O(n²)
   on large tables; clean the DB before measuring engine mode (bench_pg/bench_mysql are
   DROP/CREATE'd upfront).

### Erratum

- The first-round report title wrongly said "48 cores"; this machine is **18 cores**
  (Intel Ultra 5 125H).

## §2 Engine side: DA nonce batch writes + User/Token in-memory indexes

Continuing "engine-mode leftover ①": `StoreDANonce`'s non-WAL branch now goes through the
record buffer for batched persistence (`RecordBuffer.AddDANonce`, flushed when full,
never rejected; converged via `BulkStoreDANonces`). p50 dropped from 159ms to ~47ms.
Re-measurement details and this repo's docs (RISKS/REQUIREMENTS/functions) are in sync.

While re-reviewing, the user asked "shouldn't SELECT be served from memory?" — which
confirmed the engine has **no in-memory index for users/tokens**, and core serve still
hits the DB twice per request for auth:

- `authByToken`: `GetToken` (`SELECT u.id,u.username,u.role FROM rbac_api_token
  JOIN rbac_users ...`) + `GetUserByUsername` (`SELECT id,username,password_hash,
  salt,role,COALESCE...`);
- `authByBasic` / `authFromAIC` / gateway delegation / route rules likewise call
  `GetUserByUsername` every time.

**Decision**: full "memory is truth" — the engine adds a User index (full rbac_users row)
+ Token index (stores only the SHA-256 hash, never the plaintext token; expiry + user
enabled checked on read, semantically equal to `db.GetToken`'s JOIN+WHERE):

- Startup rebuild `load()` fully loads users/tokens (tiny tables, single query, no
  pagination);
- serve side adds `getUserByUsername` / `getToken` wrapper methods: **engine first, on
  miss fall back to DB** (same pattern as `getCertStatus`; out-of-band writes stay
  visible);
- Write path writes through: login / token creation (`createAPIToken`) hits the DB first,
  then `PutTokenHash` into memory; user create/update/delete (`createUser` /
  `updateUserPassword` / `updateUserOperatorCert` / `deleteUser`), `deleteTokenByID`,
  and password rotation token purge (`DeleteTokensByUserID`) update memory in sync;
- Only trade-off: users created out-of-band (CLI/second instance) are not in memory →
  token auth falls back to the DB (consistent with cert OOB behavior); asserted in tests.

**Re-measurement (PG engine, 25s, 2500 agents/users, maxpending=200000, Bearer)**:

| Stage | certs/s | p50 | p95 | error |
|-------|---------|------|------|-------|
| BasicAuth (argon2) | 1,990 | 158ms | — | — |
| Bearer token auth | 3,204 | 158ms | — | — |
| + DA nonce batch writes | 3,529 | 47ms | 394ms | 0.48% |
| + User/Token memory indexes (600ms interval) | **4,111** | **2.7ms** | 22.1ms | 0.00% |
| + same (100ms interval, 25k/s injection) | 3,643 | 287ms | 850ms | 3.58% (503 backpressure) |

- **At the 600ms interval (injection ceiling 4,167/s): the ceiling is hit**, 4,111/s ≈
  the cap; once auth is off the hot path p50 drops to milliseconds;
- **The 100ms interval pushes into the write pipeline**: 503s appear (maxpending
  backpressure); the real wall = record buffer batch-write throughput ≈3.6-4.1K/s
  (consistent with the earlier "PG regular 4,134"), **unrelated to auth/ECDSA/argon2/
  nonces**;
- Live `pg_stat_activity`: only bulk `INSERT INTO certificates` remains, connections
  stable (sample 2), no user/token SELECTs, no single-row da_nonce INSERTs.

New engine tests: `TestUserTokenLoadAndAuthLookups`,
`TestTokenIndexExpiryAndEnabled`, `TestUserIndexMutations`,
`TestTokenIndexLoadPutDelete`; core adds `rbac_engine_test.go`
(`TestEngineLoginTokenMemoryAuthoritative`, `TestEngineOutOfBandUserFallback`,
`TestEngineUpdateUserPasswordInvalidatesTokens`, `TestEngineUserWriteThroughAPI`,
race clean). Engine full tests and core `internal/serve` full tests pass.

Next to-dos: ① speed up write-pipeline batch persistence further (now the only wall);
② fix the MariaDB+engine write-pipeline crash (21GB/conn reset); ③ land
`BulkInsertAICExtensions`; ④ change startup LOAD to batched (replace LIMIT/OFFSET).

## §3 MariaDB+engine write-pipeline crash root cause and fix (R12)

Continuing "§1 engine-mode leftover ②". **Two-layer root cause**:

1. **The documented 21GB is an OOM kill** (`sudo dmesg` proof): the original crash round
   showed `oom-kill: task=bench-smoke, anon-rss:~21GB` (twice). "connection reset by
   peer" was its downstream symptom. The current `MaxResidentBytes` default 2GiB budget
   (options.go:98-99) makes RSS platform-bound and it no longer reproduces.
2. **The real defect in the current code = MariaDB half-open connections with no read
   timeout**: `bulkInsertChunk→Exec→mysqlConn.readPacket` blocks forever with no
   deadline; the entire flush holds `flushMu` → the drain goroutine hangs → pending pins
   at maxPending (all requests 503) → `Stop()→FlushAll()` deadlocks waiting on the same
   lock → graceful shutdown hangs (proven by SIGQUIT dump: goroutine 1 main stack
   `FlushAll` waiting for flushMu; recordbuffer run→drain→flushLocked→
   `BulkInsertCertRecords`→readPacket stuck on read). MariaDB itself is healthy
   (processlist shows INSERTs executing normally) — the hang is the client side having no
   timeout.

**Fix (engine repo, R12)**:
- `db/db.go`: inject `ensureMariaDBTimeouts` into the MariaDB DSN (`timeout=10s&readTimeout=30s&
  writeTimeout=30s`, not overwriting existing, skipping `@unix(`); add `ExecContext`;
- `db/batch.go` / `db/da_nonces.go`: `BulkInsertCertRecordsCtx` /
  `BulkStoreDANoncesCtx` (old entry points delegate to Background);
- `recordbuffer`: `flushLocked` / `replayWAL` wrap batch writes with a `flushDBTimeout=2min`
  ctx fallback — a half-open connection stalls at most 2 minutes before erroring and
  retrying, no infinite blocking;
- Bonus: PG/MariaDB chunk size **39 → 500 rows/statement** (`certChunkSize`; SQLite stays at
  the 999-variable limit), cutting write round-trips ~13× — directly removing part of the
  write-pipeline wall.

**Re-measurement (local MariaDB 10.11 / PostgreSQL 15, all exit=0 with reports printed)**:

| Scenario | Before | After |
|----------|--------|-------|
| MariaDB regular @100ms (original crash scenario) | ~398/s crash (21GB/conn reset) | **7,575 certs/s**, p50 80.7ms, error 35% (503 backpressure) |
| MariaDB AIC @100ms | 4,325/s | **6,034 certs/s**, p50 305.9ms, error 1.61% |
| MariaDB AIC @600ms | — | 4,114 certs/s, error 0.06% |
| PG AIC @600ms | 4,111/s | 4,054 certs/s (no regression, p50 2.9ms) |

> Note: the 35% error rate at MariaDB regular @100ms comes from maxpending backpressure
> (503) — a by-design rate limit, not a failure; the key point is **no more crash/hang,
> clean shutdown**. At very high injection, shutdown drains the backlog (up to ~200k) at
> MariaDB write-wall speed (~2-4k/s), so under extreme load allow several minutes for the
> shutdown drain phase (expected, not a hang; MariaDB keeps INSERTing throughout).

**Verification**: `-race` clean (db/recordbuffer/engine); new unit tests
`TestEnsureMariaDBTimeouts` / `TestBulkInsertCertRecordsCtxCancelled` /
`TestBulkStoreDANoncesCtxCancelled`. engine `docs/RISKS.md` R12 and `NEXT_STEPS.md`
updated.

Next to-dos (updated): ① the write-pipeline wall is partly removed (4,325→6,034/s), but
at 100ms high injection backpressure (503) can still occur; keep evaluating larger
chunks / batched AIC extensions; ② land `BulkInsertAICExtensions`; ③ change startup LOAD
to batched (replace LIMIT/OFFSET).

## §4 Bottleneck prof analysis + lock sharding + full-buffer herd fix (R4/R13)

**prof findings (AIC MariaDB @100ms; the 18 cores only use ~8)**: p50 was lock waiting;
throughput was limited by two single locks + ECDSA; the write pipeline had already become
the floor (no longer the drag). The user's insight about nonces was correct and adopted —
DA nonces carry timestamp+lifetime, the freshness check (skew 30s) already bounds the
usable window, so in-memory retention only needs **skew + 3min buffer** (don't use a flat
24h NonceTTL — it would hold hundreds of millions of entries).

**This round of optimizations (engine repo)**:
- **Short DA nonce retention**: `StoreDANonce(nonce, exp)` changes signature; serve-side
  `daNonceExpiry(ts, lifetime, skew, ttl)` picks the shortest of skew>0 → lifetime → ttl,
  with a lower bound of now+3min buffer. In-memory: 40s run RSS peak 3.04GB→1.86GB and
  reclaimable.
- **NonceSet sharded 16 ways** (FNV-1a, atomic count, full-shard reclaimExpired scan when
  full), **CertIndex sharded 16 ways** (R5, single-shard lock for single-shard ops,
  per-shard RLock merge for cross-shard queries).
- **bench pre-generates agent keys/CSRs** (aicWorker no longer does server-side keygen
  inside the timed window).
- **R13 full-buffer herd fix** (see engine RISKS.md): `AddDANonce` no longer synchronously
  `FlushAll()` on full buffer (that summoned a thundering herd onto flushMu, freezing the
  whole server); instead `waitForCapacity()` broadcasts a wait; if no capacity frees
  within 5s → `ErrBackpressure` → HTTP 503.
- Also fixed a `certAfterCursor` cursor-logic inversion introduced by the R5 rewrite
  (pagination test regression).

**Re-measurement (local MariaDB 10.11, engine mode, 2500 agents/2500 users, all exit=0)**:

| Scenario | Value |
|----------|-------|
| AIC @100ms 20s | 5.3–5.5k certs/s, p50 137–220ms (buffer absorbs bursts) |
| AIC @100ms 40s (pre-fix R5 baseline 3,160/s; pre-R5-fix 40s collapse to ~108k total) | **~163k successes / 40s ≈ 4.1k certs/s sustained**, no collapse, backpressure = clean 503 |
| MariaDB bulk-insert standalone ceiling (500-row chunk, hot) | ≈ 7.3k certs/s |

> Key: **the pre-fix 40s collapse was the R13 flushMu herd** — once the buffer filled
> (~18s), every `AddDANonce` did a synchronous FlushAll, 2k+ goroutines queued behind the
> same lock, freezing the server (dump-proof). After the fix the 40s total of 163k
> exactly equals the MariaDB bulk-insert sustained ceiling (≈8k records/s incl. DA nonces),
> i.e. throughput is now capped by the backend write wall; further gains require writing
> less (see to-dos).

Verification: `-race` clean (db/recordbuffer/engine); serve-related cases green; engine
`docs/RISKS.md` R13 and `NEXT_STEPS.md` updated.

Next to-dos (updated): ① throughput is already at the MariaDB write wall (~4k certs/s
sustained); to go higher you must write less:
   - The AIC scenario writes 1 cert + 1 nonce per request = 2 DB writes; evaluate whether
     DA nonces must be batched to disk at all (replay protection lives in memory; the DB
     side is audit/recovery only);
   ② land `BulkInsertAICExtensions`; ③ change startup LOAD to batched (replace
   LIMIT/OFFSET).
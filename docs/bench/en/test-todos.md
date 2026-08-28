# Test To-Do Items

**Date**: 2026-08-27  
**Status**: Pending

---

## Current Coverage

| Project | Package | Coverage | Status |
|---------|---------|----------|--------|
| core | auth | 88.0% | ✅ |
| core | cmd/pki | 74.7% | ⚠️ |
| core | internal | 90.4% | ✅ |
| core | internal/ca | 78.4% | ⚠️ |
| core | internal/capregistry | 79.5% | ⚠️ |
| core | internal/i18n | 91.2% | ✅ |
| core | internal/notifier | 87.3% | ✅ |
| core | internal/ocsp | 84.2% | ✅ |
| core | internal/pkcs12 | 84.2% | ✅ |
| core | internal/provisioner | 79.6% | ⚠️ |
| core | internal/remotesigner | 89.9% | ✅ |
| core | internal/routing | 91.7% | ✅ |
| core | internal/secrets | 95.7% | ✅ |
| core | internal/serve | 78.5% | ⚠️ |
| core | internal/signer | 80.4% | ✅ |
| core | internal/tsa | 87.8% | ✅ |
| client | client | 70.2% | ⚠️ |
| gateway | capreg | 94.1% | ✅ |
| gateway | http | 76.2% | ⚠️ |
| gateway | tcp | 68.6% | ❌ |
| gateway | udp | 64.5% | ❌ |

**Target**: all packages ≥ 80%

---

## To-Do Items

### 1. Add gateway/udp tests (coverage 64.5%)

- [ ] Add DTLS handshake-failure test
- [ ] Add mTLS authentication-failure test
- [ ] Add QUIC connection-timeout test
- [ ] Add invalid-packet handling test
- [ ] Add connection-limit-triggered test
- [ ] Add nonce replay/expiry test

### 2. Add gateway/tcp tests (coverage 68.6%)

- [ ] Add tunnel connection-failure test
- [ ] Add mesh node-disconnect test
- [ ] Add port-mapping conflict test
- [ ] Add audit-log write-failure test
- [ ] Add cert-expiry disconnect test
- [ ] Add concurrent-connection-limit test

### 3. Add client tests (coverage 70.2%)

- [ ] Add AIC batch-issuance boundary test
- [ ] Add encrypted-key decryption-failure test
- [ ] Add config-file permission-denied test
- [ ] Add network-timeout retry test
- [ ] Add cross-host redirect interception test (CL2)
- [ ] Add policy-signature forgery detection test

### 4. Add core/cmd/pki tests (coverage 74.7%)

- [ ] Add `init-full` hierarchy-mode test
- [ ] Add `ca offline-sign` flow test
- [ ] Add `cold-backup` encryption verification test
- [ ] Add `verify-path` policy verification test
- [ ] Add `benchmark` output-format test
- [ ] Add `report` PDF generation test

### 5. Add core/internal/ca tests (coverage 78.4%)

- [ ] Add name-constraint violation test
- [ ] Add policy-constraint violation test
- [ ] Add path-length overflow test
- [ ] Add cross-cert revocation-chain test
- [ ] Add trust-bridge federation-failure test
- [ ] Add key-rotation atomicity test

### 6. Add core/internal/serve tests (coverage 78.5%)

- [ ] Add RBAC enterprise-mode CA scope rejection test
- [ ] Add delegation-proxy session-expiry test
- [ ] Add config hot-reload atomicity test
- [ ] Add audit-log Merkle-chain integrity test
- [ ] Add rate-limit triggered test
- [ ] Add CORS cross-origin rejection test

### 7. Add core/internal/provisioner tests (coverage 79.6%)

- [ ] Add OIDC auth-flow test
- [ ] Add Basic Auth Argon2id verification test
- [ ] Add mTLS incomplete-chain test
- [ ] Add token-expiry/revocation test
- [ ] Add AIC empty-capability-intersection test

### 8. Add core/internal/routing tests (coverage 91.7%)

- [ ] Add wildcard path-match boundary test
- [ ] Add allow_aic=false rejection test
- [ ] Add require_role suffix-match test

### 9. Negative tests (all projects)

- [ ] Authentication-failure scenarios (invalid token, expired cert, wrong password)
- [ ] Permission-denied scenarios (insufficient role, CA scope mismatch)
- [ ] Invalid-input scenarios (malformed JSON, overlong fields, empty required fields)
- [ ] Concurrency-conflict scenarios (revoking the same cert simultaneously)
- [ ] Resource-exhaustion scenarios (memory, connections, file handles)

### 10. Security tests (all projects)

- [ ] SQL-injection protection test
- [ ] Path-traversal protection test
- [ ] Cert-forgery detection test
- [ ] Private-key-leak protection test
- [ ] Policy-file tamper detection test
- [ ] Replay-attack protection test (nonce)

### 11. Stress tests

- [ ] Concurrent certificate issuance (100+ concurrent)
- [ ] Concurrent API requests (1000+ QPS)
- [ ] Large-scale cert revocation (10000+ entries)
- [ ] CRL generation performance
- [ ] OCSP response cache hit rate

### 12. Large-scale Agent Simulation (50k people × 10 agents × 24 hours)

**Existing tools** (in the varwof repos):
- `engine/engine/aic_sim_bench_test.go` — 200k/1M/2M cert simulation
- `engine/engine/scale_bench_test.go` — index scaling 0/10k/100k × 1/16 concurrency
- `core/cmd/pki/benchmark.go` — crypto algorithm benchmarks
- `core/deploy/enterprise-full-test.sh` — 14 CA + 80+ cert full-stack integration

**Missing tools**:
- [x] Build a large-scale agent concurrency simulator (Go program) — done: `bench/`
      (embedded serve.NewFull + SQLite, regular/AIC scenarios, stress/random modes)
- [x] Configurable: enterprise count, agents per enterprise, request interval, duration
      — `-agents/-users/-interval/-duration`
- [x] Metrics collection: QPS, latency P50/P95/P99, error rate, DB size — JSON + text
      reports (`../results/`)
- [ ] Multi-host distributed load testing (SSH scheduling)
- [ ] HTML report generation (charts)
- [ ] Baseline comparison (diff vs previous run)

**First-round benchmark** (2026-08-27; reported as "48 cores / 30GB RAM, SQLite file
DB" — later corrected to 18 cores, see the [work log](performance-worklog-2026-08-27.md) §1 erratum):
- Report: `./benchmark-report-2026-08-27.md` | Work log: `./performance-worklog-2026-08-27.md` | Raw JSON: `../results/*.json`
- Key findings: with the default record_buffer (max_pending=20000), sustained issuance is
  throttled to ~560/s (many 503s); raising max_pending gets regular to ~5,600/s; AIC degrades
  to 533/s at 2500 agents because of the synchronous `da_nonces` write per issuance plus
  SQLite single-writer lock contention.

**To-dos from first-round benchmark follow-ups**:
- [x] Validate the `record_buffer.max_pending=20000` backpressure semantics: confirmed 503
      is the intended full-chain rate limit of the P1 design; added config docs
      (max_pending/threshold tuning guide)
- [x] AIC write-path optimization ①: enable the in-memory engine (`EnableEngine`) so
      `da_nonces` go to memory
- [x] AIC write-path optimization ②: Postgres DSN comparison (engine already supports the
      pgx dialect)
- [ ] Storage model: estimate disk/row model for 360M certs (1.9KB/row); define a SQLite
      WAL lifecycle and archival policy
- [x] bench enhancements: added `-engine` (in-memory engine mode) and Postgres DSN
      (`postgres://`) support; records WAL peaks
- [x] Baseline re-measure: after fixing the record-buffer close flush (fixed 2026-08-27),
      re-ran the matrix
- [x] **argon2 root cause**: per-request Basic Auth → `authByBasic`→`db.HashPassword`→
      `argon2.IDKey` cost 44% CPU; bench changed to login-once + Bearer token; AIC and
      regular each +60% (see [Performance Engineering Work Log](performance-worklog-2026-08-27.md) §1)
- [x] engine leftover: PG `StoreDANonce` synchronous single-row INSERT converted to batch
      (see "DA nonce batch writes" below); **MySQL+engine write-pipeline crash
      (21GB/conn reset) fixed** — see "MySQL+engine write-pipeline crash root cause and
      fix" below
- [ ] `BulkInsertAICExtensions` landed; engine startup LOAD switched to batching (replace
      LIMIT/OFFSET)
- [x] **Remaining AIC wall identified**: not ECDSA/argon2. After removing argon2, ECDSA
      verification is only ~3 cores (CPU utilization 65%, not saturated); the real
      bottleneck = synchronous single-row `INSERT INTO da_nonces` fsynced through the WAL
      per request (proven by pg_stat_activity sampling); fix directions in the report
- [x] **DA nonce batch writes (fixed engine-side)**: `StoreDANonce`'s non-WAL branch now
      goes through `RecordBuffer.AddDANonce` batch convergence + flush-when-full; AIC
      re-measured 3,529/s, p50 47ms ([Performance Engineering Work Log](performance-worklog-2026-08-27.md) §2 table)
- [x] **User/Token in-memory indexes (landed in both engine + serve)**: engine adds
      User/Token indexes + startup load; serve auth read path `getUserByUsername`/`getToken`
      engine-first with DB fallback; write path writes through
      (login/create/delete/password-rotate). AIC @600ms reached **4,111 certs/s (injection
      ceiling)**, p50 2.7ms; DB activity reduced to bulk `INSERT INTO certificates` only.
      New tests green (4 engine + 4 core rbac_engine, race clean)
- [x] **MySQL+engine write-pipeline crash root cause and fix (R12, engine repo)**:
      two-layer cause — ① the documented 21GB proven by dmesg to be an **OOM kill**
      (`oom-kill bench-smoke anon-rss ~21GB`; current 2GiB `MaxResidentBytes` budget
      guards it, no longer reproduces); ② the real defect = **MySQL has no read timeout**,
      half-open connections let `bulkInsertChunk→Exec→readPacket` block forever while
      holding `flushMu` → drain stuck (pending pins at maxPending, all 503) →
      `Stop()→FlushAll()` deadlock hang. Fix: inject
      `timeout=10s&readTimeout=30s&writeTimeout=30s` into the MySQL DSN
      (`ensureMySQLTimeouts`) + `ExecContext` + `BulkInsertCertRecordsCtx`/
      `BulkStoreDANoncesCtx` + recordbuffer `flushDBTimeout=2min` ctx fallback.
      **Bonus PG/MySQL chunk 39→500 rows/statement**
      (`certChunkSize`, round-trips down ~13×). Re-measured (all exit=0 with reports):
      MySQL regular @100ms **7,575/s**, AIC @100ms **6,034/s** (was 4,325 before fix),
      AIC @600ms 4,114/s; PG AIC @600ms 4,054/s no regression. `-race` clean; new unit
      tests `TestEnsureMySQLTimeouts`/`TestBulkInsertCertRecordsCtxCancelled`/
      `TestBulkStoreDANoncesCtxCancelled`
- [ ] Next wall: **write-pipeline batch-write throughput** — already improved by the R12
      chunk optimization (MySQL AIC 4,325→6,034/s), but at 100ms high injection
      backpressure (503) can still occur; keep evaluating larger chunks / batched AIC
      extensions
- [ ] engine leftover: land `BulkInsertAICExtensions`; startup LOAD switched to batching
      (replace LIMIT/OFFSET)

### 13. Fuzzing

- [ ] Cert parser fuzz
- [ ] CSR parser fuzz
- [ ] JSON request-body fuzz
- [ ] Config-file parser fuzz
- [ ] PEM encode/decode fuzz

---

## Priorities

| Priority | Task | Impact |
|----------|------|--------|
| P0 | Negative tests | prevent bad behavior in production |
| P0 | Security tests | prevent security vulnerabilities |
| P1 | gateway/udp additions | coverage < 70% |
| P1 | gateway/tcp additions | coverage < 70% |
| P1 | client additions | coverage < 75% |
| P2 | core/cmd/pki additions | CLI completeness |
| P2 | core/internal/ca additions | core CA logic |
| P2 | core/internal/serve additions | API service layer |
| P3 | Stress tests | performance validation |
| P3 | Fuzzing | robustness validation |
| P3 | Large-scale agent simulation | production validation |
| P3 | Benchmark follow-ups: AIC write-path optimization (engine/Postgres) | carrying the production 4,167 req/s |

---

## Progress Tracking

| Task | Owner | Start date | Completion date | Status |
|------|-------|------------|-----------------|--------|
| | | | | |
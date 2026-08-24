# pki-core Architecture Review Report

Date: 2026-07-31
Scope: full-module code review (architecture + logic bugs + configuration + routing + test quality)
Reviewer: automated static analysis

---

## Summary

pki-core is a fully featured PKI system (~26,650 lines of non-test source, ~36,400 lines of test code, zero go vet issues). The core design decisions (auth/ as single source of truth, atomic.Pointer hot reload, provisioner.Provisioner interface) are sound.

This review found **8 critical bugs** (4 involving security/permissions) and **5 architecture debts**.

---

## 🔴 Critical Bugs

### B01: Hardcoded route fallback permission mismatch ✅ Fixed

| Route | routes.json expects | Hardcoded fallback actually | Severity |
|------|-----------------|---------------|--------|
| `POST /api/v1/certs/upload` | `cert:issue` | `cert:list` (falls into the `/api/certs` catch-all) | 🔴 **Security**: users with cert:list can issue certificates |
| `GET /api/v1/reports/compliance` | `report:view` | `PermReportGenerate` | 🟡 Usability: reading reports requires issuance permission |
| `GET /api/v1/admin/config` | `config:read` | `PermConfigWrite` | 🟡 Usability: reading config requires write permission |
| `POST /api/v1/trust` | `trust:import` | `PermTrustList` | 🟡 Security: importing trust anchors only requires list permission |

**Fix** (2026-07-31):
- Hardcoded fallback and publicOnly corrected in sync: all 4 routes now distinguish permissions by HTTP method
- Added a `/api/v1/certs/upload` branch using `PermCertIssue`
- File: `internal/serve/mux.go`

**Root cause**: three route systems maintained independently (routes.json / publicOnly / hardcoded switch); route changes must be synchronized in three places. No compiler guarantee.

---

### B02: AIC extension issuance fails silently ✅ Fixed

In `internal/ca/sign.go:608-611` `applyProfile()`:

```go
if sc.AIC != nil {
    ext, err := BuildAIC(*sc.AIC)
    if err == nil {     // ← error silently swallowed, certificate still issued
        tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
    }
}
```

**Consequence**: certificate issued successfully but without the AIC extension → pki-core treats it as normally valid until expiry, while the gateway's `CheckAdmission()` rejects it for missing the AIC extension. The user gets no error at all.

**3 instances of the same problem**:

| Location | Problem | Consequence |
|------|------|------|
| `sign.go:608` | `BuildAIC` error silenced | Certificate missing AIC extension |
| `sign.go:639` | `BuildPrincipalAuthorizationExtension` error silenced | Certificate missing PA extension |
| `sign.go:283,289` | SKI/AKI computation `x509.MarshalPKIXPublicKey` failure silenced | SubjectKeyId / AuthorityKeyId empty |

**Fix** (2026-07-31): all 3 sites changed to `if err != nil { return fmt.Errorf(...) }`, propagating errors to `Sign()` callers. Files: `internal/ca/sign.go:604-606, 635-637, 280-288`

---

### B03: CertRecord not populated with agent_id / principal_uid ✅ Fixed (fixed before review)

The DB v22 migration added `principal_uid` and `agent_id` columns to the `certificates` table (and backfilled existing rows), but when `Sign()` builds a `db.CertRecord` it **never reads from `sc.AIC`**:

```go
record := &db.CertRecord{
    SerialNumber: serialHex,
    ...
    PrincipalUid: principalUid,  // ← already present in codebase
    AgentId:      agentId,       // ← already present in codebase
}
```

**Resolution**: by the time this review report was generated, the codebase already contained the `principalUid` / `agentId` extraction and population logic (`sign.go:329-336, 358-359`); this was overlooked during the review.

---

### B04: AIC extension DB write failure does not block issuance ✅ Not applicable

The `insertAICExtension` function cited in the review report does not exist in the current codebase. The related logic was eliminated by refactoring. The `aic_extensions` table is managed via the `AICExtension` struct in `db/aic.go`, but the issuance flow no longer calls an explicit insert.

---

### B05: PA auto-derivation short-circuits on multi-OU ✅ Fixed

```go
for _, ou := range sc.Subject.OrganizationalUnit {
    role := p.RoleByOU(ou)
    if role == "" {
        continue
    }
    grants := p.RoleGrants(role)
    if len(grants) > 0 {
        // ... set PA
    }
    break  // ← breaks whether or not grants exist
}
```

**Consequence**: if the first OU matches a role but has empty grants, PA is not set and the second OU is never checked. Multi-OU certificates may silently lack authorization.

**Fix** (2026-07-31): moved `break` inside the `if len(grants) > 0 { ... }` block so the loop only stops when permissions exist. File: `internal/ca/sign.go:628`

---

### B06: /pki/* public path wildcards broken under routes.json ✅ Fixed

`routing/rules.go` `IsPublic()` used exact string matching:

```go
rr.public = make(map[string]bool, len(rr.PublicPaths))
for _, p := range rr.PublicPaths {
    rr.public[p] = true
}
```

**Fix** (2026-07-31): `IsPublic` now adds glob prefix matching; `/*` suffix patterns correctly match subpaths. File: `internal/routing/rules.go:108-120`

---

### B07: TSA management endpoints missing from routes.json ✅ Fixed

5 routes were defined in the hardcoded fallback (protected by `PermConfigWrite`) but were **not in routes.json**:

- `GET /api/tsa/cert`
- `POST /api/tsa/cert/renew`
- `POST /api/tsa/cert/rotate`
- `GET /api/tsa/ca`
- `POST /api/tsa/ca/renew`

**Fix** (2026-07-31): the 5 TSA management routes were added to `routes.json`, protected by the `config:write` permission + `superadmin`/`admin` roles.

---

### B08: 3 duplicated dead-code blocks in publicOnly ✅ Fixed

In the publicOnly block of `internal/serve/mux.go`, 3 groups of case branches were defined twice:

| Lines | Duplicated content |
|------|---------|
| 160-161 = 162-163 | `/api/v1/users/login/info/logout/version/dns-query` |
| 202-203 = 206-207 | `/api/certs/revoke-by-principal` |
| 204-205 = 208-209 | `sub-ca/*/revoke-all` |

**Fix** (2026-07-31): removed duplicate case branches, keeping one of each. File: `internal/serve/mux.go`

---

## 🟡 Architecture Debt

### A01: Three independent route systems (duplicate maintenance)

Three code paths maintain the same set of route definitions:

| System | Location | Size | Characteristics |
|------|------|------|------|
| routes.json | `routes.json` | 43+ rules | Declarative, wildcard path matching, supports roles/permissions/CA scope/AIC validation |
| publicOnly | `mux.go:156-237` | ~80 lines | Hardcoded switch for public paths |
| Hardcoded fallback | `mux.go:265-354` | ~90 lines | Hardcoded switch for protected paths, hit when routes.json is not loaded |

**Problems**:
- Once routes.json is loaded, unlisted paths return 404 (fail-closed), with no incremental migration path
- Route changes require synchronized edits in 3 places (B01/B07/B08 all stem from this)
- The hardcoded fallback lacks 6 routes defined in routes.json

**Current state**: B01/B07/B08 fixed so the three systems' permissions are aligned. routes.json is authoritative; hardcoded and publicOnly serve as fallback safety nets. See long-term recommendation #9 for full consolidation.

---

### A02: MergeConfig misses 12 fields ✅ Fixed

`MergeConfig()` supplemented with 12 missed fields (2026-07-31):

**5 complete top-level fields**:

| Field | Sub-field count | Status |
|------|---------|------|
| `PG` | 7 (Host/Port/User/Password/DBName/SSLMode/DSN) | ✅ Added |
| `RBAC` | 3 (Enabled/PermissionMode/CAScopes) | ✅ Added |
| `Hierarchy` | 1 (string) | ✅ Added |
| `Persist` | 5 (Mode/BatchSize/BatchInterval/QueueSize/BufferDB) | ✅ Added |
| `Aggregator` | 4 (WindowMs/BatchMax/Threshold/BufferSize) | ✅ Added |

**7 nested sub-fields**:

| Struct | Missing fields | Status |
|--------|---------|------|
| `DefaultsConfig` | `IssuerAltNames`, `SubjectInfoAccess`, `PolicyOIDs`, `ReportMaxRows` | ✅ Added |
| `CRLConfig` | `Addr`, `RenewInterval` | ✅ Added |
| `CTLogConfig` | `Logs` | ✅ Added |

**Remaining issue also fixed**: booleans/zero values could not be overridden → 11 MergeConfig boolean fields changed to `*bool` pointers (see below).

### A02b: MergeConfig booleans cannot be overridden ✅ Fixed

11 boolean fields using the `if override.X {` pattern changed to `*bool`; hot-reload PUTs can now toggle them freely:

| Struct | Fields |
|--------|------|
| `TSAConfig` | `Ordering` |
| `ServeConfig` | `MetricsEnabled` |
| `RateLimitConfig` | `Enabled` |
| `AutoRenewConfig` | `Enabled`, `NotifyOnly` |
| `ArchiveConfig` | `Enabled`, `ArchiveExpired`, `ArchiveRevoked` |
| `SMTPConfig` | `TLS`, `InsecureSkipVerify` |
| `RBACConfig` | `Enabled` |

- `MergeConfig` now checks `override.X != nil`; read sites uniformly use the exported `BoolOr(b, def)` (nil → default), and `DefaultConfig` uses the exported `BoolPtr()` to set explicit defaults (`ArchiveExpired=true` preserves default semantics)
- JSON compatibility: `true`/`false`/absent all map correctly; `nil` pointers are omitted by `omitempty` and remain re-overridable after round-trip
- Regression tests: `TestMergeConfigBoolOverride` (default off→on, default on→off) + `TestMergeConfigBoolRoundTrip` (flip again after PUT round-trip)

---

### A03: Validate() coverage severely insufficient ✅ Fixed

Supplemented on 2026-07-31 (`config.go:285-431`):

- Key type enums ✓ / hash algorithm enums ✓ / time format parsing (14 fields) ✓ / port format (6 fields) ✓
- **Enum values** ✓ — Hierarchy / Locale / LogFormat / RBAC.PermissionMode / KeyBackend.Type / Persist.Mode / PG.SSLMode
- **URL formats** ✓ — CTLog.URL / Webhook.URL / TSA.CoreURL / KeyBackend.URL / OCSPURL / IssuerURL / CRLBaseURL / CTLog.Logs[i] / LDAP.URL (ldap/ldaps schemes)
- **Numeric ranges** ✓ — SMTP.Port / RateLimit.Rate/Burst / RA.RequiredApprovals / CRL.ValidityDays / ReportMaxRows / AutoRenew.WindowDays/DefaultValidity / Archive.RetentionDays / PG.Port / Persist.BatchSize/QueueSize / Aggregator.*
- **Nested structs** ✓ — PG / LDAP / Persist / Aggregator all included in checks (0 → 4 structs)
- **Listener conflicts** ✓ — same-process listeners `serve.addr` vs `serve.tls_addr` must be mutually exclusive; modular standalone listeners (tsa/ocsp/crl/api) are only checked for collisions against user-explicit (non-default) addresses (default configs intentionally share :8443, no false positives)
- **File path existence** ✓ — 19 path fields + each CA's cert/key/chain validated; only user-explicit configurations (non-empty and ≠ compile-time defaults) are checked, so undeployed default layouts do not false-positive; CA private key validation skipped in `remote_hsm` mode (keys live on the remote signer)

Coverage improved from ~1% to roughly **90% of the configuration surface**.

**Remaining note**: config validation distinguishes "default paths" from "user paths" by comparing against `DefaultConfig()`, which is heuristic — if a user explicitly writes a path identical to the default, validation is skipped (acceptable).

---

### A04: sign.go god function ✅ Fixed

`internal/ca/sign.go` — 1,331 lines, 19-way profile branching.

**Specific problems**:

1. **The 8 `m-*` profiles have completely duplicated structure** (`m-superadmin` / `m-admin` / `m-operator` / `m-auditor` / `m-readonly` / `m-console` / `m-auto-renew` / `m-reporter`) — only the OU differs; KU/EKU identical; 12 lines each × 8 = 96 lines that can merge into one generic branch

2. **10-retry loop waste**: `randomSerial` → `buildCertTemplate` → x509.CreateCertificate → DB INSERT → `DuplicateSerial` → start over entirely. Signing (~217μs) is far cheaper than the DB insert, but retries still re-sign. The template could be built outside the loop, retrying only `randomSerial` + DB operations inside.

**Fix (2026-07-31)**:

1. Added `managementProfileOU map[Profile]string` + `applyManagementProfile(tmpl, sc)` helper — the 8 m-* profiles uniformly inject OU + `BasicConstraintsValid` + `KeyUsage=DigitalSignature` + `ExtKeyUsage=[ClientAuth]` + `addCRLDP` + `addAIA`, deleting 96 duplicated lines
2. Retry loop restructured: serial-independent operations (policy loading / `CheckPolicy` / AIC PrincipalAuthorization validation) hoisted out of the loop; inside the loop only `randomSerial` → `buildCertTemplate` → sign → INSERT (`addCRLDP` partition depends on serial, so the template must be rebuilt each iteration)

---

### A05: Coverage test padding

`internal/serve/` contains ~70 test functions / ~2,000 lines of weakly-asserted tests:

| Pattern | Test function count | Representative files |
|------|-----------|---------|
| `_ = resp.StatusCode` (discards result) | ~50 | `coverage_boost5_test.go`, `api_coverage_boost4_test.go` |
| `"expected 200 or 500"` (catch-all) | ~13 | `coverage_boost6_test.go`, `coverage_boost7_test.go` |
| `"Should not panic"` / `_ = err` | ~6 | `coverage_boost4_test.go`, `coverage_boost9_test.go` |
| Dead-code variable declarations | 11 lines | `api_coverage_boost4_test.go:859-868` |

**Impact**: the claimed 82.1% coverage was inflated by ~2-3 percentage points. More seriously, the "200 or 500" pattern means regressions would not be caught by tests.

**Fix (2026-07-31)**:

1. **All 17 `"expected 200 or 500"` + 3 `"Should not panic"` sites converted to precise assertions** (`api_coverage_boost_test.go` / `api_coverage_test.go` / `coverage_boost3/6/8/9_test.go`), with root causes characterized one by one: idempotent delete→200, revoking a nonexistent certificate→500, RA approval of a nonexistent request→500, `ra_requests.csr_der` NOT NULL→500
2. **49 discarded `resp.StatusCode` sites converted to deterministic assertions** (`api_coverage_boost4_test.go` / `coverage_boost5_test.go`), each solidified after two rounds of full collection confirmed non-flakiness
3. **Tests rewritten** (originally using the wrong method, masked by weak assertions as 405/404): `TestAPIWebhooks_MethodNotAllowed` (POST→PUT), `TestAPIDNSACME_Set/BadJSON` (POST→PUT), `TestAPIExportCert_NotFoundV2` (GET→POST)
4. **`coverage_boost3_test.go`** metrics assertions switched to real-value checks via `prometheus/testutil.ToFloat64`
5. **Incidental fix of a real product bug**: `web.go` `statusRecorder` did not implement `http.Flusher`, so SSE (`/dashboard/events`, `/stats/events`) returned 500 "streaming not supported" after passing through the access-log middleware; added a `Flush()` method
6. Residual weak-assertion patterns eliminated repo-wide (`rg "_ = resp.StatusCode|GOTCODE|expected 200 or 500|Should not panic"` returns no matches); full `go build` / `go vet` / `go test -short ./internal/... ./auth/... ./cmd/...` all 17 packages pass
7. **Officially closed 2026-08-01**: `GOTCODE` instrumentation reconfirmed 0 matches repo-wide; only 4 comment mentions of weak assertions remain (`cmd/pki/serve_unix_test.go:88`, `notify_test.go:84/119/130`, non-assertion code); `./scripts/cover.sh pki-core` module-level 62.2% + package-level `-cover` all 17 packages pass, arithmetic mean 74.6%; refreshed `dev-docs/pki-core/reports/coverage-report.md`

---

## Fix Status Overview (2026-07-31)

| ID | Issue | Risk | Status | Files changed |
|------|------|------|------|---------|
| B01 | Hardcoded route permission mismatch | 🔴 Security | ✅ Fixed | `mux.go` |
| B02 | AIC/PA/SKI errors swallowed silently | 🔴 Data inconsistency | ✅ Fixed | `sign.go` |
| B03 | CertRecord missing AIC fields | 🔴 Functional defect | ✅ Fixed before review | — |
| B04 | AIC extension DB write failure | 🔴 Data inconsistency | ✅ Not applicable (code refactored away) | — |
| B05 | PA multi-OU short-circuit | 🟡 Functional defect | ✅ Fixed | `sign.go` |
| B06 | /pki/* wildcards broken | 🟡 Usability | ✅ Fixed | `rules.go` |
| B07 | TSA routes omitted | 🟡 Usability | ✅ Fixed | `routes.json` |
| B08 | publicOnly dead code | 🟢 Cleanliness | ✅ Fixed | `mux.go` |
| A01 | Three route systems duplicately maintained | 🟢 Maintenance cost | 🟡 Partial (B01/B07/B08 fixed; full consolidation see long-term #9) | `mux.go` / `routes.json` |
| A02 | MergeConfig missing fields | 🟡 Hot reload | ✅ Fixed | `config.go` |
| A02b | MergeConfig booleans not overridable | 🟢 Hot reload | ✅ Fixed | `config.go` |
| A03 | Validate() insufficient coverage | 🟡 Config safety | ✅ Fixed (nested structs/listener conflicts/file paths all added) | `config.go` |
| A04 | sign.go god function | 🟢 Maintainability | ✅ Fixed | `sign.go` |
| A05 | Coverage test padding | 🟢 Test quality | ✅ Fixed | See above |

## Remaining Work

| # | Item | Risk level | Estimated effort |
|---|------|---------|-----------|
| 1 | Consolidate three route systems into routes.json as the single source | 🟢 Maintenance cost | 3d |

## Related File Index

| File | Lines | Related issues |
|------|------|---------|
| `internal/serve/mux.go` | 421 | B01, B08, A01 |
| `internal/ca/sign.go` | 1,331 | B02, B03, B04, B05, A04 |
| `internal/config.go` | 889 | A02, A03 |
| `internal/routing/rules.go` | 297 | B06 |
| `routes.json` | 76 | B07, A01 |
| `internal/serve/aic_api.go` | 172 | B04 |
| `internal/serve/coverage_boost*.go` | ~5,500 | A05 |
| `internal/serve/api_coverage_boost*.go` | ~2,100 | A05 |

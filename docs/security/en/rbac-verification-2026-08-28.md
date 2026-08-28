# RBAC Authorization Verification Report

> Date: 2026-08-28
> Commits covered: `cc46b20` (superadmin cert-only) / `117e35b` (management hard-exclusion, route fail-closed, strict default) / `f7355b2` (cert-scope wiring)
> Environment: local `--deploy` at `https://127.0.0.1:18443` (HTTP `http://127.0.0.1:18080`), locally built `cmd/pki` binary
> Reproduce: `scripts/verify-rbac-api.sh --deploy` (first time) → `scripts/verify-rbac-api.sh`

## 1. Result

| Mode | Assertions | Pass | Fail | Result |
|------|-----------|------|------|--------|
| simple | 378 | 378 | 0 | ✅ all green |
| enterprise (forced CA scope) | 378 | 378 | 0 | ✅ all green |

**378 = 9 roles × 42 protected endpoints** (generated from the route table).
In enterprise mode 217 assertions expect "deny" (including scope-less
fail-closed) and 161 expect "allow".

## 2. Matrix data (enterprise, `/tmp/pki-rbac/matrix.tsv`)

| Role | Assertions | Core capability |
|------|-----------|-----------------|
| superadmin | 42 | full read/write |
| admin | 42 | no ca:create/delete, user manage, config:write |
| operator | 42 | certs/CRL/logs |
| revoker | 42 | revoke only |
| auditor | 42 | read-only logs/reports |
| readonly | 42 | minimal read |
| auto-renew | 42 | renew only |
| reporter | 42 | reports |
| console | 42 | console |

(Per-role allow/deny split comes from the regenerated `matrix.tsv` each run.)

## 3. Key security assertions (P0 probes + behavior sanity)

| Probe | Wanted | Got | Result |
|-------|--------|-----|--------|
| operator cert mines `m-superadmin` | 403 | 403 | ✅ management hard-exclusion |
| superadmin cert mines `m-revoker` (no account) | 200 | 200 | ✅ cert is the authority |
| operator cert + **superadmin password** mines management | 403 | 403 | ✅ password cannot elevate |
| operator cert + **superadmin password** `PUT /api/v1/admin/config` | 403 | 403 | ✅ password cannot reach superadmin endpoint |
| superadmin `POST /api/v1/certs` (regular mint) | 2xx | 200 | ✅ |
| operator `POST /api/v1/certs` (regular mint) | 2xx | 200 | ✅ |
| auditor `POST /api/v1/certs` | 403 | 403 | ✅ |
| admin `PUT /api/v1/admin/config` | 403 | 403 | ✅ superadmin-only |
| cert-less Basic request | deny | TLS-layer deny | ✅ RequireAndVerifyClientCert |
| route drift (routes.json vs active table) | none | none | ✅ asserted per deploy |

## 4. Issues covered by this report

| Severity | Issue | Status | Fix |
|----------|-------|--------|-----|
| P0 | operator cert could mint `m-superadmin` (OU=SuperAdmin escalation) | fixed | `117e35b`: role-based hard exclusion |
| P0 | `resolveBasicAuth`/`resolveAPIToken` returned the real DB role — **superadmin via username+password without a cert** | fixed | `cc46b20`: non-cert auth is always `operator`, no scope injection |
| P1 | routes_file load failure fell back to lax embedded table | fixed | `117e35b`: fail-closed (panic/keep previous) |
| P1 | embedded default table too permissive | fixed | `117e35b`: strict default synced |
| P2 | `m-revoker` default profile too broad keys / cert-vs-key path confusion | fixed | `f7355b2`: `ProfileMRevoker`, 0600 private keys in deploy |

## 5. Reproduction

```bash
cd core
go build -o /tmp/varwof ./cmd/pki
bash scripts/verify-rbac-api.sh --deploy   # init CAs, 9 role certs, superadmin account alice, 0600 keys, start serve
bash scripts/verify-rbac-api.sh            # simple-mode matrix + P0 + drift
bash scripts/verify-rbac-api.sh --set-mode enterprise
bash scripts/verify-rbac-api.sh --restart
bash scripts/verify-rbac-api.sh            # enterprise-mode matrix + P0 + drift
```

Artifacts:
- `/tmp/pki-rbac/matrix.tsv`: the 378 (role,method,path,permission,want) plan
- `/tmp/pki-rbac/verify.log`: full run log

This report is a **snapshot**: after any policy/matrix change, regenerate and update it.

## 6. Scope

- Covered: HTTP API endpoint authorization, management sub-CA mint gate, cert
  scope resolution, route-table drift, public-path minimization.
- Not covered (separate audits): ACME/SCEP/OCSP/TSA internal authorization,
  multi-tenant namespaces, Web UI sessions.
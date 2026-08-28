# Threat Model & Risk Register

> Version: 2026-08-28 (aligned with commits `f7355b2` / `117e35b` / `cc46b20` / `d81c053`)
> Companion docs: `rbac-security-model.md` (controls), `rbac-verification-2026-08-28.md`
> (evidence), `deployment-hardening.md` (deployment controls), `private-key-hygiene.md`
> (key controls)

Registers asset trust boundaries, the attack surface, and **fixed/accepted known
risks** for auditors. Track items by `R-<id>`; append with the next number.

## 1. Assets

| Asset | Criticality | Location |
|-------|-------------|----------|
| Root / issuing CA private keys | highest | offline vault / `keys/*/private/` (0600) or `key_backend` (HSM) |
| Management (`m-*`) private keys + certs (= superadmin authority) | high | `management/users/private/` (0600) |
| Serve TLS private key | high | `keys/server.key` |
| Database (certs, audit chain, key digests) | high | `pki.db` / PostgreSQL |
| Route table `routes.json` / role policy `authz.json` | high (authorization decisions) | config dir + `policy_signing` signature |
| Authorization/audit chain | med-high | DB `audit_log` (Merkle chain) |
| Sessions / tokens / account hashes | med | DB |

## 2. Trust boundaries and assumptions

1. **Authorization trust root = CA private signing key**: any entity holding a
   valid management certificate is a trusted principal; role/permission vector
   comes from cert OU/PA/scope (cert-first). Account credentials can **never**
   reach superadmin.
2. TLS enforces `RequireAndVerifyClientCert` (with the configured CA trust
   pool): no certificate → no TLS session.
3. Server and the trusted CA pool are operator-controlled; offline root vaulting
   is the highest precondition.
4. Policy files (routes/authz) are PKCS#7-signed (`policy_signing.require=true`);
   default table is strict.
5. **Config correctness is a deployment responsibility**: `init-config` output is
   placeholder (its default `auth_password` is `changeme` — must be overridden
   before going live). All deployment controls in `deployment-hardening.md`.

## 3. Attack surface

| Surface | Exposure | Control |
|---------|----------|---------|
| TLS API (mTLS) | cert-first authorization | chain validation, PA permissions, scope resolution |
| HTTP API (admin) | Basic/token (always operator) | internal-only, checklist B |
| ACME / OCSP / TSA endpoints | public paths | protocol auth + deployment allow-list |
| CLI and config/policy files | local actor | `policy_signing`, fail-closed load |
| Deploy script chain | key/cert material on disk | 0600 checks, `helpers.py` cert↔key pairing |
| Backup media | keys + audit chain | encrypted backups, `cold-backup` |
| Direct DB access | record tampering | audit Merkle chain + `pki audit verify` |

## 4. Risk register

| ID | Severity | Risk | Mitigation | Status |
|----|----------|------|-----------|--------|
| R-001 | P0 | operator cert could mint `m-superadmin` (OU=SuperAdmin escalation) into the management sub-CA | management hard-exclusion: `m-*` superadmin-only + mTLS in hand (`401/403` gate) | ✅ fixed `117e35b` |
| R-002 | P0 | `resolveBasicAuth`/`resolveAPIToken` returned the DB role — superadmin via username+password without a cert | non-cert auth always `operator`, no scope injection; mTLS-presence check | ✅ fixed `cc46b20` |
| R-003 | P1 | `routes_file` load failure fell back to the lax embedded table | fail-closed: startup panic / keep previous table on reload | ✅ fixed `117e35b` |
| R-004 | P1 | embedded default route table too permissive | strict least-privilege default + deploy-time drift assertion | ✅ fixed `117e35b` |
| R-005 | P2 | `m-revoker` default profile too broad; certs/ vs private/ confusion lets a public cert be used as a key | `ProfileMRevoker`; 0600 enforcement + docs; cert↔key pairing | ✅ fixed `f7355b2` / `d81c053` |
| R-006 | accepted | account/password delegation only ever has operator capability (can't reach superadmin) | by design; audit rows from such logins are attribution only | accepted (security boundary) |
| R-007 | accepted | exposure of public protocol endpoints (ACME/OCSP/TSA) | deployment allow-list (checklist B); minimal info in protocols | accepted (deployment duty) |
| R-008 | accepted | HTTP admin listener if exposed to the network | checklist B forces internal-only / not exposed | accepted (deployment duty) |
| R-009 | open | sample config weak default password (`auth_password: "changeme"`) | checklists A/F: override before start; documented prominently | deployment duty |

## 5. Threat → control mapping (STRIDE)

| Threat | Control |
|--------|---------|
| S spoofing (fake principal) | strong mTLS + CA chain; accounts always operator; signed policy files |
| T tampering (records/tables) | audit Merkle chain + periodic `AuditVerify` / `pki audit verify`; `policy_signing` |
| R repudiation | audit log (user/IP/path) + chain integrity + `pki report` evidence |
| I information disclosure | private keys 0600; per-day salt masking of audit PII; cert≠key |
| D denial of service | rate limiting, body cap, engine backpressure (503), `readyz` |
| E elevation of privilege | cert-first authorization, management sub-CA gate, fail-closed routing |

## 6. Verification loop

- Automated: `scripts/verify-rbac-api.sh` (378×2 matrix + P0 probes), results
  archived in `rbac-verification-2026-08-28.md`.
- After any policy-table/auth-chain change: rerun verification → update the
  report → refresh the R-IDs above.

## 7. Change discipline

- New risk: append `R-010…` with severity, mitigation, verification method.
- Escalation/de-escalation: update this table and the matching
  `deployment-hardening.md` checklist item.
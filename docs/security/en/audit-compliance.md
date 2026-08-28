# Audit Logging & Compliance

> Version: 2026-08-28
> Companions: `threat-model.md` (R-IDs), `rbac-verification-2026-08-28.md` (evidence)

Documents the authorization/operation audit model, query and integrity
verification, privacy masking, and evidence generation for
SOC 2 / PCI DSS / NIST SP 800-53 / ISO 27001.

## 1. Audit model

Sensitive and general API operations write to the audit chain
(implemented in `engine/db`):

```
LogAudit(username, remote_ip, method, path, detail)   // username = authenticated principal
```

Examples covered: login failures (`login_failed_user_not_found` /
`login_failed_bad_password`), cert upload/issue, revocation reasons,
user/token/RBAC changes, OCSP queries, recovery operations, audit deletions.

## 2. Query entry points

| Way | Description |
|-----|-------------|
| CLI: `pki audit --limit 50 --offset 0` | Tabular output (ID, timestamp, user, method, path, detail) |
| CLI: `pki audit verify` | Recompute + verify Merkle chain integrity (breaks flagged with entry ID) |
| REST: `GET /api/v1/audit?limit=&offset=` | Paginated JSON (superadmin / audit permission) |

## 3. Integrity (AUTH-016)

- Audit entries are **Merkle hash-chained**; any deletion/tampering on the chain
  is detectable.
- `audit_verify.enabled=true` (default) verifies periodically; `interval`
  defaults to 24h; a break logs a warning with the first anomalous entry ID.
- Out-of-band DB tampering: verify audit blocks in backup media separately;
  always run `pki audit verify` after a restore.

## 4. Privacy masking (data minimization)

- `audit_salt.enabled=true` (default): a fresh random salt per calendar day
  HMAC-masks PII fields (username, remote IP) before they are stored and chained.
- `audit_salt.retention_days` (default 365): within the window the day's
  identities can be recovered; after salt purge, masked identities are
  **permanently irreversible** while the chain stays verifiable.
- `enabled=false` is recommended only for isolated/forensic environments.

## 5. Compliance evidence

- **Reports**: `pki report --template soc2|pci|nist|iso --out <file>` → PDF with
  control mappings (e.g. PCI DSS v4.0: 2.2 config baseline, 3.6 key management,
  4.1 key change, 10.2 audit logging, 10.6 log review; SOC 2: CC6 boundary,
  CC7 monitoring; NIST CP/AU families; ISO 27001 A.8/A.12 controls).
- **CP/CPS**: `pki cpcps` generates RFC 3647 statements (CA practice, cert
  lifecycle, audit declarations).
- **Authorization matrix evidence**: output of `scripts/verify-rbac-api.sh`
  (`/tmp/pki-rbac/matrix.tsv` + `verify.log`) archived as
  `rbac-verification-2026-08-28.md` and showable to auditors (simple/enterprise
  × 378, P0 probes).

## 6. Framework mapping quick ref

| Control group | Mechanism |
|---------------|-----------|
| PCI DSS 10.2/10.6, SOC2 CC7 | full `LogAudit` recording + `pki audit` review |
| PCI DSS 10.5/10.7, NIST AU-9 | Merkle chain integrity + periodic `AuditVerify` |
| PCI DSS 3.x, SOC2 CC2.1 | `audit_salt` PII masking + retention policy |
| PCI DSS 6.4, ISO A.8.25 | `policy_signing` signed policy-file changes + review |
| NIST AC/IA, ISO A.8.2 | certificate-first RBAC (`rbac-security-model.md`) |
| NIST CP-9, ISO A.8.13 | encrypted backups of audit chain + DB and restore drills |

## 7. Operations advice

- Audit is append-only: use least-privilege read-only DB access for direct
  inspection; alert on chain breaks.
- Include `pki audit verify` in every backup-restore drill (mandatory post-restore).
- Weekly manual review of high-risk actions: `m-*` mints, `ca rotate`,
  user/token changes, key recovery (`keys/recover`).
- Retention: the salt window defines the PII-recoverable period; audit rows are
  kept per organizational policy (default: retained with the DB).
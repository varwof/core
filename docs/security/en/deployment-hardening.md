# Deployment Hardening

Pre-flight and maintenance checklist for production varwof-core deployments.
Pair with [rbac-security-model.md](rbac-security-model.md) and
[private-key-hygiene.md](private-key-hygiene.md).

## A. Authorization & RBAC

- [ ] `rbac.enabled = true`
- [ ] `rbac.mode = enterprise` for multi-CA (scope-less users denied, fail-closed)
- [ ] `routes_file` configured → active table is authoritative (fail-closed; no lax embedded fallback)
- [ ] `policy_signing.enabled = true` (+ `require: true`) for long-lived routes/authz
- [ ] No route drift: deploy-time check compares active table with repo `routes.json`
- [ ] Superadmin authority only via mTLS certificate — password account is operator-only
- [ ] Non-cert resolvers never grant `superadmin` (`resolveBasicAuth`/`resolveAPIToken`)
- [ ] Management (`m-*`) mint: superadmin role + mTLS in hand (401/403 otherwise)

## B. TLS & transport

- [ ] `serve` uses TLS with `RequireAndVerifyClientCert` + `serve.ca_file` trust pool
- [ ] No plaintext listener exposed to the network (internal HTTP admin only, if at all)
- [ ] Reverse proxy re-enforces client-cert authentication and pinned allow-list for `/acme/`+/`/dns/`
- [ ] TLS ≥1.2, strong cipher suites on the edge

## C. Keys & secrets

- [ ] Private keys `0600`, service-user-owned; `management/users/private/` locked
- [ ] Root CA key offline / `key_backend`(HSM); never on the API host web path
- [ ] Backup set is encrypted; cold backups via `pki cold-backup`/`backup-root-ca.sh`
- [ ] Cert-vs-key trap audited (certs/* never used as keys)
- [ ] `key_escrow` recovery restricted to superadmin (certificate-first)

## D. Ratings & limits

- [ ] `rate_limit` enabled with sane per-IP budget
- [ ] Request body cap (default 10 MB) intact
- [ ] `k8s_enabled` left at `false` unless genuinely needed
- [ ] `device_profile`/`engine`/`record_buffer` tuned to capacity (benchmarked)

## E. Observability & audit

- [ ] `/healthz`, `/readyz`, `/metrics` scraped by monitoring
- [ ] Authorization audit enabled (`audit_salt`) and reviewed via `pki audit` / `GET /api/v1/audit`
- [ ] Compliance reports generated (`pki report`) for SOC 2/PCI DSS/NIST/ISO evidence
- [ ] Pasteboard: document the deployment-mode matrix result and P0 assertions
  (see `rbac-verification-2026-08-28.md`)

## F. Operations hygiene

- [ ] Hot-reload path tested (SIGHUP); `routes_file` unreadable → startup aborts (fail-closed)
- [ ] Backup timer (`pki-backup.service`) installed; restore drill executed once per quarter
- [ ] CA key rotation procedure rehearsed (`/api/v1/ca/{name}/rotate`)
- [ ] Every recovered key open an audit record
- [ ] Version/Patch cadence: `pki version` pinned per environment
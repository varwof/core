# RBAC Security Model (Cert-First)

> Version: 2026-08-28 (aligned with commits `cc46b20` / `117e35b` / `f7355b2`)
> Applies to: any deployment with `rbac.enabled=true`

Authoritative security model for the varwof-core permission system. It answers
the three audit-critical questions: **whose authorization is trustworthy,
what credentials reach what role, and where the boundary is.**

## 1. Trusted authority: certificates only, accounts never

Authorization (role + permission vector) comes **only** from claims embedded in
the mTLS management certificate:

- Role ← certificate OrganizationalUnit (OU) → maps to `superadmin / admin / operator / auditor / readonly / revoker / auto-renew / reporter`, etc.
- Permission vector ← certificate PrincipalAuthorization (PA) extension (certificate-only; `user.HasPerm` is decided on PA).
- CA scope ← SAN URI `urn:pki:ca:<scope>` or OID `1.3.6.1.4.1.66257.1.5.1`.

All person credentials (username/password, API token, cookie) take **no part**
in role or permission authority.

## 2. Authentication input → effective role

| Input | Effective role | Permissions / scope source |
|-------|----------------|----------------------------|
| mTLS management cert | OU → role (up to superadmin) | cert PA, cert SAN/OID |
| `Authorization: Basic` (user+pass) | **always `operator`** | operator defaults; scope only from bound operator cert |
| `X-Auth-Token` / `Bearer` / cookie | **always `operator`** | same |
| AIC certificate (delegated agent) | `permissions = PA ∩ AIC capabilities` | restricted intersection |
| Trusted-gateway delegation headers (B1/B2) | per certificate after `trusted_gateway_ous` check | certificate claims |

Implementation (`cmd/pki/serve.go`):

```
resolveAPIToken / resolveBasicAuth:
    Role        → fixed "operator"
    Permissions → getRolePerms("operator")
    CAScopes    → nil (not injected; scope derived from the bound operator cert)
```

## 3. Superadmin is certificate-only (gate on the highest authority)

Management (`m-*`) certificates are issued **only** by the superadmin role with
an mTLS client certificate in hand:

```
POST /api/v1/certs  { profile: "m-*" }
  ├─ no mTLS client cert (TLS.PeerCertificates empty)
  │     → 401 api.auth_required
  ├─ cert role != superadmin
  │     → 403 api.management_mint_denied  (operator & others hard-excluded)
  └─ role = superadmin → mint (optionally with ca_scope)
```

- **operator and every other role are hard-excluded from the management sub-CA**.
- **The operator's management-mint capability is marked deprecated (scheduled
  for removal)**; this gate is the fail-closed front line.
- Scope is written CA-side (not self-declared by the requester).

## 4. Limitations of username/password (must-read for auditors)

These are **deliberate security boundaries** — hard limits of every account credential:

1. **The DB role column does not authorize anything.** Even if an account's
   `rbac_users.role` is configured as `superadmin`, Basic/Token authentication
   still yields effective role `operator`.
2. **An account password cannot elevate anything.** Measured: operator cert +
   the superadmin account password (`alice:<RBAC_ADMIN_PASS>`) requesting a
   management mint → `403`; requesting a superadmin-only endpoint
   (`PUT /api/v1/admin/config`) → `403`.
3. **Scope is not injected by the account.** Account-declared CA scopes are not
   used as an authorization basis; only the bound operator certificate derives scope.
4. Passwords are valid for: **identity attribution, audit trail, operator-cert
   binding matching** — nothing more.

Operational consequences:

- To grant a person anything above operator, **issue the matching management
  certificate**; a password cannot do it.
- If an account table shows a "superadmin" role name, that account does **not**
  have superadmin capability.
- Certificate private keys (`management/users/private/`) are the true secret;
  the deploy script enforces `chmod 600`. `management/users/certs/*.pem` are
  public certificates and must **never** be used as `--key` material.

## 5. CA scope

- Only certificate-sourced scope is trusted (SAN URI / OID 1.3.6.1.4.1.66257.1.5.1),
  written CA-side via the `scope` parameter.
- Enterprise mode + no scope → deny (fail-closed); simple mode + no scope → allow.
- Non-certificate resolvers do not inject `cas:scope:*` permissions
  (`resolveAPIToken` no longer does).

## 6. Route-level authorization (fail-closed)

- With `routes.json` configured but unreadable: **panic at startup** (no prior
  table) or **keep the previous table** (on reload) — never fall back to the lax
  embedded table.
- The embedded default (`internal/serve/routes_default.json`) is a strict
  least-privilege table kept in sync with repo `routes.json`; the deploy script
  asserts "no drift".
- Public (no-auth) path minimum: `/healthz /readyz /metrics /tsa /ocsp /acme/ /api/v1/users/login|info|logout /api/v1/session /api/v1/version`.

## 7. Role × permission matrix (core)

| Role | ca:create/delete | cert:issue/revoke/renew | user:manage | config:write | webhook:manage | log:read/report |
|------|------------------|-------------------------|-------------|--------------|----------------|-----------------|
| superadmin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| admin | — | issue/revoke/renew | — | — | ✓ | ✓ |
| operator | — | issue/revoke/renew | — | — | — | ✓ |
| revoker | — | revoke | — | — | — | ✓ |
| auditor | — | — | — | — | — | read |
| readonly | — | — | — | — | — | — |
| auto-renew | — | renew | — | — | — | ✓ |
| reporter | — | — | — | — | — | view |

Endpoint-level matrix: see `routes.json` (drift-checked against the embedded default each deploy).

## 8. Audit guide

- Replay the matrix and P0 assertions in one command: `scripts/verify-rbac-api.sh`
  (with `--deploy` for a one-shot environment).
- Results archive: `docs/security/zh/rbac-verification-2026-08-28.md`.
- Commits covering these boundaries: `f7355b2` (cert-scope wiring),
  `117e35b` (management hard-exclusion + route fail-closed + strict default),
  `cc46b20` (superadmin certificate-only; accounts always operator).

## 9. Trust boundary

- TLS enforces `RequireAndVerifyClientCert` + configured CA trust pool (no
  certificate → no request).
- Management certs issued by this PKI, status checkable (DB records + CRL);
  `ExtractAdminScope` is enforced across the chain.
- Assumptions: root CA private key protected; `management/users/private/` is 0600;
  policy tables (routes/authz) are PKCS#7-signed with `policy_signing` where
  enabled (missing signature → load refused).
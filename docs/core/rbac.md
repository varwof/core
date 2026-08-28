# RBAC & Permission System

## Overview

The varwof PKI implements a role-based access control (RBAC) system with two modes:
- **Simple**: Role-based, CA scope optional
- **Enterprise**: Role-based + mandatory CA scope enforcement

## Authentication Chain

Every request is authenticated via one of these methods (in priority order):

```
1. mTLS client certificate
   ├── AIC certificate (has AIC extension) → Delegation auth verification
   ├── Trusted gateway delegation (B2: X-Client-Cert-DER, B1: X-Agent-User)
   ├── Standard management cert → Role from OU, permissions from PA extension
   └── Delegated-Agent cert → Requires valid X-Agent-TTL header

2. X-Auth-Token header / pki_token cookie → DB lookup → "operator" role

3. Authorization: Bearer → Same as X-Auth-Token

4. Authorization: Basic → Argon2id password verification + caching
```

**Cert-First Authorization Model**:
- mTLS certificates: Permissions come **only** from the certificate's PrincipalAuthorization (PA) extension
- Non-certificate auth (token/basic/cookie): Always assigned "operator" role
- AIC certificates: `Permissions = PA grants ∩ AIC capabilities`

## Roles

### Core Roles

| Role | Profile | Scope | Description |
|------|---------|-------|-------------|
| `superadmin` | `m-superadmin` | `["Management CA"]` | Full access including CA creation/deletion |
| `admin` | `m-admin` | — | All permissions except CA/user management |
| `operator` | — | — | Cert issue/revoke/renew, CRL, logs |
| `revoker` | `m-revoker` | `["*"]` | Certificate revocation only |
| `auditor` | `m-auditor` | — | Read-only: logs, reports, certificates |
| `readonly` | `m-readonly` | — | Minimal read-only access |
| `console` | — | — | Web console operations |
| `auto-renew` | `m-auto-renew` | — | Certificate renewal only |
| `reporter` | `m-reporter` | — | Report generation and export |
| `agent` | `agent-proxy` | — | AI agent with gateway capabilities |

### Gateway Roles (namespaced `gateway:`)

| Role | Grants |
|------|--------|
| `gateway-admin` | `gateway:*` (all gateway operations) |
| `gateway-reader` | `SELECT:*` (read-only) |
| `gateway-writer` | `SELECT:*`, `INSERT:*`, `UPDATE:*` |
| `gateway-ops` | `SELECT:*`, `INSERT:*`, `UPDATE:*`, `DELETE:*` |
| `gateway-ddl` | All DML + `DDL:*` |

## Permissions

32 permission constants in `resource:action` format:

| Resource | Actions |
|----------|---------|
| `ca` | `create`, `delete`, `list`, `info` |
| `cert` | `issue`, `revoke`, `renew`, `list`, `export`, `batch` |
| `crl` | `generate` |
| `user` | `manage`, `list`, `revoke-all` |
| `log` | `read`, `export` |
| `report` | `view`, `export`, `generate` |
| `config` | `read`, `write` |
| `ra` | `approve`, `reject` |
| `cross-cert` | `issue`, `revoke` |
| `webhook` | `manage` |
| `key` | `recover` |
| `dns` | `manage` |
| `trust` | `import`, `list`, `delete` |
| `agent` | `manage` |
| `swagger` | `view` |
| `web` | `view` |

## Permission Matrix

| Role | ca:create | ca:delete | cert:issue | cert:revoke | cert:renew | user:manage | config:write | log:read |
|------|-----------|-----------|------------|-------------|------------|-------------|--------------|----------|
| superadmin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| admin | — | — | ✓ | ✓ | ✓ | — | — | ✓ |
| operator | — | — | ✓ | ✓ | ✓ | — | — | ✓ |
| revoker | — | — | — | ✓ | — | — | — | ✓ |
| auditor | — | — | — | — | — | — | — | ✓ |
| readonly | — | — | — | — | — | — | — | — |
| auto-renew | — | — | — | — | ✓ | — | — | ✓ |
| reporter | — | — | — | — | — | — | — | ✓ |

## Authorization Modes

### Simple Mode

```json
{
  "rbac": {
    "enabled": true,
    "mode": "simple"
  }
}
```

- Role-based permission check only
- CA scope **not enforced** unless user has a bound scope
- Users with no scope are allowed everything
- Suitable for single-CA deployments

### Enterprise Mode

```json
{
  "rbac": {
    "enabled": true,
    "mode": "enterprise"
  }
}
```

- Role-based permission check + mandatory CA scope enforcement
- Users with **no scope are DENIED** (fail-closed)
- CA scope extracted from operator certificate, DB, or config
- Required for multi-CA deployments

## CA Scope

CA scopes restrict which Certificate Authorities a user can operate on.

### Scope Sources (evaluated in order)

1. **Operator Certificate (cryptographic binding)**
   - SAN URIs matching `urn:pki:ca:<scope>`
   - OID extension `1.3.6.1.4.1.66257.1.5.1`
   - Must pass full validation (valid, unrevoked, issued by this PKI)

2. **DB `ca_scopes` column**
   - Comma-separated scope list stored per user

3. **Config file `rbac.ca_scopes`**
   ```json
   {
     "rbac": {
       "ca_scopes": {
         "operator": ["Client CA", "VPN CA"],
         "admin": ["*"]
       }
     }
   }
   ```

4. **Policy `scope` field** in `authz.json`
   ```json
   {
     "roles": {
       "superadmin": { "scope": ["Management CA"] },
       "revoker": { "scope": ["*"] }
     }
   }
   ```

### Scope Resolution Logic

1. Framework operations (`ca:create`/`ca:delete`) are scope-exempt (superadmin only)
2. Read-only roles (`auditor`, `readonly`, `reporter`) are always allowed
3. Roles with `scope: ["*"]` are always allowed
4. No scope defined:
   - Simple mode → ALLOW
   - Enterprise mode → DENY
5. Scope contains `*` → ALLOW
6. Extract CA name from request (path, query, or POST body)
7. Exact string match against scope list
8. Config file fallback match
9. No match → DENY

### CA Name Extraction

| Source | Pattern |
|--------|---------|
| URL path | `/api/v1/cert/{ca}/{serial}/revoke` |
| Query parameter | `?ca=<name>` |
| POST/PUT body | `{"ca": "<name>"}` (peek up to 64KB) |

## Route-Level Authorization

Route rules are defined in `routes.json` (or embedded defaults):

```json
{
  "version": "v1",
  "public_paths": ["/healthz", "/readyz", "/metrics"],
  "rules": [
    {
      "method": "POST",
      "path": "/api/v1/certs",
      "permission": "cert:issue",
      "description": "Issue certificate",
      "ca_scope": true,
      "require_role": ["superadmin", "admin"],
      "allow_aic": false
    }
  ]
}
```

### RouteRule Fields

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method (`*` for any) |
| `path` | string | URL pattern (`/api/v1/cert/{ca}/{serial}`) |
| `permission` | string | Required permission |
| `ca_scope` | bool | Enable CA scope check |
| `require_role` | []string | Additional role whitelist |
| `allow_aic` | *bool | Allow AIC agent access (nil = true) |
| `max_validity` | string | Max cert validity for issuance |

### Path Pattern Matching

| Pattern | Specificity | Example |
|---------|-------------|---------|
| Literal | 1000+ | `/api/v1/certs` |
| Param | 600+ | `/api/v1/cert/{ca}/{serial}` |
| Single wildcard | 500+ | `/api/v1/ca/*` |
| Double wildcard | 400+ | `/api/**` |

### Public Paths (bypass all auth)

- `/healthz`, `/readyz`, `/metrics`
- `/api/v1/users/login`, `/api/v1/users/info`, `/api/v1/users/logout`
- `/api/v1/session`, `/api/v1/version`
- `/tsa`, `/ocsp`, `/acme/`

## Operator Certificate Binding

Bind a management certificate to a user account for cryptographic scope definition.

### Bind

```bash
# CLI
pki user bind-operator-cert --username operator1 --cert operator.pem

# API
curl -X POST -H "X-Auth-Token: <token>" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n..."}'
```

### Certificate Validation

The bound certificate must satisfy ALL:

1. Valid PEM, parseable X.509
2. Management cert (DigitalSignature + ClientAuth + valid OU)
3. OU maps to a real role
4. Within NotBefore/NotAfter window
5. Issued by this PKI (DB record exists)
6. Not revoked (status "V")

If validation fails, authentication fails (no silent downgrade).

### Scope Derivation

```
Bound operator cert → ExtractAdminScope(cert)
  → SAN URIs: urn:pki:ca:<scope>
  → OID extension: 1.3.6.1.4.1.66257.1.5.1
  → Overrides DB ca_scopes
```

Scope is cached for 30 seconds (max 4096 entries).

## Policy File Signing

Policy files (`authz.json`, `routes.json`) can be signed with PKCS#7 detached signatures.

### Configuration

```json
{
  "policy_signing": {
    "enabled": true,
    "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
    "require_admin_ou": true,
    "require": true,
    "sig_suffix": ".sig"
  }
}
```

### Signing

```bash
# CLI
pki policy sign --file authz.json --cert admin.pem --key admin.key --out authz.json.sig

# varwof-cli
varwof-cli config.json policy sign --file authz.json --cert admin.pem --key admin.key
```

### Verification

1. PKCS#7 detached signature verification
2. Admin OU check (`admin` or `gateway:admin`)
3. Chain verification against configured CA trust pool
4. Fail-closed: missing/invalid signature rejects loading

## HTTP Middleware Stack

```
Request
  │
  ▼
1. Body size limit (10MB)
  │
  ▼
2. Rate limiting (per-IP token bucket)
  │
  ▼
3. Public path check → bypass
  │
  ▼
4. TSA/OCSP protocol dispatch
  │
  ▼
5. Route rules engine
   ├── CORS check
   ├── authenticate()
   │   ├── mTLS certificate
   │   ├── Token/Cookie
   │   └── Basic auth (Argon2id)
   ├── require_role check
   ├── permission check (user.HasPerm)
   ├── CA scope check (enterprise mode)
   ├── AIC identity check
   └── Store AuthUser in context
  │
  ▼
6. Handler execution
```

## Delegated-Agent Sessions

| Control | Description |
|---------|-------------|
| `X-Agent-TTL` header | RFC3339 future timestamp required |
| Max TTL | `serve.agent_session_max_ttl` (default 24h) |
| Disable | Set `agent_session_max_ttl = "0"` |
| Trusted gateways | `serve.trusted_gateway_ous` (empty = reject all) |

## Namespace System

| Namespace | Prefix | Roles |
|-----------|--------|-------|
| Core | (none) | `admin`, `operator`, `auditor`, etc. |
| Gateway | `gateway:` | `gateway-admin`, `gateway-reader`, etc. |
| Web | `web:` | Reserved for web console |

Wildcard matching: `gateway:*` matches any gateway role, `*` matches globally.

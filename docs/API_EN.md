# varwof REST API Documentation

**Base URL**: `http://<host>:8443/api/v1`

Authentication: `X-Auth-Token: <token>` or `Authorization: Bearer <token>`

---

## Authentication

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/users/login` | Log in to obtain a token | ❌ Public |
| GET | `/users/info` | Current user information | ✅ Token |
| GET | `/session` | Session identity probe (user + bound certificate identity, used for web user detection) | ✅ mTLS cert / Token / Cookie |
| POST | `/users/logout` | Log out and revoke the token | ✅ Token |

### Login

```bash
curl -s -X POST http://localhost:8443/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"Admin","password":"Secret123"}'
# → {"token":"...","user_id":1,"username":"Admin","role":"admin"}
```

### Current User

```bash
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/info
# → {"user_id":1,"username":"Admin","role":"admin"}
```

### Session Identity Probe

Supports the full authentication chain (mTLS certificate / gateway certificate forwarding / token / cookie / Basic) and returns the current identity along with the bound client certificate information (if any). The web console calls this endpoint at startup to detect the user and certificate identity.

```bash
# Direct mTLS connection (client certificate at the TLS layer)
curl -s --cert client.pem --key client.key --cacert ca.pem \
  https://<host>:4433/api/v1/session
# → {"authenticated":true,"username":"varwof:alice:","role":"admin(agent)",
#    "cert_identity":{"serial":"...","issuer":"...","cn":"...","spki_hash":"...",
#    "principal_uid":"varwof:alice:","agent_id":"agent-1","not_after":"..."}}

# Token session (no certificate)
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/session
# → {"authenticated":true,"username":"Admin","role":"admin"}
```

`cert_identity` is returned only when the session is bound to a client certificate (direct mTLS connection or via gateway B2 certificate forwarding); token/Basic logins carry no certificate, so only `username`/`role` are returned.

---

## User Management

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/users` | List users | ✅ |
| POST | `/users` | Create a user | ✅ |
| DELETE | `/users/{id}` | Delete a user | ✅ |
| POST | `/users/{id}/operator-cert` | Bind an operator certificate (proxies the user's CA scope) | ✅ admin |
| DELETE | `/users/{id}/operator-cert` | Unbind the operator certificate | ✅ admin |

```bash
# Create a user
curl -s -X POST http://localhost:8443/api/v1/users \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"Pass1234","role":"operator"}'

# Delete a user
curl -s -X DELETE -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/1

# Bind an operator certificate (must be issued by this PKI, unexpired and unrevoked,
# with the OU mapped to a real role)
curl -s -X POST -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n"}'
# → {"status":"bound","scope":["VPC Client CA"]}

# Unbind
curl -s -X DELETE -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/users/1/operator-cert
```

> **Operator certificate proxy**: once a CA-scope-restricted `m-*` management certificate is bound to a user who logs in with username/password or token, that user's effective CA scope at login time becomes the certificate's scope (written to both SAN URI and OID)—a cryptographic binding; when the certificate expires or is revoked, access to the corresponding CAs is lost immediately. Binding is validated fail-closed: expired, revoked, or certificates not issued by this PKI are rejected immediately.

---

## Token Management

> Permissions (AUTH-005): exact gating via the route table—`GET` requires `user:list`, `POST`/`DELETE` require `user:manage`.
> Under the cert-first model, only management certificates holding the corresponding grants can access these endpoints (e.g., `m-superadmin`); password/token logins (operator) cannot.

| Method | Path | Description | Auth | Permission |
|--------|------|-------------|------|------------|
| GET | `/tokens?user_id=N` | List tokens | ✅ | `user:list` |
| POST | `/tokens` | Create a token | ✅ | `user:manage` |
| DELETE | `/tokens/{id}` | Revoke a token | ✅ | `user:manage` |

---

## Certificate Operations

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/certs` | Issue a certificate | ✅ |
| POST | `/certs/upload` | Upload an external certificate (e.g., NAS device certificate) into inventory | ✅ |
| GET | `/certs` | List certificates | ✅ |
| GET | `/certs/report.pdf` | PDF report | ✅ |
| POST | `/certs/batch` | Batch issuance | ✅ |
| GET | `/cert/{ca}/{serial}` | Certificate details | ✅ |
| POST | `/cert/{ca}/{serial}/revoke` | Revoke a certificate | ✅ |
| POST | `/cert/{ca}/{serial}/renew` | Renew a certificate | ✅ |
| POST | `/cert/{ca}/{serial}/export` | Export the certificate PEM | ✅ |
| POST | `/certs/revoke-by-principal` | Bulk revoke by PrincipalUid | ✅ |
| POST | `/certs/revoke-batch` | Batch revoke (revocation storms; engine memory is the source of truth) | ✅ |

### Issue a Certificate

```bash
curl -s -X POST http://localhost:8443/api/v1/certs \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ca": "tls",
    "cn": "server.example.com",
    "san": "DNS:san1.example.com",
    "profile": "tls-server",
    "key_type": "ecdsa-p256",
    "validity": 365,
    "subject": "/C=CN/ST=BJ/L=Beijing/O=Acme/OU=IT/CN=server.example.com"
  }'

# Management certificates: use an m-* profile to set the OU automatically (e.g., m-admin, m-operator, m-auto-renew)
# curl -s -X POST ... -d '{"ca":"admin-ca","cn":"Alice","profile":"m-admin","validity":180}'
# → {"serial_number":"...","cert_pem":"...","key_pem":"..."}

# Administrator certificates with a scope (m-admin/m-superadmin): the scope is written into
# SAN URI + OID extensions, restricting the certificate to managing only the specified sub-CAs.
# Only superadmin may specify arbitrary scopes (privilege escalation prevention).
# curl -s -X POST ... -d '{"ca":"admin-ca","cn":"Bob","profile":"m-admin","validity":180,"ca_scope":"Client CA"}'
```

#### identity-user auto-issuance (identity source → base identity certificate)

The `identity-user` profile resolves a person's attributes from the configured
identity source (bridge-ldap `/api/v1/lookup` or bridge-oauth userinfo) and fills
CN/OU/email into the certificate. Requires `config identity.source_url` (Phase 2).

```bash
curl -s -X POST http://localhost:8443/api/v1/certs \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ca": "issuing",
    "profile": "identity-user",
    "identity_username": "001",
    "identity_source": "ad-main",
    "key_type": "ecdsa-p256"
  }'
# → {"serial_number":"...","common_name":"张三","cert_pem":"...","key_pem":"..."}
# CN=张三 (full_name), OU=gateway:ops (ou_from_groups), email SAN=zhangsan@hospital.local
```

- `identity_username`: identity-source username (required; cn may be omitted)
- `identity_source`: optional source_tag override (default `config identity.source`)
- `ou_from_groups` maps groups to OU (RBAC roles); `default_ou` fallback; else dept
- Disabled accounts are rejected by default (403); `disabled_ok: true` allows
- No identity source configured → 400; user not found → 502; bridge unreachable → 502

### Upload External Certificates (register NAS and other device certificates)

Register externally issued/self-signed device certificates into the PKI inventory for lifecycle tracking (private keys are not held).

```bash
curl -s -X POST http://localhost:8443/api/v1/certs/upload \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "ca_name": "NAS Devices",
    "device_type": "nas",
    "device_name": "nas1"
  }'

# → 201 {"serial_number":"...","common_name":"nas1.varwof.com","ca_name":"NAS Devices",
#        "not_before":"...","not_after":"...","fingerprint":"..."}
# Uploading the same Serial again returns 409; invalid certificates return 400.
# profile_used is recorded as uploaded-<device_type> (e.g., uploaded-nas) and can be
# searched in the certificate list/details.
```

### Revoke a Certificate

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/revoke \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
# → {"status":"revoked","ca":"root","serial":"..."}
```

### Batch Revocation (revocation storms)

Revoke a large number of certificates in a single request. When the in-memory engine is enabled, the entire batch is marked revoked within a single lock (memory is the source of truth, visible immediately to readers) and persisted to the database asynchronously in the background; certificates not resident in memory automatically fall back to a DB transaction.

```bash
curl -s -X POST http://localhost:8443/api/v1/certs/revoke-batch \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {"ca":"root","serial":"AB12","reason":"keyCompromise"},
      {"ca":"root","serial":"CD34"},
      {"ca":"issuing","serial":"EF56","reason":"cACompromise"}
    ]
  }'
# → {"status":"ok","revoked_count":3}
```

`reason` is optional and takes the same values as single-certificate revocation (`keyCompromise`/`cACompromise`/`affiliationChanged`/...).

### Renew a Certificate

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/renew \
  -H "X-Auth-Token: <token>"
# → {"serial_number":"...","cert_pem":"...","key_pem":"..."}
```

### Export Certificate PEM

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/export \
  -H "X-Auth-Token: <token>" \
  -o cert.pem
```

### Certificate List Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ca` | string | Filter by CA name |
| `status` | string | V(valid) / R(revoked) / E(expired) |
| `cn` | string | Search by common name |
| `format` | string | json / csv |

---

## CA Management

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/cas` | List CAs | ✅ |
| GET | `/cas/tree` | CA tree structure | ✅ |
| GET | `/ca/{name}` | CA details | ✅ |
| GET | `/ca/{name}/rotation` | CA master key rotation status (active/legacy dual-signing transition info) | ✅ |
| POST | `/ca/{name}/rotate` | CA master key rotation (atomic hot swap + dual-signing transition period; requires superadmin/admin) | ✅ |

### CA Master Key Rotation (C7)

The CA master key should be rotated before the CA expires. Rotation does not interrupt online issuance: the new key takes effect atomically, and the old key is retained during the transition period for verifying previously issued certificates/CRLs.

```bash
# Check rotation status
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotation

# Perform rotation (provide the new CA certificate + private key PEM, inline or file path)
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

Response: `{"status":"rotated","ca":"...","old_serial":"...","new_serial":"...","active":{...}}`.
The server checks every CA's expiry every 12 hours and logs the warning `WARN serve: CA master key approaching expiry` when expiry is within 7 days.

---

## CRL

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/crl/{ca}` | Download the CRL | ✅ |
| POST | `/crl/{ca}/generate` | Generate the CRL | ✅ |

---

## Cross Certificates

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/cross-certs` | List | ✅ |
| POST | `/cross-cert/issue` | Issue | ✅ |
| POST | `/cross-cert/revoke` | Revoke | ✅ |

---

## Statistics & Dashboard

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/dashboard` | Full dashboard statistics | ✅ |
| GET | `/dashboard/events` | SSE real-time push | ✅ |
| GET | `/stats` | Summary statistics | ✅ |

### Dashboard Response

```json
{
  "summary": {
    "total_certs": 100,
    "total_cas": 5,
    "valid": 85,
    "revoked": 10,
    "expired": 5,
    "expiring_30d": 3,
    "revoked_ratio": 0.1
  },
  "per_ca": [
    {"name": "root", "certs": 50, "revoked": 5, "expiring_30d": 1}
  ],
  "expiry": {
    "within_30d": 3, "within_60d": 5, "within_90d": 8,
    "within_180d": 15, "within_365d": 30, "over_365d": 39
  },
  "trends": {
    "issued_today": 2, "issued_this_week": 10,
    "issued_this_month": 25, "revoked_today": 0
  }
}
```

---

## Audit / RA / Key Recovery

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/audit?limit=50&offset=0` | Audit logs (`username`/`remote_addr` are HMAC-masked with a daily salt by default; see the `audit_salt` configuration) | ✅ |
| GET | `/ra?status=pending` | List RA requests | ✅ |
| POST | `/ra` | Submit an RA request | ✅ |
| POST | `/ra/{id}/approve` | Approve | ✅ |
| POST | `/ra/{id}/reject` | Reject | ✅ |
| POST | `/keys/recover` | Recover escrowed keys | ✅ |

---

## Webhook

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/webhooks` | List subscriptions | ✅ |
| POST | `/webhooks` | Create a subscription | ✅ |

---

## DNS Service

### Overview

Built-in authoritative DNS server for ACME DNS-01 challenge validation and certificate distribution. The management API is accessed via the main port `:8443`; DNS queries support DoH and DoT.

### Startup

```bash
varwof --config config.json serve dns
```

Configuration options:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dns.enable` | false | Enable the DNS server |
| `dns.addr` | `:53` | DNS UDP listen address |
| `dns.zone` | - | Authoritative zone |
| `dns.dot_addr` | - | DoT listen address (e.g., `:853`; requires a certificate) |
| `dns.server_cert` | - | DoT server certificate PEM |
| `dns.server_key` | - | DoT server key PEM |
| `dns.ca_cert` | - | CA for client certificate verification |
| `dns.crl_path` | - | CRL file path |
| `dns.crl_refresh` | `60s` | CRL refresh interval |
| `dns.ocsp_url` | - | OCSP responder address |

### DNS Management API (`:8443`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/v1/dns/records` | List DNS records | Token |
| GET | `/api/v1/dns/healthz` | Health check | Public |
| PUT | `/api/v1/dns/acme-challenge/{domain}` | Set ACME DNS-01 | Token |
| DELETE | `/api/v1/dns/acme-challenge/{domain}` | Clear ACME DNS-01 | Token |
| PUT | `/api/v1/dns/cert/{domain}` | Set CERT record | Token |
| DELETE | `/api/v1/dns/cert/{domain}` | Clear CERT record | Token |

### ACME DNS-01

```bash
# Set
curl -X PUT http://localhost:8443/api/v1/dns/acme-challenge/example.com \
  -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  -d '{"key_auth":"..."}'

# Verify
dig @localhost -p 53 _acme-challenge.example.com TXT
```

### DNS over HTTPS (DoH)

Encrypted queries via the main port `:8443`:

```bash
curl "http://localhost:8443/api/v1/dns-query?name=example.com&type=TXT"
```

Supported types: A, AAAA, TXT, CNAME, MX, NS, SOA, PTR, SRV, CERT, TLSA

### DNS over TLS (DoT)

```bash
# Configuration
{ "dns": { "dot_addr": ":853", "server_cert": "...", "server_key": "..." } }
# Client: kdig @localhost -p 853 example.com TXT +tls
```

### Security Verification

The management API supports triple verification via mTLS + CRL + OCSP:
- Client certificate (`dns.ca_cert`): verified during the TLS handshake
- CRL check (`dns.crl_path`): revocation list refreshed periodically
- OCSP query (`dns.ocsp_url`): real-time online status

---


## Ports

| Service | Port | Description |
|---------|------|-------------|
| `varwof serve` | `:8443` | Web UI + REST API + TSA + OCSP + CRL + DoH |
| `varwof serve dns` | `:53` | DNS UDP (ACME DNS-01) |
| `varwof serve dns` (DoT) | `:853` | DNS over TLS (requires `dot_addr` + certificates) |

## Protocol Endpoints (non-JSON APIs)

| Path | Method | Description |
|------|--------|-------------|
| `/tsa` | POST | RFC 3161 timestamp (application/timestamp-query) |
| `/ocsp` | POST/GET | RFC 6960 OCSP (application/ocsp-request) |
| `/acme/` | — | RFC 8555 ACME v2 automated issuance |
| `/acme/renewalInfo/{cert-id}` | GET | RFC 9445 ACME ARI renewal info (cert-id = base64url(SHA-256(DER))) |
| `/scep` | — | RFC 8894 SCEP network device enrollment |

---

## System

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/healthz` | Health check | ❌ Public |
| GET | `/readyz` | Readiness check | ❌ Public |
| GET | `/swagger/` | Swagger UI interactive documentation | ✅ readonly |
| GET | `/version` | Version information | ❌ Public |

### Swagger UI

After starting the service, open in a browser:

```
http://localhost:8443/swagger/
```

---

## Internationalization

The web UI supports both Chinese and English. Switch languages via:
- **Automatic**: browser `Accept-Language` header
- **Manual**: URL parameter `?lang=zh` or `?lang=en`

The CLI message language is controlled by the `locale` field in the configuration file.

---

## Error Response Format

```json
{
  "code": 401,
  "message": "unauthorized",
  "detail": "optional detail"
}
```

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 400 | Invalid request parameters |
| 401 | Unauthenticated / invalid token |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 500 | Server error |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `varwof report --template soc2\|pci\|nist\|iso --out report.pdf --ca name` | Generate a compliance report PDF (SOC 2 / PCI DSS v4.0 / NIST SP 800-53 / ISO 27001) |

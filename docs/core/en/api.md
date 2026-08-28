# REST API Reference

**Base URL**: `http://<host>:8443/api/v1`

**Authentication**: `X-Auth-Token: <token>` or `Authorization: Bearer <token>`

---

## Authentication

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/users/login` | Log in to obtain a token | Public |
| GET | `/users/info` | Current user information | Token |
| GET | `/session` | Session identity probe | mTLS/Token/Cookie |
| POST | `/users/logout` | Log out and revoke token | Token |

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

Returns current identity with bound certificate info (if any).

```bash
# mTLS connection
curl -s --cert client.pem --key client.key --cacert ca.pem \
  https://<host>:4433/api/v1/session

# Token session
curl -s -H "X-Auth-Token: <token>" http://localhost:8443/api/v1/session
```

---

## User Management

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/users` | List users | Token |
| POST | `/users` | Create a user | Token |
| DELETE | `/users/{id}` | Delete a user | Token |
| POST | `/users/{id}/operator-cert` | Bind operator certificate | admin |
| DELETE | `/users/{id}/operator-cert` | Unbind operator certificate | admin |

### Create User

```bash
curl -s -X POST http://localhost:8443/api/v1/users \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"Pass1234","role":"operator"}'
```

Roles: `admin`, `operator`, `auditor`, `readonly`

### Bind Operator Certificate

```bash
curl -s -X POST -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  http://localhost:8443/api/v1/users/1/operator-cert \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n"}'
# → {"status":"bound","scope":["VPC Client CA"]}
```

---

## Token Management

| Method | Path | Description | Auth | Permission |
|--------|------|-------------|------|------------|
| GET | `/tokens?user_id=N` | List tokens | Token | `user:list` |
| POST | `/tokens` | Create a token | Token | `user:manage` |
| DELETE | `/tokens/{id}` | Revoke a token | Token | `user:manage` |

---

## Certificate Operations

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/certs` | Issue a certificate | Token |
| POST | `/certs/upload` | Upload external certificate | Token |
| GET | `/certs` | List certificates | Token |
| GET | `/certs/report.pdf` | PDF report | Token |
| POST | `/certs/batch` | Batch issuance | Token |
| GET | `/cert/{ca}/{serial}` | Certificate details | Token |
| POST | `/cert/{ca}/{serial}/revoke` | Revoke certificate | Token |
| POST | `/cert/{ca}/{serial}/renew` | Renew certificate | Token |
| POST | `/cert/{ca}/{serial}/export` | Export certificate PEM | Token |
| POST | `/certs/revoke-by-principal` | Bulk revoke by PrincipalUid | Token |
| POST | `/certs/revoke-batch` | Batch revoke | Token |

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
```

### Upload External Certificate

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
```

### Revoke a Certificate

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/revoke \
  -H "X-Auth-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
```

### Batch Revocation

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
```

### Renew a Certificate

```bash
curl -s -X POST http://localhost:8443/api/v1/cert/root/<serial>/renew \
  -H "X-Auth-Token: <token>"
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
| GET | `/cas` | List CAs | Token |
| GET | `/cas/tree` | CA tree structure | Token |
| GET | `/ca/{name}` | CA details | Token |
| GET | `/ca/{name}/rotation` | CA key rotation status | Token |
| POST | `/ca/{name}/rotate` | CA master key rotation | admin |

### CA Master Key Rotation

```bash
# Check rotation status
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotation

# Perform rotation
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/varwof-issuing-ca/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

---

## CRL

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/crl/{ca}` | Download CRL | Token |
| POST | `/crl/{ca}/generate` | Generate CRL | Token |

---

## Cross Certificates

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/cross-certs` | List | Token |
| POST | `/cross-cert/issue` | Issue | Token |
| POST | `/cross-cert/revoke` | Revoke | Token |

---

## Statistics & Dashboard

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/dashboard` | Full dashboard statistics | Token |
| GET | `/dashboard/events` | SSE real-time push | Token |
| GET | `/stats` | Summary statistics | Token |

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
| GET | `/audit?limit=50&offset=0` | Audit logs | Token |
| GET | `/ra?status=pending` | List RA requests | Token |
| POST | `/ra` | Submit RA request | Token |
| POST | `/ra/{id}/approve` | Approve request | Token |
| POST | `/ra/{id}/reject` | Reject request | Token |
| POST | `/keys/recover` | Recover escrowed keys | Token |

---

## Webhook

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/webhooks` | List subscriptions | Token |
| POST | `/webhooks` | Create subscription | Token |

---

## DNS Service

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
# Set challenge
curl -X PUT http://localhost:8443/api/v1/dns/acme-challenge/example.com \
  -H "X-Auth-Token: <token>" -H "Content-Type: application/json" \
  -d '{"key_auth":"..."}'

# Verify
dig @localhost -p 53 _acme-challenge.example.com TXT
```

### DNS over HTTPS (DoH)

```bash
curl "http://localhost:8443/api/v1/dns-query?name=example.com&type=TXT"
```

Supported types: A, AAAA, TXT, CNAME, MX, NS, SOA, PTR, SRV, CERT, TLSA

---

## Protocol Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/tsa` | POST | RFC 3161 timestamp (application/timestamp-query) |
| `/ocsp` | POST/GET | RFC 6960 OCSP (application/ocsp-request) |
| `/acme/` | — | RFC 8555 ACME v2 |
| `/acme/renewalInfo/{cert-id}` | GET | RFC 9445 ACME ARI |
| `/scep` | — | RFC 8894 SCEP |

---

## System

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/healthz` | Health check | Public |
| GET | `/readyz` | Readiness check | Public |
| GET | `/swagger/` | Swagger UI | readonly |
| GET | `/version` | Version information | Public |

---

## Port Allocation

| Service | Port | Description |
|---------|------|-------------|
| `varwof serve` | `:8443` | Web UI + REST API + TSA + OCSP + CRL + DoH |
| `varwof serve dns` | `:53` | DNS UDP (ACME DNS-01) |
| `varwof serve dns` (DoT) | `:853` | DNS over TLS |

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

## Internationalization

The web UI supports Chinese and English:
- **Automatic**: browser `Accept-Language` header
- **Manual**: URL parameter `?lang=zh` or `?lang=en`

CLI message language is controlled by the `locale` field in configuration.

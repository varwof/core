# Architecture Overview

## System Architecture

```
                          ┌─────────────────────────────────────────┐
                          │            pki (single binary)          │
                          ├─────────────────────────────────────────┤
                          │                                         │
  ┌──────────┐            │  ┌─────────┐  ┌──────────┐  ┌────────┐ │
  │ Web UI   │◄───────────┼─►│  serve   │  │  config  │  │  i18n  │ │
  │ (SPA)    │            │  │ (HTTP)  │  │          │  │        │ │
  └──────────┘            │  └────┬────┘  └──────────┘  └────────┘ │
                          │       │                                  │
  ┌──────────┐            │  ┌────▼────┐  ┌──────────┐             │
  │ CLI      │◄───────────┼─►│   ca    │  │ provisioner│            │
  │ (cobra)  │            │  │ (engine)│  │ (mTLS/   │             │
  └──────────┘            │  └────┬────┘  │  Token/  │             │
                          │       │       │  OIDC)   │             │
  ┌──────────┐            │  ┌────▼────┐  └──────────┘             │
  │ REST API │◄───────────┼─►│   db    │                           │
  │ (:8443)  │            │  │(SQLite/ │  ┌──────────┐             │
  └──────────┘            │  │ PG/MySQL│  │ routing  │             │
                          │  └─────────┘  └──────────┘             │
                          │                                         │
                          │  ┌─────────┐  ┌──────────┐             │
                          │  │  ocsp   │  │   tsa    │             │
                          │  │(RFC6960)│  │(RFC3161) │             │
                          │  └─────────┘  └──────────┘             │
                          │                                         │
                          │  ┌─────────┐  ┌──────────┐  ┌────────┐│
                          │  │  acme   │  │   scep   │  │  dns   ││
                          │  │(RFC8555)│  │(RFC8894) │  │        ││
                          │  └─────────┘  └──────────┘  └────────┘│
                          │                                         │
                          │  ┌─────────┐  ┌──────────┐  ┌────────┐│
                          │  │ pkcs7   │  │ pkcs12   │  │notifier││
                          │  │(signing)│  │ (export) │  │(webhook││
                          │  └─────────┘  └──────────┘  └────────┘│
                          │                                         │
                          │  ┌─────────┐  ┌──────────┐            │
                          │  │rbac     │  │ratelimit │            │
                          │  │(authz)  │  │(token    │            │
                          │  │         │  │ bucket)  │            │
                          │  └─────────┘  └──────────┘            │
                          └─────────────────────────────────────────┘
```

## Component Overview

### Core Engine (`internal/ca/`)

The heart of the system. Handles certificate issuance, renewal, revocation, and CRL generation. The in-memory engine provides high-throughput reads/writes with async batch persistence to the database.

Key responsibilities:
- Certificate signing (X.509 v3)
- CSR parsing and validation
- SAN processing (DNS, IP, URI, email)
- Name constraints enforcement
- Profile-based extension templating
- CRL generation and signing
- Key escrow encryption/decryption

### HTTP Server (`internal/serve/`)

Dual-mux architecture:
- **Full mux** (`:8443`): All endpoints including admin operations
- **Public mux** (`:4430`): Health checks, CRL distribution, OCSP

Middleware stack:
1. Access logging
2. Rate limiting (token bucket)
3. RBAC authorization (simple/enterprise modes)
4. mTLS client certificate verification
5. Delegated-agent session handling

### Database Layer (`internal/db/`)

Abstracted via `github.com/varwof/engine/db` interface. Supports:
- **SQLite**: Zero-config, single-node (recommended for dev/small scale)
- **PostgreSQL**: Multi-writer, production-grade
- **MySQL/MariaDB**: Multi-writer, MySQL ecosystem

Schema migrations are applied automatically on startup.

### Protocol Servers

#### OCSP Responder (`internal/ocsp/`)
- RFC 6960 compliant
- In-memory cache with optional disk-backed persistence
- Stateless node support via `cache_file`

#### TSA (`internal/tsa/`)
- RFC 3161 compliant
- Automatic signer certificate renewal
- Configurable accuracy (seconds/millis/micros)

#### ACME (`internal/acme/`)
- RFC 8555 compliant (ACME v2)
- HTTP-01 and DNS-01 challenge support
- External Account Binding (EAB)
- Automatic Renewal Information (ARI, RFC 9445)
- Per-IP rate limiting

#### SCEP (`internal/scep/`)
- RFC 8894 compliant
- Device enrollment for enterprise environments

#### DNS Server (`internal/dns/`)
- Authoritative DNS for ACME DNS-01 challenges
- DoH (DNS over HTTPS) via main port
- DoT (DNS over TLS) on separate port
- CERT, SRV record support

### Security Components

#### Provisioner (`internal/provisioner/`)
Authentication chain:
1. mTLS client certificate
2. API token (`X-Auth-Token`)
3. OIDC (OpenID Connect)
4. HTTP Basic Auth (fallback)

#### RBAC (`auth/`)
Two modes:
- **Simple**: OU-based role mapping
- **Enterprise**: Full permission matrix with CA scopes

#### Policy Signing
PKCS#7 signature verification for `authz.json` and `routes.json`. Prevents local tampering with fail-closed behavior.

### Notifications

#### Webhook (`internal/notifier/`)
HTTP POST JSON payloads on certificate lifecycle events:
- Certificate issued
- Certificate revoked
- Certificate expiring (configurable thresholds)

#### SMTP
Email notifications for the same events.

### Cryptographic Operations

#### PKCS#7 Signing (`internal/pkcs7/`)
- Detached signatures
- Embedded signatures
- CAdES-T (timestamped) signatures

#### PKCS#12 Export (`internal/pkcs12/`)
- PFX/PKCS#12 bundle creation
- Password-protected private keys

#### Key Backend (`internal/remotesigner/`)
Pluggable remote HSM signer delegation for hardware security module integration.

### Identity Integration

#### LDAP (`internal/ldap/`)
Directory integration for:
- User authentication
- Subject DN auto-fill from directory attributes

#### Identity Bridge
Automated certificate issuance from identity sources:
- LDAP bridge (`bridge-ldap`)
- OAuth bridge (password grant + userinfo)

### Monitoring

#### Audit Log
- Merkle hash chain integrity
- Per-day HMAC salt masking of PII
- Configurable retention and cleanup

#### Metrics
Prometheus-compatible `/metrics` endpoint (when enabled).

#### Dashboard
Real-time SSE push for certificate lifecycle events.

## Data Flow

### Certificate Issuance

```
Client Request → Auth (mTLS/Token/OIDC) → RBAC Check → Rate Limit
    → CA Engine → CSR Parse → Profile Apply → Sign → Store (DB + Engine)
    → Webhook Notify → Response
```

### Certificate Revocation

```
Revoke Request → Auth → RBAC Check → Engine Update (memory)
    → DB Async Persist → CRL Regenerate → OCSP Cache Invalidate
    → Webhook Notify → Response
```

### Config Hot Reload

```
SIGHUP / Poll Timer → Parse JSON → Validate → Atomic Swap:
    (handlers, DB, engine, provisioners, route rules, capability schemes)
```

## Port Allocation

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Main server | `:8443` | HTTP | Web UI + REST API + TSA + OCSP + CRL + DoH |
| TLS server | `:4433` | HTTPS | mTLS-protected endpoints |
| DNS | `:53` | UDP/TCP | ACME DNS-01 + CERT + SRV |
| DoT | `:853` | TLS | DNS over TLS |
| TSA (standalone) | `:3180` | HTTP | RFC 3161 timestamp |
| OCSP (standalone) | `:9080` | HTTP | RFC 6960 responder |

## Source Tree

```
core/
├── cmd/pki/                  CLI entry point (cobra commands)
│   ├── main.go               Root command, signal handling
│   ├── cmd_*.go              Subcommand implementations
│   ├── serve.go              HTTP server bootstrap
│   └── *_test.go             Test suites
├── internal/
│   ├── ca/                   CA issuance engine
│   ├── serve/                HTTP API handlers + middleware
│   ├── db/                   Database abstraction
│   ├── config.go             Configuration structs
│   ├── acme/                 ACME v2 protocol
│   ├── ocsp/                 OCSP responder
│   ├── tsa/                  TSA timestamping
│   ├── dns/                  DNS server
│   ├── pkcs7/                PKCS#7 signing
│   ├── pkcs12/               PFX export
│   ├── notifier/             Webhook notifications
│   ├── provisioner/          Authentication providers
│   ├── routing/              Route rule engine
│   ├── i18n/                 Internationalization (en.json, zh.json)
│   ├── engine/               In-memory engine
│   ├── secrets/              CA key password resolution
│   ├── capregistry/          Capability scheme registry
│   └── remotesigner/         HSM/remote signer delegation
├── auth/                     RBAC policies, policy signing
├── deploy/                   Deployment scripts
└── docs/                     Documentation
```

## Satellite Projects

| Project | Description |
|---------|-------------|
| `varwof-gateway-tcp` | TCP security gateway |
| `varwof-gateway-http` | HTTP security gateway |
| `varwof-gateway-udp` | UDP security gateway |
| `varwof-protocols` | EST/SCEP/CMP protocols |
| `pki-dns-server` | Standalone DNS server |
| `bridge-ldap` | LDAP bridge service |
| `pki-pades` | PAdES PDF signing |
| `pki-deploy` | Deployment tools |
| `pki-webhook` | Webhook push service |
| `varwof-cli` | CLI management tool |
| `user-signer` | Remote signing service |
| `pki-hsm-proxy` | HSM adapter |
| `console` | Web console |

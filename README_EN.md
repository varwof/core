# pki · The Swiss Army Knife for Internal PKI

> ⚠️ **Technical Preview** — Core cryptographic primitives have passed OpenSSL interoperability verification; RFC compliance completion is ongoing.
> Issues and contributions are welcome.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/core)](https://pkg.go.dev/github.com/varwof/core)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/varwof/core/actions)

**Single binary, pure Go, your private CA running in one minute.** No OpenSSL wrappers, no Python services, no complex multi-tool orchestration.

> **Pure Go implementation**: all functionality is implemented in pure Go with no external dependencies (no openssl, sqlite3, or other command-line tools needed).
> **System requirements**: none. Just a single Go-compiled binary.
> **Target users**: individual developers, small teams, and K8s dev clusters that need internal HTTPS certificates without being hassled by commercial CA fees.

**Language**: Go 1.26 — **Database**: SQLite (**recommended**, pure Go, no CGO) — **Binary size**: ~20MB

---

## Features

| Category | Capabilities |
|----------|-------------|
| **CA** | init-ca (root/sub), ca-list, ca-info, name constraints, **Remote Signer** (HSM delegation) |
| **Issue** | CSR or auto keygen, 9 profiles, batch CSV, renew, encrypted private key |
| **Revoke** | CLI revocation, OCSP real-time, CRL periodic generation |
| **TSA** | RFC 3161 timestamp, configurable Policy QIs |
| **OCSP** | RFC 6960 responder, LRU cache |
| **Code sign** | PKCS#7 detached/embedded, CAdES-T (real TSA), PAdES-B PDF sign, verify |
| **RFC 5280** | 20B serial, AIA caIssuers, Name Constraints (DNS/Email/URI/IP), CRL InvalidityDate, IssuerAltName, SubjectInfoAccess, CertificatePolicies |
| **PFX** | PKCS#12 export (pure Go, AES-256-CBC + SHA-256) |
| **SM2** | SM2 key gen + cert issue + OpenSSL verify (build -tags gmsm) |
| **Multi-DB** | SQLite (**recommended**), PostgreSQL (community), MySQL/MariaDB (community) |
| **Modular** | pki serve {tsa,ocsp,crl,api,dns} independent deployment |
| **DNS** | Built-in DNS server for ACME DNS-01, DoH, DoT |
| **i18n** | Bilingual EN/ZH UI and CLI messages |
| **ACME v2** | RFC 8555, HTTP-01, auto-issuance |
| **SCEP** | RFC 8894, GetCACert, PKCSReq |
| **K8s** | cert-manager External Issuer (extracted to a separate repository `pki-k8s-issuer`) |
| **RBAC** | Users (4 roles), API tokens (SHA-256 hashed at rest), audit log with Merkle chain |
| **RA workflow** | M-of-N multi-level approval |
| **LDAP** | Directory auto-fill for certificate Subject |
| **Webhook** | Issue/revoke/expiry event push |
| **CT** | Certificate Transparency log submission |
| **Key escrow** | RSA-OAEP + AES-256-GCM backup & recovery |
| **Encryption** | PBKDF2 + AES-256-CBC private key encryption |
| **DB backup** | Online VACUUM INTO snapshot |
| **Hot reload** | Auto-poll config changes (`--reload`) |
| **Rate limit** | Per-IP token bucket |
| **Web UI** | Built-in dashboard |
| **REST API** | JSON API for all operations |
| **Health** | `/healthz`, `/readyz` endpoints |
| **Shell completion** | bash, zsh, fish |
| **Deploy** | `pki deploy --target nginx/apache/k8s-secret` config generator |

## Hardware support

Private keys can be protected by **PicoKeys Pico HSM** (RP2350/ESP32-S3) via `key_backend` config.
See [pki-hsm-proxy](https://github.com/varwof/pki-hsm-proxy) for the HSM proxy component and [PicoKeys](https://www.picokeys.com/) for hardware details.

Features: ECC P-256/P-384/P-521, Ed25519, RSA 2048/4096, PKCS#11, hardware key generation,
physical press-to-confirm signing, 128 keypairs capacity, 16 isolated key domains.

## Quick start

```bash
# Build
go build -o /usr/local/bin/pki ./cmd/pki/

# Initialize root CA
pki init-ca --name root --profile root-ca --out-dir /etc/varwof/core/root

# Initialize issuing CA
pki init-ca --name issuing --profile sub-ca \
  --parent root --parent-key /etc/varwof/core/root/private/ca.key

# Start all services (TSA + OCSP + Web UI + ACME + SCEP)
pki serve

# Issue a certificate
pki issue --cn server.example.com \
  --san "DNS:server.example.com,IP:10.0.0.1" \
  --profile tls-server --out-dir /etc/varwof/core/certs

# Code sign a binary
pki sign myapp.bin --embed

# Revoke a certificate
pki revoke --serial $(openssl x509 -in cert.pem -noout -serial | cut -d= -f2) --reason keyCompromise
```

## Documentation

| Document | EN | CN |
|---|---|---|
| Getting Started | [`docs/GettingStarted_EN.md`](docs/GettingStarted_EN.md) | [`docs/GettingStarted_CN.md`](docs/GettingStarted_CN.md) |
| Configuration | [`docs/Configuration_EN.md`](docs/Configuration_EN.md) | [`docs/Configuration_CN.md`](docs/Configuration_CN.md) |
| Feature Overview | [`docs/FeatureOverview_EN.md`](docs/FeatureOverview_EN.md) | [`docs/FeatureOverview_CN.md`](docs/FeatureOverview_CN.md) |
| API Reference | [`docs/API.md`](docs/API.md) | — |
| Deployment | — | [`docs/Deployment_CN.md`](docs/Deployment_CN.md) |
| End-to-End Demo | — | [`docs/EndToEndDemo_CN.md`](docs/EndToEndDemo_CN.md) |
| Migration | — | [`docs/Migration_CN.md`](docs/Migration_CN.md) |
| Release Guide | [`docs/ReleaseGuide_EN.md`](docs/ReleaseGuide_EN.md) | [`docs/ReleaseGuide_CN.md`](docs/ReleaseGuide_CN.md) |
| RFC Deviations | [`docs/RFC_DEVIATIONS.md`](docs/RFC_DEVIATIONS.md) | — |
| Project Pitch | [`docs/PITCH.md`](docs/PITCH.md) | — |
| OpenAPI Spec | [`docs/openapi.yaml`](docs/openapi.yaml) | — |
| Architecture | [`../dev-docs/core/arch/architecture.md`](../dev-docs/core/arch/architecture.md) | — |
| Changelog | [`../dev-docs/core/changelogs/changelog.md`](../dev-docs/core/changelogs/changelog.md) | — |
| Bug Fixes | [`../dev-docs/core/changelogs/bug-fixes.md`](../dev-docs/core/changelogs/bug-fixes.md) | — |
| Coverage Report | [`../dev-docs/core/reports/coverage-report.md`](../dev-docs/core/reports/coverage-report.md) | — |
| Archived Plan | — | [`../dev-docs/core/archived/PLAN.md`](../dev-docs/core/archived/PLAN.md) |

> **RFC Compliance**: pki has undergone per-clause compliance review against
> RFC 5280, 3161, 6960, 8555, 8894, 3628, and 6125.
> [View the full compliance table](../dev-docs/core/rfc/COMPLIANCE.md).

## Configuration

Search order: `./pki.json` → `~/.config/pki/pki.json` → `/etc/varwof/core/pki.json`
Override: `--config <path>`

```jsonc
{
  "db": "/var/lib/pki/pki.db",
  "serve": { "addr": ":4430", "tls_addr": ":4433" },
  "cas": {
    "root":    { "cert": "/etc/varwof/core/root/ca.pem", "key": "/etc/varwof/core/root/private/ca.key" },
    "issuing": { "cert": "/etc/varwof/core/issuing/ca.pem", "key": "/etc/varwof/core/issuing/private/ca.key", "chain": "/etc/varwof/core/root/ca.pem" }
  },
  "defaults": { "ca": "issuing", "profile": "tls-server", "key_type": "ecdsa-p256" },
  "rbac": { "enabled": true, "jwt_secret": "CHANGE_ME" },
  "ra": { "required_approvals": 2 }
}
```

See `pki init-config` for a full annotated config file.

## Architecture

```
pki binary
 ├─ serve :4430/:4433
 │   ├─ TSA (RFC 3161) / OCSP (RFC 6960) [LRU cache]
 │   ├─ ACME v2 / SCEP
 │   ├─ JSON REST API [RBAC + rate limit]
 │   ├─ Web UI
 │   └─ Static files
 ├─ issue / renew / batch → certificate issuance [LDAP auto-fill]
 ├─ sign / pades / export → code signing + PAdES PDF + PFX
 ├─ user / token / audit → RBAC & audit
 ├─ ra submit/approve → approval workflow
 └─ db / key / recover → operations
        │
        ▼
   SQLite database
```

## Key types

| Algorithm | Signing | Hash |
|-----------|---------|------|
| ECDSA P-256 | ✓ | SHA-256 |
| ECDSA P-384 | ✓ | SHA-384 |
| RSA 2048 | ✓ | SHA-256 |
| RSA 4096 | ✓ | SHA-384 |
| Ed25519 | ✓ | None (intrinsic) |

## License

[Apache 2.0](LICENSE) © 2026 varwof

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Project Structure

```
core/
├── cmd/pki/              # Entry commands
├── internal/             # Internal packages (ca/config/db/tsa/ocsp/signer/pkcs7/...)
├── auth/                 # Authorization policy
├── docs/                 # User documentation
├── dev-docs/             # Development/internal documentation (scripts + RFC references)
├── deploy/               # Deployment files
├── README.md
├── CLAUDE.md
├── AGENT.md
├── CONTRIBUTING.md
└── go.mod
```

# core Reference Manual

> **This document has been consolidated into the following documents:**

- **API Endpoints**: [API.md](API.md) / [openapi.yaml](openapi.yaml)
- **Configuration Fields**: [Configuration_EN.md](Configuration_EN.md)
- **Features**: [FeatureOverview_EN.md](FeatureOverview_EN.md)
- **RFC Deviations**: [RFC_DEVIATIONS.md](RFC_DEVIATIONS.md)

## Architecture Overview

```
core (single binary)
├── cmd/pki/          — CLI entry point
├── internal/
│   ├── ca/          — CA issuance engine
│   ├── serve/       — HTTP API server
│   ├── db/          — Database abstraction (SQLite/PG/MySQL)
│   ├── acme/        — ACME v2 (RFC 8555)
│   ├── ocsp/        — OCSP responder (RFC 6960)
│   ├── tsa/         — TSA timestamping (RFC 3161)
│   ├── dns/         — DNS server
│   ├── pkcs7/       — PKCS#7 code signing
│   ├── pkcs12/      — PFX export
│   ├── notifier/    — Webhook notifications
│   ├── provisioner/ — Authentication (mTLS/Token/OIDC)
│   ├── routing/     — Route rule engine
│   └── i18n/        — Internationalization
├── auth/            — RBAC policies
└── deploy/          — Deployment scripts
```

## Satellite Projects

| Satellite | Description |
|-----------|-------------|
| varwof-gateway-{tcp,http,udp} | Three-layer security gateway |
| varwof-protocols | EST/SCEP/CMP protocols |
| pki-dns-server | DNS server |
| bridge-ldap | LDAP bridge |
| pki-pades | PAdES signing |
| pki-deploy | Deployment tools |
| pki-webhook | Webhook push |
| varwof-cli | CLI management tool |
| user-signer | Remote signing service |
| pki-hsm-proxy | HSM adapter |
| console | Web console |

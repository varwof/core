# core Usage Guide

> **The content of this document has been consolidated into the following documents:**

- **CLI commands in detail**: [GettingStarted_CN.md](GettingStarted_CN.md) § CLI Commands
- **Configuration usage**: [Configuration_CN.md](Configuration_CN.md)
- **API calls**: [API.md](API.md)
- **Deployment usage**: [Deployment_CN.md](Deployment_CN.md)
- **End-to-end demo**: [EndToEndDemo_CN.md](EndToEndDemo_CN.md)

## Core Operations Quick Reference

| Operation | CLI Command | API Endpoint |
|-----------|-------------|--------------|
| Initialize CA | `varwof init-ca` | — |
| Issue certificate | `varwof issue` | `POST /api/v1/certs` |
| Revoke certificate | `varwof revoke` | `POST /api/v1/certs/revoke` |
| Renew certificate | `varwof renew` | `POST /api/v1/certs/renew` |
| Generate CRL | `varwof crl` (`--delta --since` generates a delta CRL) | `POST /api/v1/crl/{ca}/generate` (`?delta=1&since=`) |
| List CAs | `varwof ca-list` | `GET /api/v1/ca` |
| View CA | `varwof ca-info` | `GET /api/v1/ca/{name}` |
| Start service | `varwof serve` | — |
| Batch issuance | `varwof batch` | `POST /api/v1/certs/batch` |
| Query certificates | `varwof list` | `GET /api/v1/certs` |

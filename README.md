# Varwof PKI

> ⚠️ **Technical Preview** — Core cryptographic primitives verified for OpenSSL interoperability; RFC compliance ongoing.
> **Not for production use.** APIs and features may change before official release.

[![License](https://img.shields.io/badge/license-AGPL%203.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/core)](https://pkg.go.dev/github.com/varwof/core)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/varwof/core/actions)

**Single binary, pure Go, private CA up in one minute.**

[中文](README_CN.md)

> **Pure Go**: all features implemented in pure Go, no external dependencies.
> **System Requirements**: none. Just a single Go-compiled binary.
> **Target Users**: individual developers, small teams, K8s dev clusters.

**Language**: Go 1.26 — **Database**: SQLite (recommended, pure Go)

---

## Features

| Category | Capabilities |
|----------|-------------|
| **CA** | init-ca (root/sub), ca-list, ca-info, sub-ca create |
| **Issue** | CSR or auto keygen, 9 profiles, batch CSV, renew |
| **Revoke** | CLI revocation, OCSP real-time, CRL generation |
| **TSA** | RFC 3161 timestamp |
| **OCSP** | RFC 6960 responder |
| **Code sign** | PKCS#7 detached/embedded, CAdES-T, verify |
| **Cross-cert** | Cross-certificate issue/list/revoke |
| **Trust bridge** | Cross-sign CA, federate trust anchors |
| **Multi-DB** | SQLite (recommended), PostgreSQL, MySQL/MariaDB |
| **RBAC** | Users (4 roles), API tokens, audit log |
| **REST API** | JSON API for all operations |
| **Health** | `/healthz`, `/readyz` endpoints |

## Quick Start

```bash
go build -o /usr/local/bin/pki ./cmd/pki/

pki init-ca --name root --profile root-ca --out-dir /etc/varwof/core/root
pki init-ca --name issuing --profile sub-ca \
  --parent root --parent-key /etc/varwof/core/root/private/ca.key

pki serve

pki issue --cn server.example.com \
  --san "DNS:server.example.com,IP:10.0.0.1" \
  --profile tls-server --out-dir /etc/varwof/core/certs
```

## Installation

```bash
go build -o /usr/local/bin/pki ./cmd/pki/
```

## Architecture

```mermaid
graph TB
    subgraph varwof["varwof Ecosystem"]
        core["core<br/>PKI CA<br/>:4430/:4433"]
        tcp["gateway-tcp<br/>TCP L4"]
        http["gateway-http<br/>HTTP L7"]
        udp["gateway-udp<br/>UDP L3"]
        gwcore["gateway-core<br/>Security Engine"]
        client["client<br/>CLI"]
        types["types<br/>Shared Types"]
        reg["register<br/>Capability Registry"]
        eng["engine<br/>In-Memory"]
    end
    client -->|mTLS| core
    tcp --> gwcore
    http --> gwcore
    udp --> gwcore
    gwcore -->|mTLS API| core
    core --> eng
    core --> types
    core --> reg
```

## Documentation

| Document | EN | CN |
|---|---|---|
| Getting Started | [`docs/GettingStarted_EN.md`](docs/GettingStarted_EN.md) | [`docs/GettingStarted_CN.md`](docs/GettingStarted_CN.md) |
| Configuration | [`docs/Configuration_EN.md`](docs/Configuration_EN.md) | [`docs/Configuration_CN.md`](docs/Configuration_CN.md) |
| API Reference | [`docs/API.md`](docs/API.md) | — |
| OpenAPI Spec | [`docs/openapi.yaml`](docs/openapi.yaml) | — |

core is the **core CA engine** of the varwof ecosystem, providing complete PKI lifecycle management. This project is a member of the [Open Invention Network](https://openinventionnetwork.com/).

## Links

| | |
|---|---|
| Homepage | https://varwof.com |
| Community | https://varwof.org |
| IETF Draft | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| License | AGPL-3.0 |
| Member | [Open Invention Network](https://openinventionnetwork.com/) |

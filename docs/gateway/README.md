# varwof-gateway

Three-layer zero-trust security gateway unifying TCP/HTTP/UDP protocols with mTLS, RBAC, and AIC capability verification.

**Module**: `github.com/varwof/gateway`  
**License**: Apache-2.0  
**Status**: Preview

## Overview

The varwof gateway provides three protocol-specific binaries:

| Binary | Layer | Protocol | Use Case |
|--------|-------|----------|----------|
| `gateway-http` | L7 | HTTP/1.1, HTTP/2, H2C, gRPC, WebSocket, HTTP/3, QUIC | Web apps, APIs, microservices |
| `gateway-tcp` | L4 | TCP, mTLS, Mesh | Database proxies, SSH, generic TCP |
| `gateway-udp` | L3 | UDP, DTLS, QUIC | DNS, VoIP, IoT, gaming |

All three share the same security core (`gateway-core`):
- mTLS client certificate authentication
- CRL real-time revocation
- OCSP stapling/check
- AIC (Agent Identity Certificate) verification
- RBAC (role-based access control)
- Capability plugin system
- Short-lived certificate auto-issuance
- Audit logging with Merkle hash chain
- Prometheus metrics
- SIGHUP hot reload

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         gateway-core (shared)        │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ CRL     │ │ OCSP   │ │ Audit  │ │
                    │  │ Cache   │ │ Cache  │ │ Logger │ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ RBAC    │ │ AIC    │ │ CapReg │ │
                    │  │ Check   │ │ Verify │ │        │ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    │  ┌─────────┐ ┌────────┐ ┌────────┐ │
                    │  │ Short   │ │ Revoker│ │ Risk   │ │
                    │  │ Lived   │ │        │ │ Monitor│ │
                    │  └─────────┘ └────────┘ └────────┘ │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
    ┌─────────▼─────────┐ ┌───────▼───────┐ ┌──────────▼──────────┐
    │   gateway-http    │ │  gateway-tcp  │ │    gateway-udp      │
    │   (L7 reverse     │ │  (L4 mapping  │ │    (L3 forwarding   │
    │    proxy)         │ │   + tunnel)   │ │     + DTLS/QUIC)    │
    └───────────────────┘ └───────────────┘ └─────────────────────┘
```

## Installation

```bash
# Build all three
go build -o gateway-http ./cmd/http/
go build -o gateway-tcp ./cmd/tcp/
go build -o gateway-udp ./cmd/udp/
```

## Quick Start

### HTTP Gateway

```bash
# 1. Create config
cat > gateway-http.json << 'EOF'
{
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http2",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "/etc/varwof/gateway/ca.pem"
      },
      "routes": [
        {
          "path": "/api/*",
          "target": "http://backend:8080",
          "allow_roles": ["gateway:ops"]
        }
      ]
    }
  ],
  "management": {
    "listen": "127.0.0.1:9443",
    "cert_file": "/etc/varwof/gateway/mgmt.pem",
    "key_file": "/etc/varwof/gateway/mgmt.key",
    "ca_file": "/etc/varwof/gateway/ca.pem"
  },
  "capreg": {
    "capability_dir": "/etc/varwof/capabilities"
  }
}
EOF

# 2. Start
gateway-http --config gateway-http.json

# 3. Verify
curl --cert client.pem --key client.key --cacert ca.pem \
  https://localhost:443/api/healthz
```

### TCP Gateway

```bash
# Mapping server
gateway-tcp server \
  --listener "name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem"

# Client tunnel
gateway-tcp tunnel \
  --gateway gateway-host:8443 \
  --server-cert client.pem \
  --server-key client.key \
  --ca-cert ca.pem \
  --target 10.0.0.1:3306 \
  --name db-tunnel
```

### UDP Gateway

```bash
gateway-udp \
  --config gateway-udp.json
```

## Configuration

### HTTP Config

```json
{
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http2",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "/etc/varwof/gateway/ca.pem",
        "cert_file": "/etc/varwof/gateway/server.pem",
        "key_file": "/etc/varwof/gateway/server.key"
      },
      "routes": [
        {
          "path": "/api/*",
          "target": "http://backend:8080",
          "allow_roles": ["gateway:ops"],
          "allow_methods": ["GET", "POST"],
          "required_capabilities": ["read:data"],
          "upstream_tls": {
            "enabled": true,
            "ca_file": "/etc/varwof/gateway/upstream-ca.pem"
          }
        }
      ],
      "http_ext": {
        "max_body_bytes": 10485760,
        "request_timeout": "30s"
      }
    }
  ],
  "management": {
    "listen": "127.0.0.1:9443",
    "cert_file": "/etc/varwof/gateway/mgmt.pem",
    "key_file": "/etc/varwof/gateway/mgmt.key",
    "ca_file": "/etc/varwof/gateway/ca.pem"
  },
  "capreg": {
    "capability_dir": "/etc/varwof/capabilities"
  },
  "shortlived_cert": {
    "enabled": true,
    "validity": "1h",
    "renew_before": "5m"
  },
  "revoker": {
    "enabled": true
  },
  "risk_monitor": {
    "enabled": true,
    "violation_threshold": 5,
    "action": "disconnect"
  }
}
```

### TCP Config

```json
{
  "mappings": [
    {
      "name": "db-proxy",
      "listen": ":8443",
      "target": "10.0.0.1:3306",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "ca.pem",
        "cert_file": "server.pem",
        "key_file": "server.key",
        "allow_roles": ["gateway:ops"],
        "max_conns_per_ip": 100,
        "max_conns_per_cert": 50,
        "max_total_conns": 500
      }
    }
  ],
  "mesh": {
    "enabled": true,
    "listen": ":7000",
    "peers": [
      {
        "name": "node-b",
        "address": "10.0.0.2:7000",
        "ca_cert_file": "ca.pem"
      }
    ],
    "target_allowlist": ["10.0.0.0/24"]
  },
  "management": { ... },
  "capreg": { ... }
}
```

### UDP Config

```json
{
  "listeners": [
    {
      "name": "dtls-gw",
      "listen": ":5353",
      "target": "10.0.0.5:8080",
      "tls_mode": "dtls",
      "mtls": {
        "ca_cert_file": "ca.pem",
        "cert_file": "server.pem",
        "key_file": "server.key"
      },
      "rate_limit": {
        "requests_per_second": 1000,
        "burst": 2000
      },
      "nonce_ttl_sec": 300
    }
  ],
  "management": { ... },
  "capreg": { ... }
}
```

## Security Pipeline

Every connection passes through the admission pipeline:

```
TLS Handshake (client cert verified)
  → CRL Check (certificate on revocation list?)
  → OCSP Check (online status validation)
  → RBAC Check (certificate OU matches allowed roles?)
  → AIC Parse + Verify (delegation signature, nonce, capabilities)
  → Parameter Boundary Validation
  → Capability Plugin Evaluation
  → Risk Signal Recording
  → Admission Decision: Allow or Deny
```

## TLS Modes

| Mode | Description |
|------|-------------|
| `plain` | No TLS |
| `server` | Server-side TLS only |
| `mtls` | Mutual TLS (client certificate required) |
| `client` | Client-side TLS (for upstream connections) |
| `mesh` | Inter-gateway mTLS (TCP mesh federation) |
| `dtls` | Datagram TLS (UDP) |
| `quic` | QUIC protocol (UDP) |

## Management API

All gateways expose an mTLS-protected management API:

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Health check |
| `GET /metrics` | Prometheus metrics |
| `POST /reload` | Hot reload configuration |
| `GET /connections` | Active connections |
| `POST /crl/refresh` | Force CRL refresh |
| `GET /audit` | Query audit logs |
| `GET /policy/version` | Current policy version |

## Protocol Support

### HTTP Gateway

| Protocol | Description |
|----------|-------------|
| HTTP/1.1 | Standard HTTP |
| HTTP/2 | Multiplexed streams |
| H2C | Cleartext HTTP/2 |
| gRPC | Remote procedure calls |
| WebSocket | Full-duplex communication |
| WebSocket Secure | WebSocket over TLS |
| HTTP/3 | QUIC-based HTTP |
| QUIC | Raw QUIC streams |

### TCP Gateway

| Feature | Description |
|---------|-------------|
| TCP mapping | Port forwarding with mTLS |
| Client tunnel | Penetration tunnel for NAT traversal |
| Mesh federation | Cross-node state sync |

### UDP Gateway

| Protocol | Description |
|----------|-------------|
| UDP | Plain packet forwarding |
| DTLS | Datagram TLS |
| DTLS mTLS | Mutual DTLS |
| QUIC | QUIC streams |
| QUIC mTLS | Mutual QUIC |

## Features

### mTLS Authentication

Bidirectional client certificate authentication with server certificates.

### CRL Real-Time Revocation

Per-listener CRL cache with periodic refresh and forced reload via API.

### OCSP Stapling

Online certificate status validation with configurable fallback (allow/deny/crl).

### AIC Verification

Parses custom OID extensions for:
- Delegation authorization signatures
- Nonce anti-replay (5-minute window)
- Capability subset verification

### RBAC

Maps certificate OU fields to roles. Per-listener/per-route role restrictions.

### Capability Plugin System

Two-stage routing:
1. Connection/declaration-layer plugins
2. Operation-layer plugins

Signed rules loaded from disk.

### Short-Lived Certificates

Automatic background issuance and renewal with zero-downtime certificate switching.

### Conditional Revocation

Revoke-on-completion for tasks. Risk-based revocation via RiskMonitor.

### Audit Logging

JSON Lines format with Merkle hash chain. TSA timestamping for external proof.

### Prometheus Metrics

Per-protocol metrics:
- `pki_gateway_http_*` (HTTP)
- `pki_gateway_mapping_*` (TCP)
- `pki_gateway_udp_*` (UDP)

### Hot Reload

SIGHUP triggers configuration reload without restart.

## Connection Limits

| Limit | Description |
|-------|-------------|
| Per-IP | Max connections from single IP |
| Per-cert | Max connections per client certificate |
| Global | Total connection limit |

## Mesh Federation (TCP)

Gateway nodes form an mTLS mesh for:
- Cross-node revocation broadcasting
- Disconnect propagation
- State synchronization

Frame format: `0xC0 magic + 2B big-endian length + JSON`

## CLI Reference

### gateway-http

```
gateway-http [flags]
  --config <path>          JSON config file
  --lang <en|zh>           UI language
  --port <port>            Management API port
  --admin <user>           Admin username
  --agent-id <id>          Agent identifier
  --management <addr>      Management listen address
  --management-cert <path> Management TLS cert
  --management-key <path>  Management TLS key
  --management-ca <path>   Management CA cert
  --version                Print version
```

### gateway-tcp

```
gateway-tcp server [flags]   Run as mapping server
gateway-tcp tunnel [flags]   Run as client tunnel
gateway-tcp audit [flags]    Query audit logs
```

**Server flags:**
```
  --config <path>          JSON config file
  --listener <name=...>    Define TCP mapping (repeatable)
  --lang <en|zh>           UI language
  --port <port>            Management API port
```

**Tunnel flags:**
```
  --gateway <host:port>    Gateway address
  --server-cert <path>     Server certificate
  --server-key <path>      Server private key
  --ca-cert <path>         CA certificate
  --target <host:port>     Backend target
  --name <string>          Tunnel name
```

**Audit flags:**
```
  --dir <path>             Audit log directory
  --since <time>           Start time filter
  --until <time>           End time filter
  --action <string>        Action type filter
  --limit <n>              Max entries
  --search <keyword>       Full-text search
  --chain                  Print audit chain DAG
```

### gateway-udp

```
gateway-udp [flags]
  --config <path>          JSON config file
  --listener <name=...>    Define UDP listener (repeatable)
  --lang <en|zh>           UI language
  --port <port>            Management API port
```

## Inline Listener Syntax

```bash
# TCP
gateway-tcp server --listener "name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem"

# UDP
gateway-udp --listener "name=dns,listen=:5353,target=10.0.0.5:53,tls-mode=dtls,ca-cert=ca.pem"
```

## Relationship to Core

```
varwof-cli ──mTLS──> varwof-core (PKI CA)
                         │
                         ▼
varwof-gateway ──mTLS──> varwof-core (CRL/OCSP/AIC verification)
```

The gateway uses the core PKI for:
- Client certificate verification (CRL + OCSP)
- AIC signature verification
- Short-lived certificate issuance
- Audit log TSA timestamping

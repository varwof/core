# Varwof Core — PKI Infrastructure

All-in-one PKI infrastructure in a single Go binary. Replaces OpenSSL wrappers, Python services, and fragmented toolchains with one unified system.

## Features at a Glance

- **Full PKI hierarchy**: Root CA + 8 business sub-CAs in one command
- **ACME v2** (RFC 8555): HTTP-01/DNS-01 challenges, EAB, ARI renewal info
- **SCEP** (RFC 8894): Device enrollment for enterprise environments
- **OCSP responder** (RFC 6960): In-memory and disk-backed cache
- **TSA** (RFC 3161): Timestamp authority with auto-renewal
- **PKCS#7 signing**: Detached, embedded, CAdES-T timestamped
- **Certificate Transparency**: Log submission with SCT verification
- **RBAC**: Simple/enterprise modes, per-CA scoping, operator certificate binding
- **Registration Authority**: Multi-party approval workflow
- **LDAP integration**: Subject DN auto-fill from directory
- **Key escrow/recovery**: Admin RSA public key encryption
- **Auto-renewal**: Once or daemon mode
- **Trust bridge federation**: Cross-CA trust establishment
- **Remote HSM signer**: Pluggable key backend
- **In-memory engine**: High-throughput reads/writes with async batch persistence
- **Compliance reports**: SOC 2, PCI DSS, NIST, ISO as PDF
- **CP/CPS generation**: RFC 3647 format
- **Webhook/SMTP notifications**: Certificate lifecycle events
- **Config hot reload**: SIGHUP or polling, atomic handler swap
- **Web UI**: Dashboard, cert management, RA workflow, topology view
- **Windows service**: Install/uninstall support
- **i18n**: Chinese and English

## Quick Start

```bash
# Install
go install github.com/varwof/core/cmd/pki@latest

# Generate config
pki init-config > pki.json

# Initialize root CA
pki ca init --name "Root CA" --key-type ecdsa-p256 --validity 8760d \
  --out-cert root/ca.pem --out-key root/ca.key

# Issue a certificate
pki issue --ca "Root CA" --cn server.example.com \
  --san DNS:server.example.com --profile tls-server \
  --out-dir certs/ --out-name server

# Start the server
pki serve --config pki.json
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](quickstart.md) | Installation, first CA, first certificate |
| [Commands](commands.md) | Complete CLI command reference |
| [Configuration](configuration.md) | All configuration options |
| [Architecture](architecture.md) | System design and component overview |
| [API Reference](api.md) | REST API endpoints |
| [Deployment](deployment.md) | Production deployment guide |
| [PKI Hierarchy](pki-hierarchy.md) | Setting up a full PKI hierarchy |

## Project Structure

```
core/
├── cmd/pki/              CLI entry point (main.go)
├── internal/
│   ├── ca/               CA issuance engine
│   ├── serve/            HTTP API server
│   ├── config.go         Configuration structs
│   ├── acme/             ACME v2 (RFC 8555)
│   ├── ocsp/             OCSP responder (RFC 6960)
│   ├── tsa/              TSA timestamping (RFC 3161)
│   ├── dns/              DNS server (ACME DNS-01)
│   ├── pkcs7/            PKCS#7 code signing
│   ├── pkcs12/           PFX export
│   ├── notifier/         Webhook notifications
│   ├── provisioner/      Authentication (mTLS/Token/OIDC/Basic)
│   ├── routing/          Route rule engine
│   ├── i18n/             Internationalization
│   ├── engine/           In-memory engine
│   ├── secrets/          CA key password resolution
│   ├── capregistry/      Capability scheme registry
│   └── remotesigner/     HSM/remote signer delegation
├── auth/                 RBAC policies, policy signing
├── deploy/               Deployment scripts
└── docs/                 Documentation
```

## Satellite Projects

| Project | Description |
|---------|-------------|
| varwof-gateway-{tcp,http,udp} | Three-layer security gateway |
| varwof-protocols | EST/SCEP/CMP protocols |
| pki-dns-server | DNS server |
| bridge-ldap | LDAP bridge |
| pki-pades | PAdES PDF signing |
| pki-deploy | Deployment tools |
| pki-webhook | Webhook push |
| varwof-cli | CLI management tool |
| user-signer | Remote signing service |
| pki-hsm-proxy | HSM adapter |
| console | Web console |

## License

AGPL-3.0

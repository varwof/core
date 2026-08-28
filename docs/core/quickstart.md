# Quick Start

This guide walks you through installing Varwof Core, initializing a CA, and issuing your first certificate.

## Prerequisites

- Go 1.26+ (for building from source)
- SQLite (embedded, zero-config) or PostgreSQL/MySQL (optional)

## Installation

### From source

```bash
git clone https://github.com/varwof/core.git
cd core
go build -o pki ./cmd/pki/
```

### Via go install

```bash
go install github.com/varwof/core/cmd/pki@latest
```

### Verify

```bash
pki version
# varwof 1.1.1 linux/amd64 go1.26.x
```

## Generate Configuration

```bash
pki init-config > pki.json
```

Edit `pki.json` to set your organization name, domain, and database path. The default database is SQLite at `/etc/varwof/core/pki.db`.

Key fields to change:

```json
{
  "db": "/etc/varwof/core/pki.db",
  "serve": {
    "addr": ":8443"
  },
  "defaults": {
    "ca": "Root CA",
    "org": "My Organization",
    "country": "US"
  }
}
```

## Initialize a Root CA

```bash
pki ca init \
  --name "Root CA" \
  --key-type ecdsa-p256 \
  --validity 8760d \
  --out-cert root/ca.pem \
  --out-key root/ca.key
```

This creates:
- `root/ca.pem` — Root CA certificate (public)
- `root/ca.key` — Root CA private key (keep offline!)

## Initialize an Issuing CA

```bash
pki ca init \
  --name "Issuing CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert issuing/ca.pem \
  --out-key issuing/ca.key \
  --permitted-dns "*.example.com"
```

## Start the Server

```bash
pki serve --config pki.json
```

The server starts on `:8443` by default. Verify with:

```bash
curl http://localhost:8443/healthz
```

## Issue a Certificate

```bash
pki issue \
  --ca "Issuing CA" \
  --cn server.example.com \
  --san DNS:server.example.com,DNS:www.example.com \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --out-dir certs/ \
  --out-name server
```

This creates:
- `certs/server.pem` — Certificate
- `certs/server.key` — Private key

Verify the certificate:

```bash
openssl x509 -in certs/server.pem -text -noout
```

## Issue with Private Key Encryption

```bash
pki issue \
  --ca "Issuing CA" \
  --cn client.example.com \
  --san DNS:client.example.com \
  --profile tls-client \
  --encrypt \
  --encrypt-password "my-secret" \
  --out-dir certs/ \
  --out-name client
```

The private key is encrypted with PBES2 (PKCS#8).

## Revoke a Certificate

```bash
pki revoke --serial <serial> --ca "Issuing CA" --reason key-compromise
```

## Generate CRL

```bash
pki crl --ca "Issuing CA" --out crl.pem
```

## Next Steps

- [Configuration Reference](configuration.md) — All configuration options
- [CLI Commands](commands.md) — Complete command reference
- [API Reference](api.md) — REST API endpoints
- [Deployment Guide](deployment.md) — Production deployment
- [PKI Hierarchy](pki-hierarchy.md) — Full PKI setup with 8 sub-CAs
- [Architecture](architecture.md) — System design

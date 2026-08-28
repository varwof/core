# varwof-cli (Client)

CLI management client for the varwof PKI core system. Connects to the core CA API over mTLS or HTTP+token to perform certificate lifecycle management.

**Module**: `github.com/varwof/client`  
**License**: Apache-2.0  
**Status**: Preview

## Features

- Full certificate lifecycle: issue, revoke, renew, re-sign, query
- AIC (Agent Identity Certificate) issuance with delegation authorization
- Batch certificate issuance from JSON/CSV
- Policy file PKCS#7 signing (authz.json / routes.json)
- Self-check: closed-loop health verification
- Certificate extension inspection (AIC / PrincipalAuthorization OIDs)
- Encrypted private key support (PBES2/PBKDF2-SHA256/AES-256-CBC)
- SPIFFE ID integration
- Interactive REPL mode
- Cross-platform (Linux, macOS, Windows)

## Installation

```bash
go install github.com/varwof/client@latest
```

Or build from source:

```bash
git clone https://github.com/varwof/client.git
cd client
go build -o varwof-cli .
```

## Quick Start

### 1. Create Configuration

```json
{
  "server": "https://varwof-core:4433",
  "ca_cert": "/etc/varwof/core/root/ca.pem",
  "client_cert": "/etc/varwof/core/keys/superadmin.pem",
  "client_key": "/etc/varwof/core/keys/superadmin-key.pem"
}
```

Save as `cli-config.json`.

### 2. Issue a Certificate

```bash
varwof-cli cli-config.json issue \
  --cn server.example.com \
  --san DNS:server.example.com,DNS:www.example.com \
  --ca tls \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out certs/
```

### 3. List Certificates

```bash
varwof-cli cli-config.json list --ca tls --status valid
```

### 4. Revoke a Certificate

```bash
varwof-cli cli-config.json revoke --ca tls --serial AB12CD34 --reason keyCompromise
```

## Configuration

```json
{
  "server": "https://varwof-core:4433",
  "ca_cert": "/path/to/ca.pem",
  "client_cert": "/path/to/client.pem",
  "client_key": "/path/to/client-key.pem",
  "key_password": "optional-password",
  "token": "optional-api-token"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `server` | string | Yes | Core service URL |
| `ca_cert` | string | Yes (mTLS) | CA certificate for server verification |
| `client_cert` | string | Yes (mTLS) | Client certificate |
| `client_key` | string | Yes (mTLS) | Client private key |
| `key_password` | string | No | Private key password |
| `token` | string | Yes (HTTP) | Bearer token for plain HTTP mode |

**Authentication modes:**
- **mTLS** (`https://`): requires `ca_cert`, `client_cert`, `client_key`
- **Token** (`http://`): requires `token` only

**Password resolution:**
1. Config `key_password` field
2. `PKI_KEY_PASSWORD` environment variable
3. Interactive terminal prompt

## Commands

### Certificate Lifecycle

| Command | Description | Example |
|---------|-------------|---------|
| `issue` | Issue a certificate | `issue --cn server.example.com --ca tls --profile tls-server` |
| `revoke` | Revoke a certificate | `revoke --ca tls --serial AB12 --reason keyCompromise` |
| `renew` | Renew a certificate | `renew --ca tls --serial AB12` |
| `re-sign` | Re-sign with original key | `re-sign --ca tls --serial AB12 --target-ca tls` |
| `list` | List certificates | `list --ca tls --status valid --json` |
| `cas` | List CAs or show info | `cas --ca tls --info --pem` |
| `find-by-key` | Find by public key hash | `find-by-key --hash abc123` |

### Batch Operations

| Command | Description | Example |
|---------|-------------|---------|
| `batch` | Batch issuance from JSON/CSV | `batch --requests batch.json --fast` |
| `revoke-all` | Revoke all user certs | `revoke-all --reason keyCompromise` |
| `revoke-by-principal` | Revoke by principal UID | `revoke-by-principal --principal-uid varwof:alice:` |
| `revoke-subca` | Revoke all under sub-CA | `revoke-subca --sub-ca tls --reason keyCompromise` |

### AIC (Agent Identity Certificate)

| Command | Description | Example |
|---------|-------------|---------|
| `aic issue` | Issue AIC with delegation | `aic issue --user-cert user.pem --user-key user.key --agent agent-1 --caps "http:read"` |
| `aic batch` | Batch AIC issuance | `aic batch --config users.json --ca tls` |
| `aic list` | List users in batch config | `aic list --config users.json` |

### Utilities

| Command | Description | Example |
|---------|-------------|---------|
| `cert show` | Decode varwof extensions | `cert show --cert cert.pem` |
| `policy sign` | Sign policy file (PKCS#7) | `policy sign --file authz.json --cert admin.pem --key admin.key` |
| `selfcheck` | Smoke-test PKI | `selfcheck --ca tls` |
| `repl` | Interactive REPL | `repl` |

## Command Details

### `issue`

Issue a new certificate.

```bash
varwof-cli config.json issue \
  --cn server.example.com \
  --san DNS:server.example.com,IP:10.0.0.1 \
  --ca tls \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out certs/
```

| Flag | Description |
|------|-------------|
| `--cn` | Common Name (required) |
| `--san` | Subject Alternative Names |
| `--ca` | CA name |
| `--profile` | Certificate profile |
| `--key-type` | Key type |
| `--validity` | Validity in days |
| `--ca-scope` | CA scope for management certs |
| `--pa` | Principal authorization (`scheme:cap ...`) |
| `--out` | Output directory |
| `--subject` | Subject DN |

### `aic issue`

Issue an Agent Identity Certificate with delegation authorization.

```bash
varwof-cli config.json aic issue \
  --user-cert user.pem \
  --user-key user.key \
  --agent agent-1 \
  --caps "http:read,http:write" \
  --ca tls \
  --ou gateway:ops \
  --out certs/ \
  --spiffe \
  --spiffe-domain example.com
```

| Flag | Description |
|------|-------------|
| `--user-cert` | User certificate (required) |
| `--user-key` | User private key (required) |
| `--agent` | Agent identifier (required) |
| `--caps` | Capabilities (`scheme:cap ...`) (required) |
| `--ca` | CA name |
| `--ou` | Organizational Unit (role) |
| `--out` | Output directory |
| `--constraints` | Session constraints (`scheme:cap[:jsonparams] ...`) |
| `--spiffe` | Generate SPIFFE ID |
| `--spiffe-domain` | SPIFFE trust domain |
| `--json` | JSON output |

### `selfcheck`

Closed-loop health verification:

1. Probe `/healthz` (DB, TSA signer, CRL freshness)
2. Auto-repair CRL if degraded
3. Issue test certificate
4. Verify certificate chain
5. Revoke test certificate
6. Generate CRL
7. Download and parse CRL

```bash
varwof-cli config.json selfcheck --ca tls
```

### `policy sign`

Sign a policy file with PKCS#7 detached signature.

```bash
varwof-cli config.json policy sign \
  --file authz.json \
  --cert admin.pem \
  --key admin.key \
  --out authz.json.sig
```

The signature requires an admin-OU certificate. Self-verifies after signing.

### `repl`

Interactive REPL mode. Password entered once, all commands available interactively.

```bash
varwof-cli config.json repl
```

## Security Features

- **CL2**: Cross-host HTTP redirects blocked (prevents mTLS credential leakage)
- **CL4**: Config files must not be world-readable
- **CL5**: Plain HTTP with non-loopback server triggers warning
- **CL6**: AIC cert/key write failures surfaced (no silent drops)

## Supported Profiles

`tls-server`, `tls-client`, `code-signing`, `smime`, `ocsp-signing`, `timestamping`, `sub-ca`, `agent-proxy`, `cmp`

## Supported Key Types

`ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`, `ed25519`

## Supported Revoke Reasons

`unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`

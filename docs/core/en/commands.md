# CLI Command Reference

Binary name: `pki` (or `varwof`)

Global flags:
- `--config <path>` — Config file path (overrides auto-discovery)
- `-v, --verbose` — Enable debug logging

## Certificate Authority

### `varwof ca init`

Initialize a new CA (root or intermediate).

```bash
varwof ca init \
  --name "My CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert ca.pem \
  --out-key ca.key
```

| Flag | Description |
|------|-------------|
| `--name` | CA name (unique identifier) |
| `--profile` | CA profile: `root-ca`, `sub-ca` |
| `--parent` | Parent CA name (for sub-CAs) |
| `--parent-key` | Parent CA private key path |
| `--key-type` | `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096` |
| `--validity` | Validity duration (e.g., `3650d`, `87600h`) |
| `--out-cert` | Output certificate path |
| `--out-key` | Output private key path |
| `--password` | Encrypt private key with password |
| `--org` | Organization name |
| `--country` | Country code |
| `--permitted-dns` | Name constraint: permitted DNS |
| `--excluded-dns` | Name constraint: excluded DNS |

### `varwof ca list`

List all CAs in the database.

### `varwof ca info`

Show CA details.

```bash
varwof ca info --name "My CA"
```

### `varwof ca offline-sign`

Offline sign a sub-CA certificate (air-gapped operation).

```bash
varwof ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

### `varwof ca cold-backup`

Create encrypted cold backup of CA keys.

```bash
varwof ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json
```

## Certificate Lifecycle

### `varwof issue`

Issue a certificate (from CSR or auto-generated key).

```bash
varwof issue \
  --ca "Issuing CA" \
  --cn server.example.com \
  --san DNS:server.example.com \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --out-dir certs/ \
  --out-name server
```

| Flag | Description |
|------|-------------|
| `--ca` | CA name to issue from |
| `--cn` | Common Name |
| `--san` | Subject Alternative Names (`DNS:`, `IP:`, `URI:`, `email:`) |
| `--profile` | Certificate profile |
| `--key-type` | Key type for auto-generated key |
| `--validity` | Certificate validity |
| `--csr` | Inline CSR (PEM) |
| `--csr-file` | Path to CSR file |
| `--out-dir` | Output directory |
| `--out-name` | Output file base name |
| `--encrypt` | Encrypt private key |
| `--encrypt-password` | Password for key encryption |
| `--no-store-key` | Don't store private key in DB |
| `--must-staple` | Add OCSP must-staple extension |

SAN format examples:
```
--san DNS:example.com,DNS:www.example.com,IP:10.0.0.1,email:user@example.com
```

### `varwof renew`

Renew a certificate.

```bash
varwof renew --serial <serial> --ca "Issuing CA" --validity 365d
```

| Flag | Description |
|------|-------------|
| `--serial` | Certificate serial number |
| `--cert` | Path to certificate file (alternative to --serial) |
| `--ca` | CA name |
| `--validity` | New validity duration |
| `--keep-key` | Reuse existing private key |
| `--key-type` | New key type |

### `varwof revoke`

Revoke a certificate.

```bash
varwof revoke --serial <serial> --ca "Issuing CA" --reason key-compromise
```

Revocation reasons: `unspecified`, `key-compromise`, `ca-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation`, `certificate-hold`, `remove-from-crl`, `privilege-withdrawn`, `aa-compromise`.

### `varwof list`

List certificates.

```bash
varwof list --ca "Issuing CA" --status valid --format table
varwof list --cn server --format json --limit 10
```

### `varwof view`

View certificate details.

```bash
varwof view --serial <serial> --ca "Issuing CA"
```

## Batch Operations

### `varwof batch`

Batch-issue certificates from CSV.

```bash
varwof batch --ca "Issuing CA" --csv hosts.csv --out-dir certs/
```

CSV format:
```csv
cn,san,profile
server1.example.com,DNS:server1.example.com,tls-server
server2.example.com,DNS:server2.example.com,tls-server
```

## PKCS#7 Signing

### `varwof sign`

Sign a file with PKCS#7.

```bash
# Detached signature
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --sig document.pdf.p7s

# Embedded signature
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --embed --sig document.pdf.p7s

# CAdES-T (timestamped)
varwof sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --cades --sig document.pdf.p7s
```

### `varwof verify`

Verify a PKCS#7 signature.

```bash
varwof verify --sig document.pdf.p7s --in document.pdf
varwof verify --embed document-signed.pdf
```

### `varwof run`

Verify a binary's detached signature, then execute.

```bash
varwof run --run-ca "CodeSign CA" --sig tool.bin.p7s tool.bin
```

## Import/Export

### `varwof import`

Import certificates from OpenSSL format or PKCS#12.

```bash
# From OpenSSL index.txt
varwof import --ca "My CA" --index index.txt --cert-dir certs/

# From PKCS#12
varwof import --ca "My CA" --pfx bundle.p12 --password "secret"
```

### `varwof export`

Export certificate as PKCS#12.

```bash
varwof export --cert cert.pem --key key.pem --chain ca-chain.pem \
  --pfx out.p12 --pfx-password "secret"
```

## Key Management

### `varwof key encrypt` / `varwof key decrypt`

Encrypt/decrypt private keys.

```bash
varwof key encrypt --in plain.key --out encrypted.key --password "secret"
varwof key decrypt --in encrypted.key --out plain.key --password "secret"
```

### `varwof recover`

Recover an escrowed private key.

```bash
varwof recover --serial <serial> --ca "My CA" --admin-key admin.key --out recovered.key
```

## Server

### `varwof serve`

Start all PKI services (TSA + OCSP + Web + API).

```bash
varwof serve --config pki.json
```

| Flag | Description |
|------|-------------|
| `--config` | Config file path |
| `--reload` | Enable config hot-reload |
| `--install` | Install as Windows service |
| `--uninstall` | Uninstall Windows service |

### `varwof serve tsa`

Start TSA only (standalone).

### `varwof serve ocsp`

Start OCSP responder only (standalone).

### `varwof serve crl`

Start CRL generation + distribution.

### `varwof serve api`

Start REST API + Web UI only.

### `varwof serve dns`

Start DNS server (ACME DNS-01 + CERT + SRV records).

## User & RBAC Management

### `varwof user add`

```bash
varwof user add --username admin --password secret --role admin
varwof user add --username operator1 --password secret --role operator
```

Roles: `admin`, `operator`, `auditor`, `readonly`

### `varwof user bind-operator-cert`

Bind an operator certificate to a user (for mTLS-based CA scope).

```bash
varwof user bind-operator-cert --username operator1 --cert operator.pem
```

### `varwof token create`

```bash
varwof token create --username admin --description "CI token" --expires 720h
```

## Trust Federation

### `varwof trust bridge issue`

Cross-sign a CA to establish trust bridge.

### `varwof trust bridge list`

List existing trust bridges.

### `varwof trust import`

Import a trust anchor.

## Registration Authority

### `varwof ra submit`

Submit a CSR for approval.

```bash
varwof ra submit --cn server.example.com --san DNS:server.example.com --profile tls-server
```

### `varwof ra approve` / `varwof ra reject`

Approve or reject pending requests.

```bash
varwof ra approve --id <request-id>
varwof ra reject --id <request-id> --reason "insufficient documentation"
```

## Utilities

### `varwof version`

Print version and build info.

### `varwof init-full`

Create complete PKI hierarchy (root + 8 sub-CAs).

```bash
varwof init-full \
  --root-name "TestCorp Root CA" \
  --org "TestCorp" \
  --country CN \
  --base-dir /opt/pki
```

### `varwof init-config`

Print sample configuration to stdout.

### `varwof db init`

Initialize database (create + migrate to latest schema).

### `varwof db migrate`

Migrate schema to target version.

```bash
varwof db migrate --to 2 --dry-run
```

### `varwof db backup`

Backup database.

```bash
varwof db backup --out backup.db
```

### `varwof benchmark`

Benchmark hash and sign algorithm performance.

### `varwof report`

Generate compliance report PDF.

```bash
varwof report --type soc2 --out report.pdf
```

### `varwof cpcps`

Generate CP/CPS compliance documents (RFC 3647).

```bash
varwof cpcps --out-dir docs/ --separate-cp
```

### `varwof completion`

Generate shell completions.

```bash
varwof completion bash > /etc/bash_completion.d/pki
varwof completion zsh > ~/.zfunc/_pki
varwof completion fish > ~/.config/fish/completions/pki.fish
```

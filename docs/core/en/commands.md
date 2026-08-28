# CLI Command Reference

Binary name: `pki` (or `varwof`)

Global flags:
- `--config <path>` — Config file path (overrides auto-discovery)
- `-v, --verbose` — Enable debug logging

## Certificate Authority

### `pki ca init`

Initialize a new CA (root or intermediate).

```bash
pki ca init \
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

### `pki ca list`

List all CAs in the database.

### `pki ca info`

Show CA details.

```bash
pki ca info --name "My CA"
```

### `pki ca offline-sign`

Offline sign a sub-CA certificate (air-gapped operation).

```bash
pki ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

### `pki ca cold-backup`

Create encrypted cold backup of CA keys.

```bash
pki ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json
```

## Certificate Lifecycle

### `pki issue`

Issue a certificate (from CSR or auto-generated key).

```bash
pki issue \
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

### `pki renew`

Renew a certificate.

```bash
pki renew --serial <serial> --ca "Issuing CA" --validity 365d
```

| Flag | Description |
|------|-------------|
| `--serial` | Certificate serial number |
| `--cert` | Path to certificate file (alternative to --serial) |
| `--ca` | CA name |
| `--validity` | New validity duration |
| `--keep-key` | Reuse existing private key |
| `--key-type` | New key type |

### `pki revoke`

Revoke a certificate.

```bash
pki revoke --serial <serial> --ca "Issuing CA" --reason key-compromise
```

Revocation reasons: `unspecified`, `key-compromise`, `ca-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation`, `certificate-hold`, `remove-from-crl`, `privilege-withdrawn`, `aa-compromise`.

### `pki list`

List certificates.

```bash
pki list --ca "Issuing CA" --status valid --format table
pki list --cn server --format json --limit 10
```

### `pki view`

View certificate details.

```bash
pki view --serial <serial> --ca "Issuing CA"
```

## Batch Operations

### `pki batch`

Batch-issue certificates from CSV.

```bash
pki batch --ca "Issuing CA" --csv hosts.csv --out-dir certs/
```

CSV format:
```csv
cn,san,profile
server1.example.com,DNS:server1.example.com,tls-server
server2.example.com,DNS:server2.example.com,tls-server
```

## PKCS#7 Signing

### `pki sign`

Sign a file with PKCS#7.

```bash
# Detached signature
pki sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --sig document.pdf.p7s

# Embedded signature
pki sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --embed --sig document.pdf.p7s

# CAdES-T (timestamped)
pki sign --ca "CodeSign CA" --cert signer.pem --key signer.key \
  --in document.pdf --cades --sig document.pdf.p7s
```

### `pki verify`

Verify a PKCS#7 signature.

```bash
pki verify --sig document.pdf.p7s --in document.pdf
pki verify --embed document-signed.pdf
```

### `pki run`

Verify a binary's detached signature, then execute.

```bash
pki run --run-ca "CodeSign CA" --sig tool.bin.p7s tool.bin
```

## Import/Export

### `pki import`

Import certificates from OpenSSL format or PKCS#12.

```bash
# From OpenSSL index.txt
pki import --ca "My CA" --index index.txt --cert-dir certs/

# From PKCS#12
pki import --ca "My CA" --pfx bundle.p12 --password "secret"
```

### `pki export`

Export certificate as PKCS#12.

```bash
pki export --cert cert.pem --key key.pem --chain ca-chain.pem \
  --pfx out.p12 --pfx-password "secret"
```

## Key Management

### `pki key encrypt` / `pki key decrypt`

Encrypt/decrypt private keys.

```bash
pki key encrypt --in plain.key --out encrypted.key --password "secret"
pki key decrypt --in encrypted.key --out plain.key --password "secret"
```

### `pki recover`

Recover an escrowed private key.

```bash
pki recover --serial <serial> --ca "My CA" --admin-key admin.key --out recovered.key
```

## Server

### `pki serve`

Start all PKI services (TSA + OCSP + Web + API).

```bash
pki serve --config pki.json
```

| Flag | Description |
|------|-------------|
| `--config` | Config file path |
| `--reload` | Enable config hot-reload |
| `--install` | Install as Windows service |
| `--uninstall` | Uninstall Windows service |

### `pki serve tsa`

Start TSA only (standalone).

### `pki serve ocsp`

Start OCSP responder only (standalone).

### `pki serve crl`

Start CRL generation + distribution.

### `pki serve api`

Start REST API + Web UI only.

### `pki serve dns`

Start DNS server (ACME DNS-01 + CERT + SRV records).

## User & RBAC Management

### `pki user add`

```bash
pki user add --username admin --password secret --role admin
pki user add --username operator1 --password secret --role operator
```

Roles: `admin`, `operator`, `auditor`, `readonly`

### `pki user bind-operator-cert`

Bind an operator certificate to a user (for mTLS-based CA scope).

```bash
pki user bind-operator-cert --username operator1 --cert operator.pem
```

### `pki token create`

```bash
pki token create --username admin --description "CI token" --expires 720h
```

## Trust Federation

### `pki trust bridge issue`

Cross-sign a CA to establish trust bridge.

### `pki trust bridge list`

List existing trust bridges.

### `pki trust import`

Import a trust anchor.

## Registration Authority

### `pki ra submit`

Submit a CSR for approval.

```bash
pki ra submit --cn server.example.com --san DNS:server.example.com --profile tls-server
```

### `pki ra approve` / `pki ra reject`

Approve or reject pending requests.

```bash
pki ra approve --id <request-id>
pki ra reject --id <request-id> --reason "insufficient documentation"
```

## Utilities

### `pki version`

Print version and build info.

### `pki init-full`

Create complete PKI hierarchy (root + 8 sub-CAs).

```bash
pki init-full \
  --root-name "TestCorp Root CA" \
  --org "TestCorp" \
  --country CN \
  --base-dir /opt/pki
```

### `pki init-config`

Print sample configuration to stdout.

### `pki db init`

Initialize database (create + migrate to latest schema).

### `pki db migrate`

Migrate schema to target version.

```bash
pki db migrate --to 2 --dry-run
```

### `pki db backup`

Backup database.

```bash
pki db backup --out backup.db
```

### `pki benchmark`

Benchmark hash and sign algorithm performance.

### `pki report`

Generate compliance report PDF.

```bash
pki report --type soc2 --out report.pdf
```

### `pki cpcps`

Generate CP/CPS compliance documents (RFC 3647).

```bash
pki cpcps --out-dir docs/ --separate-cp
```

### `pki completion`

Generate shell completions.

```bash
pki completion bash > /etc/bash_completion.d/pki
pki completion zsh > ~/.zfunc/_pki
pki completion fish > ~/.config/fish/completions/pki.fish
```

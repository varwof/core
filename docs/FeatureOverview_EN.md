# varwof Feature Overview

**Project:** `pki` — All-in-One PKI Infrastructure in Go 1.26 (single binary replacing OpenSSL wrappers + Python services)
**Database:** SQLite (`modernc.org/sqlite`, pure Go without CGO) — **recommended**; PostgreSQL and MySQL/MariaDB available via Dialect dialect but community-maintained (not CI-tested for new features)
**Code Size:** ~8,300 lines (50+ `.go` source files, excluding tests and tools)

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI (24 subcommands)                     │
│ serve│issue│renew│batch│revoke│crl│sign│export│import│      │
│ init-ca│ca-list│ca-info│ct-submit│key│db│user│token│audit│  │
│ ra│recover│version│init-config│completion│pades              │
└──────┬───────────────────────────────────────────────────────┘
       │
       ├── internal/config     Config loading/merging/searching
       ├── internal/ca         CA creation, certificate issuance, CRL, revocation, RA approval, key escrow
       ├── internal/db         SQLite ORM (v1-v7 migrations)
       ├── internal/serve      HTTP server + Web UI + JSON API
       ├── internal/ocsp       OCSP responder (RFC 6960)
       ├── internal/tsa        Timestamp server (RFC 3161)
       ├── internal/pades      PAdES PDF signing
       ├── internal/pkcs7      PKCS#7/CMS SignedData (including CAdES-T with real TSA)
       ├── internal/signer     Detached/embedded file signing + verification
        ├── internal/pkcs12     PFX export (pure Go)
       ├── internal/acme       ACME v2 (RFC 8555)
       ├── internal/scep       SCEP (RFC 8894)
       ├── internal/notify     Webhook notifications
       ├── internal/rbac       RBAC + JWT authentication
       ├── internal/serve/ratelimit  Token bucket rate limiting
       ├── internal/ocsp/cache       LRU response cache
        ├── internal/ca/ldap          LDAP/AD integration
        └── internal/signer/pbes2     Private key encryption (PBKDF2 + AES-256-CBC)
               │
        ┌──────▼──────┐
        │ pki-k8s-issuer/ │  cert-manager external issuer (separate repo, k8s.io/client-go)
        │  main.go     │  watches CertificateRequest CR → POST /api/v1/k8s/sign → patch status
        │  Dockerfile  │
        │  k8s/rbac.*  │
        └─────────────┘
              ▼
         /var/lib/pki/pki.db (SQLite)
```

---

## 2. CLI Subcommands

### 2.1 `varwof serve` — Start Unified PKI Service

Provides TSA, OCSP, Web UI, REST API, ACME, and static file distribution in a single process.

| Flag | Description |
|------|-------------|
| `--config` | Configuration file path |
| `--reload` | Enable config hot-reload (10s polling) |
| `--install` | (Windows) Install as a system service |
| `--uninstall` | (Windows) Uninstall system service |

**Port Architecture:**
- `:4430` (HTTP) — Public certificate distribution, health checks, limited API (no RBAC)
- `:4433` (HTTPS) — Full functionality: TSA / OCSP / API / Web UI / ACME / SCEP (requires `tls_addr`, `tls_cert`, `tls_key`)

**Middleware Layer (HTTPS):**
- RBAC role authorization (Bearer/Basic)
- Token bucket rate limiting (`rate_limit.enabled`)
- Access log (accessLog)

**Signal Handling:**
- SIGINT/SIGTERM — Graceful shutdown
- SIGHUP — Hot-reload config (atomic.Pointer safe swap)
- `--reload` — Auto-poll `cfgFile` mtime, call `reloadConfigNow()` to rebuild handler/CRL loop

---

### 2.2 `varwof issue` — Issue Certificate

Issues a certificate from CSR or auto-generated key pair, automatically stored in the database.

| Flag | Default | Description |
|------|---------|-------------|
| `--csr` | `""` | CSR PEM file (if provided, skip key generation) |
| `--cn` | `""` | Common Name |
| `--san` | `""` | Comma-separated SANs (supports `DNS:/IP:/URI:/email:`) |
| `--profile` | config default | Certificate template (technical + management m-* profiles) |
| `--as` | `""` | Issue as management role (auto-sets OU+profile; values: admin/operator/revoker/auditor/readonly/console/auto-renew/reporter) |
| `--key-type` | config default | Key algorithm |
| `--ca` | config default | Issuing CA |
| `--validity` | 365 | Validity period in days |
| `--out` / `--out-dir` / `--out-name` / `--out-key` | — | Output paths |
| `--encrypt` | false | Output PBKDF2+AES-256-CBC encrypted private key |

**SAN Example:** `--san "DNS:example.com,DNS:www.example.com,IP:1.2.3.4"`

**Private Key Encryption:** When `--encrypt` is set, reads config `pbes2_passphrase`, PBKDF2 (SHA-256, 100k iterations) derives key, AES-256-CBC encrypts PKCS#8 DER, outputs PEM with `DEK-Info` header.

**Key Strength Enforcement (NIST SP 800-57):** Before issuance, the requesting public key strength is validated; weak keys are rejected:
- RSA < 2048 bits rejected
- EC curves restricted to NIST P-256 / P-384 / P-521; legacy curves (e.g. P-224) rejected
- Ed25519 always accepted
- Applies to all issuance paths: CLI `issue`/`batch`, CSR signing, API, AIC, sub-CA key import (`parsePrivateKey`/`ParsePrivateKey`/`DecryptKeyPKCS8`)

---

### 2.3 `varwof batch` — Batch Issuance

Batch issue certificates from a CSV file, automatically written to `{cn}.pem` / `{cn}.key`.

| Flag | Description |
|------|-------------|
| `--csv` | CSV file path (required) |
| `--ca` | Issuing CA |
| `--profile` | Certificate template |
| `--out-dir` | Output directory |

CSV Format:
```csv
cn,san
server1,server1.example.com
server2,"DNS:server2.example.com,IP:10.0.0.2"
```

---

### 2.4 `varwof renew` — Certificate Renewal

Automatically detects original certificate profile, SANs, and key type for renewal.

| Flag | Description |
|------|-------------|
| `--serial` | Original certificate serial number |
| `--ca` | CA of the original certificate |
| `--validity` | New validity period in days (default same as original) |

---

### 2.5 `varwof sign` — File Signing (PKCS#7 / CAdES-T)

Signs a file to produce a detached signature (`.p7s`) or embedded signature. Supports `--verify` and CAdES-T (real TSA timestamp).

| Flag | Description |
|------|-------------|
| `--verify` | Verification mode (default: signing mode) |
| `--embed` | Embed signature at end of file |
| `--cades` | Add CAdES-T signature timestamp unsigned attribute (requires TSA signer cert/key) |
| `--sig` | Specify signature file path for verification |
| `--cert` / `--key` / `--chain` | Manually specify signing certificate |
| `--ca` | Use CA config to auto-load signing certificate |

**CAdES-T:** With `--cades`, reads configured TSA signing certificate, computes SHA256 hash of CMS SignedData's signatureValue, builds RFC 3161 TimeStampReq, calls in-process `tsa.SignRequest` to sign, embeds unsigned attribute `id-aa-signatureTimeStampToken` (1.2.840.113549.1.9.16.2.14). Automatically skipped when no TSA is configured (outputs DER NULL placeholder).

**Embedded Signature Format:**
```
[original content]PKISIG\x00[8 hex char length][PKCS#7 DER]
```

**Verification Support:** ECDSA / RSA PKCS#1v1.5 / Ed25519 three signature algorithms, optional root certificate chain verification.

---

### 2.6 `varwof pades sign` — PDF Signing (PAdES-B)

Signs a PDF file to produce an output PDF with PAdES-B signature.

| Flag | Description |
|------|-------------|
| `<file.pdf>` | Input PDF path (required argument) |
| `--out` | Output PDF path (default: `<file>-signed.pdf`) |
| `--ca` | Use CA config to auto-load signing certificate |
| `--cert` / `--key` / `--cn` | Manually specify signing certificate, private key, Common Name |
| `--profile` | Signing certificate profile (must support digitalSignature) |
| `--config` | Configuration file path |

**Implementation:** Appends signature field via incremental update, two-step approach: reserve 16KB hex placeholder → compute ByteRange → build CMS detached signature (`/SubFilter /adbe.pkcs7.detached`) → replace placeholder. No third-party PDF library dependency.

---

### 2.7 `varwof revoke` — Revoke Certificate

| Flag | Description |
|------|-------------|
| `--serial` | Hex serial number |
| `--cert` | Certificate file (auto-extract serial number) |
| `--reason` | Revocation reason (unspecified / keyCompromise / caCompromise / ...) |
| `--ca` | CA name |

---

### 2.8 `varwof crl` — Generate CRL

| Flag | Description |
|------|-------------|
| `--out` | Output DER path (default: `{output_dir}/{ca}.crl`) |
| `--ca` | CA name |

---

### 2.9 `varwof import` — Import from OpenSSL

Compatible with OpenSSL's `index.txt` format, batch import existing certificates into database.

| Flag | Description |
|------|-------------|
| `--index` | index.txt path (default: `index.txt`) |
| `--cert-dir` | Certificate PEM directory |
| `--ca` | Assign CA name |
| `--ca-cert` | CA certificate (automatically registered in `ca_meta`) |

---

### 2.10 `varwof export` — PFX/PKCS#12 Export

Implemented in pure Go (`software.sslmate.com/src/go-pkcs12`), using Modern encoding (AES-256-CBC + SHA-256).

| Flag | Description |
|------|-------------|
| `--cert` | Certificate PEM (required) |
| `--key` | Private key PEM (required) |
| `--chain` | Chain certificate PEM |
| `--out` | Output path (required) |
| `--password` | PFX password (empty password supported) |
| `--pfx` | Must be set to true |

---

### 2.11 `varwof init-ca` — Initialize CA

Creates a root CA or sub CA, stores in database, outputs PEM files.

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | — | CA name (required) |
| `--profile` | `root-ca` | `root-ca` or `sub-ca` |
| `--parent` | `""` | Parent CA name |
| `--key-type` | config default | Key algorithm |
| `--validity` | 3650 (10 years) | Validity period in days |
| `--out-cert` / `--out-key` | — | Output PEM paths |
| `--permitted-dns` | `""` | (Sub CA) Permitted DNS suffixes |
| `--excluded-dns` | `""` | (Sub CA) Excluded DNS suffixes |
| `--no-store-key` | false | Do not store private key after issuance (offline root CA) |

---

### 2.12 `varwof ca-list` / `varwof ca-info` — CA Query

List all CAs or view single CA details (including certificate statistics distribution).

`ca-info` output fields: Name, Subject, Issuer, Serial, Algorithm, Validity, Fingerprint, Is CA, Max Path, Certificate statistics (total/revoked/expired/expiring ≤30d)

---

### 2.13 `varwof ct-submit` — CT Log Submission

Submits a certificate to a Certificate Transparency log server and obtains an SCT.

| Flag | Description |
|------|-------------|
| `--log-url` | CT log server URL |
| `--cert` | Certificate PEM file |
| `--chain` | Chain certificate PEM file |

Automatic submission after issuance: configure `ct.enabled=true` + `ct.logs` list, auto-calls `ctSubmitLogs` during issuance.

---

### 2.14 `varwof key` — Private Key Encryption/Decryption

| Subcommand | Description |
|------------|-------------|
| `varwof key encrypt --in <key.pem> --out <enc-key.pem>` | Encrypt private key |
| `varwof key decrypt --in <enc-key.pem> --out <key.pem>` | Decrypt private key |

Encryption format: PBKDF2 (SHA-256, 100k iterations, 16B random salt) → AES-256-CBC (random 16B IV) encrypts PKCS#8 DER.

---

### 2.15 `varwof recover` — Key Recovery

Decrypts previously escrowed encrypted private key using admin private key.

| Flag | Description |
|------|-------------|
| `--serial` | Certificate serial number |
| `--ca` | CA name |
| `--admin-key` | Admin private key PEM path |

---

### 2.16 `varwof user` — User Management (RBAC)

| Subcommand | Description |
|------------|-------------|
| `varwof user add --username U --role R [--password P]` | Create user |
| `varwof user list` | List all users |
| `varwof user update --username U [--role R] [--password P]` | Update user |
| `varwof user delete --username U` | Delete user |
| `varwof user bind-operator-cert --username U --cert cert.pem` | Bind an operator certificate (proxies the account's CA scope) |
| `varwof user unbind-operator-cert --username U` | Unbind the operator certificate |

Roles: `admin` / `operator` / `revoker` / `auditor` / `readonly` / `console` / `auto-renew` / `reporter`

> **Operator-cert proxy**: bind a password-login user to a scope-limited `m-*` management certificate; the user's effective CA scope then comes from that certificate (cryptographic binding). Binding validates fail-closed; expired/revoked/foreign certificates are rejected immediately.

---

### 2.17 `varwof token` — API Token Management

| Subcommand | Description |
|------------|-------------|
| `varwof token create --username U` | Create JWT API token |
| `varwof token list` | List all active tokens |
| `varwof token revoke --token T` | Revoke token |

Tokens are used for Bearer or Basic authentication in the HTTP API.

---

### 2.18 `varwof audit` — Audit Log

| Subcommand | Description |
|------------|-------------|
| `varwof audit list` | List audit logs |
| `varwof audit verify` | Verify Merkle hash chain integrity |

Integrity algorithm: `SHA256(prev_hash + "|" + timestamp + "|" + username + "|" + action + "|" + detail)`

---

### 2.19 `varwof ra` — RA Approval Workflow

| Subcommand | Description |
|------------|-------------|
| `varwof ra submit --csr F --cn N [--san ...] [--approvals N]` | Submit approval request |
| `varwof ra list [--status pending/approved/rejected/issued]` | Request list |
| `varwof ra approve --id N [--comment "..."]` | Approve (auto-issue when threshold reached) |
| `varwof ra reject --id N [--reason "..."]` | Reject |
| `varwof ra show --id N` | Request details |

M/N multi-level approval: after `required_approvals` people approve, automatically calls `ca.Sign` to issue certificate.

---

### 2.20 `varwof db backup` — Online Database Backup

```bash
varwof db backup --out /backup/pki-2024-01-01.db
```

Uses SQLite `VACUUM INTO` to create a transactionally consistent snapshot without service interruption.

---

### 2.21 `varwof version` / `varwof init-config` / `varwof completion`

```bash
varwof version           # Version + build info
varwof init-config       # Generate annotated default config file
varwof completion bash   # Generate bash completion script
```

### 2.21 `varwof deploy` — Deployment Config Generator

| Flag | Description |
|------|-------------|
| `--target` | Deployment target: `nginx`, `apache`, or `k8s-secret` |
| `--cert` | Certificate PEM file path |
| `--key` | Private key PEM file path |
| `--chain` | CA chain PEM file path (optional) |
| `--out` | Output file path (default: stdout) |
| `--secret-name` | Kubernetes Secret name (k8s-secret target) |
| `--namespace` | Kubernetes namespace (k8s-secret, default: "default") |

Examples:
```
varwof deploy --target nginx --cert server.pem --key server.key
varwof deploy --target k8s-secret --cert server.pem --key server.key \
  --secret-name myapp-tls --namespace production --out secret.yaml
```

### 2.22 `varwof report` — Compliance Report Generation

Generate audit-ready compliance report PDFs for SOC 2, PCI DSS, NIST SP 800-53, and ISO 27001 standards.

| Flag | Description |
|------|-------------|
| `--template` | Report template: `soc2`, `pci`, `nist`, `iso` (default: `soc2`) |
| `--out` | Output PDF path (default: `compliance-<template>-<date>.pdf`) |
| `--ca` | Filter by CA name (optional) |

Examples:
```
varwof report --template soc2 --out soc2-report.pdf
varwof report --template pci
varwof report --template nist --ca "Root CA"
```

The report includes:
- **Scope** — PKI infrastructure overview
- **CA Hierarchy** — Root vs. subordinate CA counts
- **Certificate Inventory** — Valid/revoked/expired counts
- **Expiry Analysis** — Certificates expiring in 30/90 days
- **Control Mapping** — Standard-specific controls with PASS/FAIL status
- **Conclusion** — Overall compliance summary

---

### 2.23 `varwof benchmark` — Cryptographic Performance Benchmark

Measure hash and signature algorithm throughput on the current hardware for capacity planning and algorithm selection.

| Flag | Default | Description |
|------|---------|-------------|
| `--algo` | All | Comma-separated algorithm filter (`sha256,sha384,sha512,rsa-2048,rsa-4096,ecdsa-p256,ecdsa-p384,ed25519`) |
| `--size` | 0 (all sizes) | Data block size in bytes; 0 runs 1KB / 2KB / 4KB / 8KB / 12KB / 16KB / 20KB / 32KB / 64KB (certificate-sized data) |
| `--duration` | 2s | Duration per round |
| `--concurrency` | 1 | Number of parallel goroutines (multi-core throughput) |
| `--json` | false | Output JSON format |

**Examples:**
```bash
varwof benchmark                              # All algorithms, 2s/round
varwof benchmark --algo ed25519,ecdsa-p256    # Ed25519 + ECDSA P-256 only
varwof benchmark --algo sha256 --size 1024    # SHA-256 only, 1KB blocks
varwof benchmark --concurrency 4              # 4-core parallel test
varwof benchmark --duration 5s --json         # 5s/round, JSON output
```

**Output format (table):**
```
Algorithm   Operation  Size  Ops/s   Latency  Throughput
─────────   ─────────  ────  ─────   ───────  ──────────
SHA256      hash       1KB   937.2K  1.0μs    915 MB/s
ED25519     sign       1KB   30.7K   32.0μs   —
```

**Supported algorithms:**
- Hash: SHA-256, SHA-384, SHA-512 (pure Go, no CGO)
- Sign: RSA-2048, RSA-4096, ECDSA P-256, ECDSA P-384, Ed25519
- Sign measurement includes key generation + sign + verify full pipeline

---

## 3. HTTP API Endpoints

### 3.1 JSON REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/cas` | List all CAs |
| GET | `/api/v1/ca/{name}` | Single CA details |
| GET | `/api/v1/certs?ca=X&status=V/R&cn=Y` | Query certificates |
| GET | `/api/v1/cert/{caName}/{serial}` | Single certificate |
| GET | `/api/v1/crl/{caName}` | CRL download (DER) |
| GET | `/api/v1/healthz` | Health check |

### 3.2 TSA Endpoint

| Method | Path | Content-Type | Description |
|--------|------|-------------|-------------|
| POST | `/tsa` | `application/timestamp-query` | RFC 3161 timestamp |
| POST | `/timestamp` | `application/timestamp-query` | Alias |

### 3.3 OCSP Endpoint

| Method | Path | Content-Type | Description |
|--------|------|-------------|-------------|
| POST | `/ocsp` | `application/ocsp-request` | OCSP request |
| GET | `/ocsp` | `?query=<base64>` | GET method OCSP |

### 3.4 ACME Endpoint (v2)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/acme` | ACME directory |
| POST | `/acme/new-nonce` | Get nonce |
| POST | `/acme/new-account` | Register account |
| POST | `/acme/new-order` | Create order |
| POST | `/acme/challenge/{id}` | HTTP-01 challenge |
| GET | `.well-known/acme-challenge/{token}` | HTTP-01 validation |
| POST | `/acme/cert/{order-id}` | Download certificate |

### 3.5 SCEP Endpoint

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scep?operation=GetCACert` | Get CA certificate |
| GET | `/scep?operation=GetNextCACert` | Get next CA certificate (CA rollover) |
| POST | `/scep?operation=PKCSReq` | Certificate request |

### 3.6 Public Port (HTTP Only)

| Path | Description |
|------|-------------|
| `/healthz`, `/readyz` | Health checks |
| `/pki/*` | Static file distribution |

---

## 4. Core Packages

### 4.1 `internal/ca` — CA Operations

| Function/File | Description |
|---------------|-------------|
| `CreateCA(cfg)` | Create root CA or sub CA, auto-generate key, store in database |
| `Sign(cfg)` | Issue certificate using CA, 20B random serial number, up to 10 retries for collision avoidance; supports IssuerAltName/SubjectInfoAccess/CertificatePolicies extensions |
| `GenerateKey(keyType)` | 5 key types (ecdsa-p256/p384, rsa-2048/4096, ed25519, sm2(需 -tags gmsm)) |
| `GenerateCRL(cfg)` | Build DER CRL from database (including InvalidityDate per-entry extension) |
| `Revoke(db, caName, serial, reason)` | Revoke certificate |
| `LoadSigner(certPath, keyPath)` | Load PEM certificate + key |
| `escrow.go` | Key escrow: AES-256-GCM + RSA-OAEP hybrid encryption |
| `ra.go` | RA approval: submit/approve/reject/list + signFn callback decoupling |
| `CertToPEM(der)` / `KeyToPEM(key)` | DER/PKCS8 → PEM |

### 4.2 `internal/db` — SQLite Database Layer

**Table: `ca_meta`**
| Column | Description |
|--------|-------------|
| `name` | Primary key, CA identifier |
| `cert_der` | DER-encoded CA certificate |
| `subject` / `not_before` / `not_after` | Certificate metadata |
| `key_algorithm` / `fingerprint` | Algorithm/fingerprint |

**Table: `certificates`**
| Column | Description |
|--------|-------------|
| `serial_number` + `ca_name` | Composite primary key |
| `status` | V=Valid, R=Revoked, E=Expired |
| `subject` / `common_name` / `cert_der` | Subject and certificate |
| `not_before` / `not_after` / `revoked_at` | Timestamps |
| `fingerprint` / `revoke_reason` / `invalidity_date` | Fingerprint/reason/invalidity date |

**Table: `users`** (v2) | **Table: `api_tokens`** (v3) | **Table: `audit_log`** (v4+v7 hash chain) | **Table: `ra_requests`** / `ra_approvals` (v6)

**Auto Migration:** v1-v9, executed automatically at startup, tracked via `user_version`.

### 4.3 `internal/pkcs7` — PKCS#7/CMS SignedData

| Function | Description |
|----------|-------------|
| `BuildSignedData(eContentType, eContent, cert, signer, chain)` | Build signed CMS |
| `BuildSignedDataWithDigest(..., hash, signatureValue)` | Explicitly specify hash algorithm + detached signature |
| `SignatureValue(eContentType, eContent, cert, signer, hash)` | Build and return CMS signatureValue DER (computes signatureValue without building complete CMS) |

**Supported Signature OIDs:**
- ECDSA: `sha256WithECDSA` / `sha384WithECDSA` / `sha512WithECDSA`
- RSA: `sha256WithRSAEncryption` / `sha384WithRSAEncryption` / `sha512WithRSAEncryption`
- Ed25519: `id-EdDSA25519`

**Hash Auto-Selection:**
| Key Type | Hash |
|----------|------|
| ECDSA P-256 / RSA 2048 | SHA-256 |
| ECDSA P-384 / RSA 4096+ | SHA-384 |
| ECDSA P-521 | SHA-512 |
| Ed25519 | No pre-hash |

**Signed Attributes:** content-type OID, messageDigest, signingCertificate (RFC 2634 ESS)

### 4.4 `internal/signer` — File Signing

| Function | Description |
|----------|-------------|
| `SignDetached(filePath, cfg)` | Create `<file>.p7s` detached signature |
| `SignEmbedded(filePath, cfg)` | Embed signature at end of file |
| `SignWithCades(filePath, cfg)` | Add CAdES-T timestamp (real TSA signature or placeholder) |
| `VerifyDetached(filePath, sigPath, rootCAs)` | Verify detached signature |
| `VerifyEmbedded(filePath, rootCAs)` | Verify embedded signature |

### 4.5 `internal/pades` — PAdES PDF Signing

| Function | Description |
|----------|-------------|
| `SignPDF(inputPath, outputPath, cfg)` | Append incremental signature field to PDF file, PAdES-B format (`/SubFilter /adbe.pkcs7.detached`) |
| `buildByteRange(inputPath)` | Compute PDF ByteRange (file size + placeholder offset) |
| `buildSignatureDictionary(start, length, contents)` | Build PDF signature object dictionary |

### 4.6 `internal/tsa` — RFC 3161 Timestamp

| Function | Description |
|----------|-------------|
| `ParseTimeStampReq(der)` | ASN.1 parse TimeStampReq |
| `BuildTimeStampReq(hash, nonce, certReq)` | Build RFC 3161 TimeStampReq DER |
| `BuildTSTInfo(req, serial)` | Build TSTInfo (configurable accuracy/ordering/policy) |
| `SignRequest(reqDER, cfg)` | Full flow: parse → TSTInfo → PKCS#7 signing |

### 4.7 `internal/ocsp` — OCSP Responder

| Function | Description |
|----------|-------------|
| `NewHandler(cfg)` | Create OCSP HTTP handler |
| `(*Handler) ServeHTTP(w, r)` | Supports POST (DER) and GET (base64) |

**Status Results:** Good / Revoked (with timestamp + reason) / Unknown

### 4.8 `internal/pkcs12` — PFX Export

Uses pure Go PKCS#12 library (Modern encoding: AES-256-CBC + SHA-256), supports empty passwords and password protection.

### 4.9 `internal/acme` — ACME v2 (RFC 8555)

| Feature | Description |
|---------|-------------|
| Directory | `/acme` returns ACME directory |
| Account | new-account registration (JWS with JWK or KID) |
| Order | new-order creation, SAN list validation |
| Challenge | HTTP-01 / DNS-01 validation |
| Authorization | "any challenge valid" per RFC 8555 §7.1.5 |
| Issuance | Full E2E flow → certificate via `ca.Sign` (tested with lego) |
| Retry-After | Challenge returns `Retry-After: 5`, authz polls with exponential backoff |
| SQLite WAL mode | `_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` prevents lock contention |

### 4.10 `internal/scep` — SCEP (RFC 8894)

| Operation | Description |
|-----------|-------------|
| GetCACert | Returns CA certificate wrapped in degenerate PKCS#7 |
| GetNextCACert | Returns next CA certificate (GET/POST), currently same as GetCACert |
| PKCSReq | Parse PKCS#7 wrapped CSR → call `ca.Sign` to issue → return CertRep |

### 4.11 `internal/notify` — Webhook Notifications

| Feature | Description |
|---------|-------------|
| Event Push | POST JSON of issue/revoke/certificate expiry events to configured URL |
| Scheduled Scan | 24h timer scans expired CAs and certificates and pushes notifications |
| Configuration | `webhook.url` + `webhook.events` list |

### 4.12 `internal/rbac` — RBAC + JWT Authentication

| Feature | Description |
|---------|-------------|
| Users | Local SQLite storage, bcrypt password hashing |
| Roles | admin / operator / revoker / auditor / readonly / console / auto-renew / reporter |
| JWT | `golang.org/x/crypto` Ed25519 signing, RBAC middleware validation |
| Auth | Bearer Token / Basic Auth both supported |

### 4.13 `internal/serve/ratelimit` — Token Bucket Rate Limiting

| Feature | Description |
|---------|-------------|
| Algorithm | `golang.org/x/time/rate` per-IP token bucket |
| Configuration | `rate_limit.enabled` / `rate` (rps) / `burst` |
| Response | HTTP 429 Too Many Requests when exceeded |
| Cleanup | Background goroutine cleans expired IP records every minute |

### 4.14 `internal/ocsp/cache` — OCSP LRU Cache

| Feature | Description |
|---------|-------------|
| Structure | Thread-safe LRU map + TTL expiry |
| Key | SHA256(OCSP request DER) |
| Configuration | `ocsp.cache_size` / `ocsp.cache_ttl` |
| Strategy | Fetch from cache before lookup, store in cache after signing |

### 4.15 `internal/ca/ldap` — LDAP/AD Integration

| Feature | Description |
|---------|-------------|
| Connection | `NewLDAPConn(cfg)` dial + bind |
| Query | `LookupLDAP(conn, cfg, username)` search BaseDN |
| Mapping | map_* config items auto-map to pkix.Name (CN/O/OU/L/ST/C/email) |
| Verification | `CheckLDAPGroupMembership(entry, groupDN)` memberOf check |
| Integration | `issue.go` auto-uses LDAP to populate Subject during issuance |

### 4.16 `pki-k8s-issuer` — cert-manager External Issuer

| Feature | Description |
|---------|-------------|
| Architecture | Separate binary using `k8s.io/client-go` dynamic informer |
| Protocol | Watches `certificaterequests.cert-manager.io/v1` CR, posts CSR to `POST /api/v1/k8s/sign`, patches status with certificate |
| Server | `internal/serve/api_k8s.go` — parses PCA/PEM CSR, calls `ca.Sign()` |
| Authentication | PKI API token via `PKI_TOKEN` env or `--pki-token` flag |
| RBAC | ClusterRole: `certificaterequests` get/list/watch/patch + `certificaterequests/status` patch |
| ClusterIssuer | Declarative `kind: ClusterIssuer` as cert-manager API gateway |
| Deployment | `pki-k8s-issuer/k8s/deployment.yaml` — single-replica Deployment in `cert-manager` namespace |

---

## 5. Certificate Templates (Profiles)

### Technical Templates

| Template | KeyUsage | ExtKeyUsage | Special Extensions |
|----------|----------|-------------|-------------------|
| `root-ca` | certSign, crlSign | — | CA:true, pathLen:1 |
| `sub-ca` | certSign, crlSign | — | CA:true, pathLen:0, CRL DP, Name Constraints (DNS/Email/URI/IP) |
| `tls-server` | digitalSignature, keyEncipherment | serverAuth, clientAuth | CRL DP, AIA (OCSP+caIssuers) |
| `tls-client` | digitalSignature | clientAuth | CRL DP, AIA (OCSP+caIssuers) |
| `ocsp-signer` | digitalSignature | OCSPSigning | CRL DP, AIA (OCSP+caIssuers) |
| `timestamp` | digitalSignature | — | CRL DP, AIA (OCSP+caIssuers), EKU timeStamping critical via ExtraExtensions |
| `codesigning` | digitalSignature | CodeSigning | CRL DP, AIA (OCSP+caIssuers) |
| `email` | digitalSignature, keyEncipherment | EmailProtection | CRL DP, AIA (OCSP+caIssuers) |
| `document` | digitalSignature, contentCommitment | — | CRL DP, AIA (OCSP+caIssuers) |
| `agent-proxy` | digitalSignature | clientAuth | CRL DP, AIA, validity ≤ 1h, AIC extension, requires at least one OU |
| `identity-user` | digitalSignature, keyEncipherment | emailProtection, clientAuth | CRL DP, AIA — person base identity certificate issued from an identity source (Phase 2); CN/OU/email auto-filled from bridge-ldap/bridge-oauth, optional PA extension |

**All EE profiles include BasicConstraints CA:FALSE.**

**All EE profiles support optional extensions:** IssuerAltName (2.5.29.18), SubjectInfoAccess (1.3.6.1.5.5.7.1.11), CertificatePolicies (2.5.29.32), configured via `defaults.issuer_alt_names`/`subject_info_access`/`policy_oids`.

### Management Certificate Templates (m-*)

Built-in PKI management role presets that auto-set `OU=<role>` + `ClientAuth EKU` + `DigitalSignature KU`. Use the `--as` shortcut — no need to manually pass subject.

| Template | OU | Role | Recommended Use |
|----------|-----|------|-----------------|
| `m-admin` | admin | admin | Super admin mTLS cert |
| `m-operator` | operator | operator | Operations mTLS cert |
| `m-revoker` | revoker | revoker | Revocation-only mTLS cert |
| `m-auditor` | auditor | auditor | Audit mTLS cert |
| `m-readonly` | readonly | readonly | Monitoring/viewer mTLS cert |
| `m-console` | console | console | Web Console backend service cert |
| `m-auto-renew` | auto-renew | auto-renew | Automated renewal bot mTLS cert |
| `m-reporter` | reporter | reporter | Report generation mTLS cert |
| `m-subadmin` | sub-admin | — | Sub-CA admin (CA=true, CertSign, `--scope` writes OID extension) |

**Example:**
```bash
varwof issue --ca "Issuing CA" --as admin --cn "Alice Admin" --out alice.pem
varwof issue --ca "Issuing CA" --as auto-renew --cn "k8s-renewer" --out renew-bot.pem
varwof issue --ca "Issuing CA" --profile m-subadmin --scope "Agent CA" --cn "Agent CA Admin" --out agent-admin.pem
```

---

## 6. Key Type Support Matrix

| Operation | ecdsa-p256 | ecdsa-p384 | rsa-2048 | rsa-4096 | ed25519 |
|-----------|:----------:|:----------:|:--------:|:--------:|:-------:|
| Key Generation | ✓ | ✓ | ✓ | ✓ | ✓ |
| Certificate Issuance | ✓ | ✓ | ✓ | ✓ | ✓ |
| PKCS#7 Signing | ✓ | ✓ | ✓ | ✓ | ✓ |
| PKCS#7 Verification | ✓ | ✓ | ✓ | ✓ | ✓ |
| OCSP Signing | ✓ | ✓ | ✓ | ✓ | ✓ |
| TSA Signing | ✓ | ✓ | ✓ | ✓ | ✓ |
| PFX Export | ✓ | ✓ | ✓ | ✓ | ✓ |
| Hash | SHA-256 | SHA-384 | SHA-256/384 | SHA-384 | No pre-hash |

---

## 7. Configuration Guide

### 7.1 Configuration Search Order

1. `./pki.json` (current directory)
2. `~/.config/pki/pki.json`
3. `/etc/varwof/core/pki.json` (Linux) or `%PROGRAMDATA%\varwof\core\pki.json` (Windows)

Can be overridden with `--config <path>`.

### 7.2 Complete Configuration Structure

```jsonc
{
  "db": "/var/lib/pki/pki.db",
  "cas": {
    "root":    { "cert": "...", "key": "..." },
    "issuing": { "cert": "...", "key": "...", "chain": "..." },
    "tsa":     { "cert": "...", "key": "..." },
    "codesign":{ "cert": "...", "key": "..." }
  },
  "tsa": {
    "signer_cert": "...",
    "signer_key":  "...",
    "chain":       "...",
    "tsa_policy":  "2.16.840.1.113733.1.9.2",
    "ordering":    false,
    "accuracy_seconds": 1,
    "accuracy_millis": 0,
    "accuracy_micros": 0
  },
  "ocsp": {
    "signer_cert": "...",
    "signer_key":  "..."
  },
  "serve": {
    "addr":     ":4430",
    "tls_addr": ":4433",
    "tls_cert": "...",
    "tls_key":  "..."
  },
  "defaults": {
    "ca":       "issuing",
    "profile":  "tls-server",
    "key_type": "ecdsa-p256",
    "hash":     "sha256",
    "ocsp_url":   "http://pki.example.com/ocsp",
    "issuer_url": "http://pki.example.com/ca.pem",
    "issuer_alt_names":   [],
    "subject_info_access": [],
    "policy_oids":        []
  },
  "crl": {
    "validity_days": 30,
    "output_dir":    "/etc/varwof/core/crls",
    "crl_base_url":  "http://pki.example.com/api/v1/crl",
    "auto_renew":    true
  },
  "webhook": {
    "url":    "https://hooks.example.com/pki",
    "events": ["issue", "revoke", "expiry"]
  },
  "ct": {
    "enabled": true,
    "logs": [{"url": "https://ct.example.com/2025", "key": "base64key..."}]
  },
  "rbac": {
    "enabled": true,
    "jwt_secret": "CHANGE_ME"
  },
  "ra": {
    "required_approvals": 2,
    "default_ca": "issuing",
    "default_profile": "tls-server"
  },
  "pbes2_passphrase": "CHANGE_ME",
  "key_escrow": {
    "admin_public_key": "/etc/varwof/core/escrow/admin.pub.pem"
  }
}
```

### 7.3 Merge Rules

`DefaultConfig()` → `SearchConfigPath()` → `CLI --config` → subcommand `--config`, deep-merged each time with `MergeConfig(base, override)`, non-empty fields override.

---

## 8. Cross-Platform Support

### Windows
- Service management: `varwof serve --install` / `--uninstall`
- `serve_windows.go` uses `golang.org/x/sys/windows/svc`
- Service name: `pki`, auto-start, uses `%PROGRAMDATA%` paths

### Unix
- `serve_unix.go` uses `signal.Notify` to listen for SIGINT/SIGTERM/SIGHUP
- `atomic.Pointer` safe swap for config/DB/TSA/OCSP handler

---

## 9. DB Migration History

| Version | Additions |
|---------|-----------|
| v1 | Initial schema: `ca_meta`, `certificates` |
| v2 | `users` table + `serial_counter` |
| v3 | `api_tokens` table |
| v4 | `audit_log` table |
| v5 | Added `escrow_data` column to `certificates` |
| v6 | `ra_requests`, `ra_approvals` tables |
| v7 | Added `entry_hash`, `prev_hash` columns to `audit_log` |
| v9 | Added `invalidity_date` column to `certificates` (RFC 5280 InvalidityDate CRL extension) |

---

## 10. E2E Validation Status

| Validation Item | Method | Status |
|-----------------|--------|--------|
| init-ca root | `openssl verify` | ✓ |
| init-ca sub-ca | `openssl verify -CAfile root.pem sub.pem` | ✓ |
| TSA reply | `openssl ts -reply` / `-verify` | ✓ |
| OCSP good | `openssl ocsp -issuer ... -cert ...` | ✓ |
| OCSP revoked | Query status after revocation | ✓ |
| CRL | HTTP API returns valid DER | ✓ |
| Issue + chain | `openssl verify -CAfile ... -untrusted ...` | ✓ |
| CodeSign PKCS#7 | Go VerifyDetached / VerifyEmbedded | ✓ |
| CodeSign openssl | `openssl cms -verify` | ✓ |
| CAdES-T (real TSA) | CMS with `id-aa-signatureTimeStampToken` unsigned attribute | ✓ |
| PAdES-B PDF signing | Adobe Reader / Go verify PDF signature field | ✓ |
| PFX export | `pkcs12.DecodeChain` pure Go | ✓ |
| SCEP | Go test (GetCACert + GetNextCACert + PKCSReq) | ✓ |
| RBAC | Bearer/Basic auth + role authorization | ✓ |
| LDAP integration | Auto-populate Subject during issuance | ✓ |
| Rate limiting | 429 Too Many Requests | ✓ |
| OCSP cache | Cache hit/expiry | ✓ |
| RA approval | Submit → M/N approval → auto-issue | ✓ |
| Audit integrity | `varwof audit verify` full chain validation | ✓ |
| Private key encryption | `varwof key encrypt/decrypt` round-trip | ✓ |
| DB backup | VACUUM INTO consistent snapshot | ✓ |
| Config hot-reload | `varwof serve --reload` mtime detection | ✓ |
| Windows cross-compile | `GOOS=windows` build | ✓ |
| RFC 5280 serial 20B | `openssl x509 -serial` length 40 hex chars | ✓ |
| AIA caIssuers | `openssl x509 -text -certopt ext` check AIA | ✓ |
| Name Constraints all forms | `openssl x509 -text` DNS/Email/URI/IP | ✓ |
| CRL InvalidityDate | `openssl crl -text` per-entry extension | ✓ |
| IssuerAltName | `openssl x509 -text` Issuer Alt Name | ✓ |
| SubjectInfoAccess | `openssl x509 -text` Subject Info Access | ✓ |
| CertificatePolicies | `openssl x509 -text` Policies | ✓ |

---

## 11. Test Coverage (~550+ test cases, 35 test files, 72.6% coverage)

| Package | Tests | Coverage Content |
|---------|-------|------------------|
| root CLI | 16 | sign/export/init-ca/revoke/issue/crl + error paths |
| `internal/ca` | 16 | Create root/sub CA, issuance, CRL, revocation, 5 key types |
| `internal/db` | 15 | cert CRUD, ca_meta CRUD |
| `internal/serve` | 16 | Route dispatch, JSON API, MIME dispatch, WebUI |
| `internal/pkcs7` | 14 | BuildSignedData, WithChain, CAdES-T, various OIDs |
| `internal/signer` | 10 | sign/verify detached/embedded/chain/tamper |
| `internal/tsa` | 8 | Parse, TSTInfo, Policy QIs |
| `internal/ocsp` | 4 | Cache, Good, Unknown, BadRequest |
| `internal/pkcs12` | 5 | Basic/password/chain |
| `internal/config` | 6 | Default config, loading, merging |
| `internal/scep` | 3 | GetCACert, GetNextCACert, PKCSReq |
| `internal/ca` (ldap) | 1 | nil cfg safe path |
| `internal/pades` | 4 | BuildByteRange, BuildSignatureDictionary, SignPDF (including error paths) |

**All pass** `go vet ./...` and `go test -count=1 ./...`

## 16. Internationalization (i18n)

The system supports English and Chinese, negotiated via the HTTP `Accept-Language` header.

**Language detection priority:**
1. Config file `locale` field (e.g. `"locale": "zh"`)
2. HTTP `Accept-Language` header
3. Default `en`

**Coverage:**
| Area | Languages | Notes |
|------|-----------|-------|
| CLI output | EN/ZH | Error messages, prompts |
| Web UI | EN/ZH | Login, navigation, dashboard, issue form, admin panel |
| API errors | EN | Currently English only |

**Translation files:** `internal/i18n/locales/{en,zh}.json`, JSON key-value format.

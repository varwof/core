# PKI Quick Setup and Full-Feature Verification Guide

> Version: 1.0
> Date: 2026-07-24
> Goal: build a three-tier/four-tier PKI system from scratch and complete enterprise-grade certificate issuance within 5 minutes

---

## 1. Command Quick Reference

### Initialization

| Command | Purpose |
|---------|---------|
| `varwof init-full -out-dir ./pki -org MyCorp -domain mycorp.com -hierarchy simple -root-validity 7300` | Build a three-tier PKI from scratch (Root → Sub CA → end-entity) |
| `varwof init-full -out-dir ./pki -org MyCorp -domain mycorp.com -hierarchy enterprise -root-validity 7300` | Build a four-tier PKI from scratch (Root → Policy → Sub CA → end-entity) |
| `varwof init-ca -name "My CA" -profile sub-ca -parent "My Root CA"` | Create a single CA certificate standalone |
| `varwof init-config --out pki.json` | Generate a sample configuration file |

### Certificate Issuance

| Command | Purpose |
|---------|---------|
| `varwof issue --ca "MyCorp TLS CA" --cn web.example.com --san "DNS:web.example.com,IP:10.0.0.1,email:admin@example.com" --profile tls-server` | Issue a TLS server certificate (with SANs: DNS/IP/email) |
| `varwof issue --ca "MyCorp TLS CA" --cn user@example.com --profile tls-client` | Issue a TLS client certificate |
| `varwof issue --ca "MyCorp VPN CA" --cn vpn.example.com --profile vpn-server` | Issue a VPN server certificate |
| `varwof issue --ca "MyCorp VPN CA" --cn mobile-user --profile vpn-client` | Issue a VPN client certificate |
| `varwof issue --ca "MyCorp CodeSign CA" --cn dev@example.com --profile codesigning` | Issue a code-signing certificate |
| `varwof issue --ca "MyCorp TSA CA" --cn tsa.example.com --profile timestamp` | Issue a timestamping certificate |
| `varwof issue --ca "MyCorp TLS CA" --cn ocsp.example.com --profile ocsp-signer` | Issue an OCSP responder certificate |
| `varwof issue --ca "MyCorp Management CA" --cn admin@example.com --profile m-admin` | Issue an administrator certificate |
| `varwof batch --csv batch.csv` | Batch issuance (CSV format) |

### Certificate Lifecycle

| Command | Purpose |
|---------|---------|
| `varwof list --ca "MyCorp TLS CA"` | List all certificates under a CA |
| `varwof renew --cert path/to/cert.pem` | Renew a certificate |
| `varwof revoke --ca "MyCorp TLS CA" --serial <HEX> --reason keyCompromise` | Revoke a certificate |
| `varwof crl --ca "MyCorp TLS CA" --out myca.crl` | Generate a CRL |
| `varwof crl-verify -in myca.crl -cacert ca.pem` | Verify a CRL signature |
| `varwof export --cert cert.pem --key key.pem --pfx cert.pfx` | Export PFX (PKCS#12) |
| `varwof auto-renew --once` | Run auto-renewal once |

### Key Management

| Command | Purpose |
|---------|---------|
| `varwof key encrypt --in key.pem --out key.enc` | Encrypt a private key (PBKDF2 + AES-256-CBC) |
| `varwof key decrypt --in key.enc --out key.pem` | Decrypt a private key |

### PKCS#7 Signing

| Command | Purpose |
|---------|---------|
| `varwof sign --ca "MyCorp CodeSign CA" --in file.bin --out file.bin.p7s` | PKCS#7 detached signature |
| `varwof sign --embed --ca "MyCorp CodeSign CA" --in file.bin` | PKCS#7 embedded signature |
| `varwof sign --verify --in file.bin --sig file.bin.p7s` | Verify a detached signature |
| `varwof verify --embed --in file.bin` | Verify an embedded signature |

### RBAC and Users

| Command | Purpose |
|---------|---------|
| `varwof user add --name alice --password <pass> --role admin` | Add a user |
| `varwof user list` | List users |
| `varwof user passwd --name alice` | Change password |
| `varwof rbac mode -enterprise` | Switch RBAC to enterprise mode |
| `varwof rbac scope --list` | View RBAC scopes |

### Trust Anchors

| Command | Purpose |
|---------|---------|
| `varwof trust import --file root-ca.pem` | Import a trust anchor |
| `varwof trust list` | List trust anchors |
| `varwof trust info --hash <hash>` | Trust anchor details |
| `varwof trust trust/untrust --hash <hash>` | Mark trusted/untrusted |

### Cross Certificates

| Command | Purpose |
|---------|---------|
| `varwof cross-cert issue --issuer "MyCorp Root CA" --subject "Their Root CA"` | Issue a cross certificate |
| `varwof cross-cert list` | List cross certificates |
| `varwof trust-bridge issue --ca "MyCorp Root CA"` | Establish a trust bridge |

### Services

| Command | Purpose |
|---------|---------|
| `varwof serve` | Start all services (API+TSA+OCSP+Web) |
| `varwof serve api` | Start the API + Web UI as a standalone service (HTTP) |
| `varwof serve tsa` | Start the TSA timestamping service (HTTP, port :3180) |
| `varwof serve ocsp` | Start the OCSP responder service (HTTP, port :9080) |
| `varwof serve crl` | Start the CRL distribution service (HTTP, port :8081) |

### Utilities

| Command | Purpose |
|---------|---------|
| `varwof version` | Version information |
| `varwof db backup --out backup.db` | Online database backup |
| `varwof db migrate` | Database migration |
| `varwof report --template soc2 --out report.pdf` | Generate a SOC 2 compliance report |
| `varwof init-config` | Generate sample configuration |
| `varwof ca list` | List all CAs |
| `varwof ca info --name "MyCorp Root CA"` | CA details |

---

## 2. Building a Three-Tier PKI from Scratch

### 2.1 Initialization

```bash
mkdir -p /opt/pki && cd /opt/pki
varwof init-full \
  -out-dir /opt/pki \
  -org ExampleCorp \
  -domain example.com \
  -hierarchy simple \
  -root-validity 7300 \
  -root ecdsa-p384 \
  -default-key-type ecdsa-p256
```

Generated layout:

```
/opt/pki/
├── pki.json              # Configuration file
├── pki.db                # SQLite database
├── root/                 # Root CA (20 years)
│   ├── certs/ca.pem
│   └── private/ca.key
├── management/           # Management sub-CA (10 years)
│   ├── certs/ca.pem
│   ├── private/ca.key
│   └── users/certs/      # Administrator certificates (5)
│       ├── admin.pem
│       ├── operator.pem
│       ├── auditor.pem
│       ├── readonly.pem
│       └── auto-renew.pem
├── tls/                  # TLS sub-CA (10 years)
│   ├── certs/ca.pem
│   └── private/ca.key
│   └── api/certs/api.pem         # Gateway certificate
│   └── gateway/certs/gateway.pem # Service certificate
│   └── ocsp/certs/ocsp.pem       # OCSP responder
├── agent/                # Agent sub-CA
├── codesign/             # Code-signing sub-CA
├── tsa/                  # Timestamping sub-CA
│   └── tsa/certs/tsa-signer.pem
├── hr/                   # HR sub-CA
├── vpn/                  # VPN sub-CA
└── acme/                 # ACME auto-enrollment sub-CA
```

### 2.2 Hierarchy

```
ExampleCorp Root CA (no pathLen constraint, ECDSA P-384, 20 years)
  │
  ├── ExampleCorp Management CA (pathLen=1, ECDSA P-256, 10 years)
  │   ├── admin@example.com      (m-admin, clientAuth)
  │   ├── operator@example.com   (m-operator, clientAuth)
  │   ├── auditor@example.com    (m-auditor, clientAuth)
  │   ├── readonly@example.com   (m-readonly, clientAuth)
  │   └── auto-renew@example.com (m-auto-renew, clientAuth)
  │
  ├── ExampleCorp TLS CA (pathLen=1, ECDSA P-256, 10 years)
  │   ├── api.example.com          (tls-server, serverAuth+clientAuth)
  │   ├── gateway.example.com      (tls-server, serverAuth+clientAuth)
  │   ├── ocsp.example.com         (ocsp-signer, OCSP Signing)
  │   └── can issue any TLS client/server certificates
  │
  ├── ExampleCorp Agent CA (pathLen=1, ECDSA P-256, 10 years)
  ├── ExampleCorp CodeSign CA (pathLen=1, RSA 4096, 10 years)
  ├── ExampleCorp TSA CA (pathLen=1, RSA 4096, 10 years)
  ├── ExampleCorp HR CA (pathLen=1, ECDSA P-256, 10 years)
  ├── ExampleCorp VPN CA (pathLen=1, ECDSA P-256, 10 years)
  └── ExampleCorp ACME CA (pathLen=1, ECDSA P-256, 10 years)
```

### 2.3 Issuing the Certificates an Enterprise Needs

```bash
# 1) TLS server certificate (web server)
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "www.example.com" \
  --san "DNS:www.example.com,DNS:api.example.com,IP:10.0.0.1" \
  --profile tls-server \
  --out /opt/pki/certs/www.pem

# 2) Microservice certificate (internal mTLS)
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "svc-order.internal" \
  --san "DNS:svc-order.internal,DNS:localhost" \
  --profile tls-server \
  --out /opt/pki/certs/svc-order.pem

# 3) Developer client certificate
varwof issue --ca "ExampleCorp Management CA" \
  --cn "zhangsan@example.com" \
  --profile m-admin \
  --out /opt/pki/certs/zhangsan.pem

# 4) Operations client certificate
varwof issue --ca "ExampleCorp Management CA" \
  --cn "lisi@example.com" \
  --profile m-operator \
  --out /opt/pki/certs/lisi.pem

# 5) Auditor certificate
varwof issue --ca "ExampleCorp Management CA" \
  --cn "auditor@example.com" \
  --profile m-auditor \
  --out /opt/pki/certs/auditor.pem

# 6) VPN client
varwof issue --ca "ExampleCorp VPN CA" \
  --cn "mobile-user-1" \
  --profile vpn-client \
  --out /opt/pki/certs/vpn-user1.pem

# 7) VPN server
varwof issue --ca "ExampleCorp VPN CA" \
  --cn "vpn.example.com" \
  --profile vpn-server \
  --out /opt/pki/certs/vpn-server.pem

# 8) Code signing
varwof issue --ca "ExampleCorp CodeSign CA" \
  --cn "devops@example.com" \
  --profile codesigning \
  --out /opt/pki/certs/codesign.pem

# 9) S/MIME email certificate
varwof issue --ca "ExampleCorp TLS CA" \
  --cn "user@example.com" \
  --san "email:user@example.com" \
  --profile email \
  --out /opt/pki/certs/smime.pem
```

---

## 3. Building a Four-Tier PKI from Scratch

### 3.1 Initialization

```bash
mkdir -p /opt/pki-enterprise && cd /opt/pki-enterprise
varwof init-full \
  -out-dir /opt/pki-enterprise \
  -org BigCorp \
  -domain bigcorp.com \
  -hierarchy enterprise \
  -root-validity 7300 \
  -root ecdsa-p384
```

### 3.2 Hierarchy

```
BigCorp Root CA (no pathLen constraint, ECDSA P-384, 20 years)
  │
  └── BigCorp Policy CA (pathLen=2, ECDSA P-384, 10 years)  ← policy buffer tier
        │
        ├── BigCorp Management CA (pathLen=1, ECDSA P-256, 5 years)
        ├── BigCorp TLS CA       (pathLen=1)
        ├── BigCorp Agent CA     (pathLen=1)
        ├── BigCorp CodeSign CA  (pathLen=1)
        ├── BigCorp TSA CA       (pathLen=1)
        ├── BigCorp HR CA        (pathLen=1)
        ├── BigCorp VPN CA       (pathLen=1)
        └── BigCorp ACME CA      (pathLen=1)
```

The Policy CA is the only difference between four-tier and three-tier—it acts as a policy buffer: once the Root CA is kept offline, the Policy CA can adjust sub-CA policies without touching the Root.

### 3.3 Issuing Certificates (same as three-tier)

```bash
# Note: pass the sub-CA name to --ca; the path gains an extra policy tier
varwof issue --ca "BigCorp TLS CA" \
  --cn "web.bigcorp.com" \
  --san "DNS:web.bigcorp.com,IP:10.10.0.1" \
  --profile tls-server \
  --out /opt/pki-enterprise/certs/web.pem

# Chain verification requires the full chain
openssl verify \
  -CAfile /opt/pki-enterprise/root/certs/ca.pem \
  -untrusted /opt/pki-enterprise/policy/certs/ca.pem \
  -untrusted /opt/pki-enterprise/tls/certs/ca.pem \
  /opt/pki-enterprise/certs/web.pem
```

---

## 4. Certificate Verification Quick Reference

### OpenSSL

```bash
# Chain verification (three-tier)
openssl verify -CAfile root/certs/ca.pem \
  -untrusted tls/certs/ca.pem \
  certs/server.pem

# Chain verification (four-tier)
openssl verify -CAfile root/certs/ca.pem \
  -untrusted policy/certs/ca.pem \
  -untrusted tls/certs/ca.pem \
  certs/server.pem

# View certificate details
openssl x509 -in cert.pem -noout -text \
  | grep -E "Subject:|Issuer:|Not Before|Not After|CA:|AIA|CRL|SAN|EKU|Key Usage"

# CRL signature verification
openssl crl -CAfile ca.pem -in crl.crl -noout -verify

# TSA timestamp verification
openssl ts -verify -data file.txt -in response.tsr \
  -CAfile root/certs/ca.pem \
  -untrusted tsa/certs/ca.pem

# OCSP query
openssl ocsp -issuer tls/certs/ca.pem \
  -cert certs/server.pem \
  -url http://127.0.0.1:9080/ocsp \
  -verify_other tls/ocsp/certs/ocsp.pem \
  -CAfile tls/certs/ca.pem -trust_other
```

### Java Keytool

```bash
# Import the trust chain
keytool -importcert -trustcacerts -alias root \
  -file root/certs/ca.pem \
  -keystore truststore.jks -storepass changeit -noprompt

keytool -importcert -trustcacerts -alias sub \
  -file tls/certs/ca.pem \
  -keystore truststore.jks -storepass changeit -noprompt

# View a certificate
keytool -printcert -file cert.pem
```

### NSS certutil

```bash
# Create an NSS DB
mkdir -p /tmp/nssdb
certutil -d sql:/tmp/nssdb -N --empty-password

# Import the trust chain
certutil -d sql:/tmp/nssdb -A -t "CT,CT,CT" -n "Root CA" -i root/certs/ca.pem
certutil -d sql:/tmp/nssdb -A -t "CT,CT,CT" -n "Sub CA" -i tls/certs/ca.pem

# Verify a server certificate
certutil -d sql:/tmp/nssdb -A -t "u,u,u" -n "server" -i cert.pem
certutil -d sql:/tmp/nssdb -V -n "server" -u "V"

# Verify a client certificate
certutil -d sql:/tmp/nssdb -V -n "client" -u "C"
```

---

## 5. Architecture Selection Guidance

| Scenario | Recommended Tier | Rationale |
|----------|------------------|-----------|
| Startups (<50 people) | Three-tier (simple) | Simple; Root CA signs sub-CAs directly |
| SMBs (50–500 people) | Three-tier (simple) | Sufficient |
| Large enterprises (>500 people) | Four-tier (enterprise) | Policy CA buffers policy; Root CA can stay offline |
| Financial institutions / regulated | Four-tier (enterprise) | Compliance requirements, audit traceability, policy isolation |
| Multi-datacenter / multinational | Four-tier (enterprise) | Independent Policy CA per region |

### Key Size Recommendations

| Use | Recommended Algorithm | Validity |
|-----|-----------------------|----------|
| Root CA | ECDSA P-384 | 20 years |
| Policy CA (enterprise) | ECDSA P-384 | 10 years |
| Sub-CA | ECDSA P-256 | 5–10 years |
| TLS server certificate | ECDSA P-256 | 1 year |
| Administrator certificate | ECDSA P-256 | 1 year |
| Code signing | RSA 4096 | 3 years |
| TSA signer | RSA 4096 | 5 years |

---

## 6. Service Deployment

### Start All Services

```bash
# Edit the config and confirm ports
vim pki.json
# serve.addr: ":4430"        # HTTP API
# serve.tls_addr: ":4433"    # HTTPS mTLS API
# tsa.addr: ":3180"          # TSA
# ocsp.addr: "127.0.0.1:9080" # OCSP
# crl.addr: ":8081"          # CRL distribution

# Start
varwof serve
```

### Split Deployment (recommended)

```bash
# API + Web UI (public-facing)
varwof serve api

# TSA timestamping (separate port)
varwof serve tsa

# OCSP responder (internal)
varwof serve ocsp

# CRL distribution (plain HTTP)
varwof serve crl
```

### nginx Reverse Proxy Example

```nginx
server {
    listen 80;
    server_name pki.example.com;

    # CRL distribution - plain HTTP
    location /crl/ {
        proxy_pass http://127.0.0.1:8081;
    }

    # OCSP responses
    location /ocsp/ {
        proxy_pass http://127.0.0.1:9080;
    }
}

server {
    listen 443 ssl;
    server_name pki.example.com;

    ssl_certificate /opt/pki/tls/api/certs/api.pem;
    ssl_certificate_key /opt/pki/tls/api/private/api.key;

    # mTLS management API (administrator certificates)
    location /api/ {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

---

## 7. FAQ

### Q: Why doesn't CRL distribution use HTTPS?

CRLs are distributed over plain HTTP for compatibility with all clients. RFC 5280 allows CRL distribution over HTTP. The CRL itself is signed, so tamper protection does not depend on the transport layer.

### Q: What are the AIA/CRLDP addresses in issued certificates?

Issued certificates automatically embed:
- **OCSP URL**: `http://ocsp.<domain>/ocsp` — online revocation queries
- **Issuer URL**: `http://<domain>/pki` — issuer certificate download
- **CRL DP**: `http://<domain>/crl/<sub-ca-name>.crl` — CRL download location

All use HTTP to ensure compatibility.

### Q: Where are expired certificates?

They are retained permanently in the database. The CRL contains only revoked certificates that have not yet expired (`not_after >= now`). Expired certificates are excluded from the CRL but remain visible via `varwof list`.

### Q: Why does the Root CA have no pathLen limit?

Per the X.509 specification, Root CAs have no pathLen limit (CA:TRUE suffices, with no pathlen constraint); limits are imposed level by level by the Policy CA / sub-CAs.

### Q: How to store the Root CA key offline?

```bash
varwof ca cold-backup backup \
  --key /opt/pki/root/private/ca.key \
  --out /backup/root-key.enc
```

See `dev-docs/RootKeySecurity_CN.md` for details.

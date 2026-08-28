# PKI Hierarchy Setup

This guide covers setting up a full PKI hierarchy with root CA and business sub-CAs.

## Quick Setup (init-full)

The fastest way to create a complete PKI:

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --root-key-type ecdsa-p256 \
  --root-validity 8760d \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki \
  --encrypt-keys
```

This creates:

```
/opt/pki/
├── root/
│   ├── certs/ca.pem          Root CA certificate
│   └── private/ca.key        Root CA private key
├── management/
│   ├── certs/ca.pem          Management CA
│   └── private/ca.key
├── tls/
│   ├── certs/ca.pem          TLS Server CA
│   └── private/ca.key
├── people/
│   ├── certs/ca.pem          People/User CA
│   └── private/ca.key
├── codesign/
│   ├── certs/ca.pem          Code Signing CA
│   └── private/ca.key
├── tsa/
│   ├── certs/ca.pem          TSA CA
│   └── private/ca.key
├── hr/
│   ├── certs/ca.pem          HR CA
│   └── private/ca.key
├── vpn/
│   ├── certs/ca.pem          VPN CA
│   └── private/ca.key
├── acme/
│   ├── certs/ca.pem          ACME CA
│   └── private/ca.key
├── server.pem                Server TLS certificate
├── server.key                Server TLS private key
└── pki.json                  Configuration file
```

## Manual Setup

### Step 1: Initialize Root CA

```bash
pki ca init \
  --name "Root CA" \
  --key-type ecdsa-p256 \
  --validity 8760d \
  --out-cert root/ca.pem \
  --out-key root/ca.key
```

### Step 2: Initialize Sub-CAs

```bash
# TLS Server CA
pki ca init \
  --name "TLS CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert tls/ca.pem \
  --out-key tls/ca.key \
  --permitted-dns "*.example.com"

# People CA
pki ca init \
  --name "People CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type ecdsa-p256 \
  --validity 3650d \
  --out-cert people/ca.pem \
  --out-key people/ca.key

# Code Signing CA
pki ca init \
  --name "CodeSign CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --key-type rsa-4096 \
  --validity 3650d \
  --out-cert codesign/ca.pem \
  --out-key codesign/ca.key
```

### Step 3: Configure `pki.json`

```json
{
  "cas": {
    "root": {
      "cert": "/opt/pki/root/certs/ca.pem",
      "key": "/opt/pki/root/private/ca.key"
    },
    "tls": {
      "cert": "/opt/pki/tls/certs/ca.pem",
      "key": "/opt/pki/tls/private/ca.key"
    },
    "people": {
      "cert": "/opt/pki/people/certs/ca.pem",
      "key": "/opt/pki/people/private/ca.key"
    },
    "codesign": {
      "cert": "/opt/pki/codesign/certs/ca.pem",
      "key": "/opt/pki/codesign/private/ca.key"
    }
  },
  "defaults": {
    "ca": "tls",
    "profile": "tls-server"
  }
}
```

### Step 4: Start Server

```bash
pki serve --config pki.json
```

## CA Roles and Purposes

| CA | Purpose | Key Type | Validity |
|----|---------|----------|----------|
| Root CA | Trust anchor, signs sub-CAs | ECDSA P-256 | 10 years |
| TLS CA | Server/client TLS certificates | ECDSA P-256 | 5 years |
| People CA | User/employee certificates | ECDSA P-256 | 5 years |
| CodeSign CA | Code signing certificates | RSA-4096 | 5 years |
| TSA CA | Timestamp authority | ECDSA P-256 | 5 years |
| HR CA | HR-specific certificates | ECDSA P-256 | 5 years |
| VPN CA | VPN client certificates | ECDSA P-256 | 5 years |
| ACME CA | Automated certificates | ECDSA P-256 | 5 years |

## Certificate Profiles

| Profile | Use Case | Extensions |
|---------|----------|------------|
| `tls-server` | Web servers, APIs | Server Auth EKU |
| `tls-client` | Client authentication | Client Auth EKU |
| `codesigning` | Code signing | Code Signing EKU |
| `ocsp-signer` | OCSP responder | OCSP Signing EKU |
| `timestamp` | TSA signing | Time Stamping EKU |
| `email` | S/MIME | Email Protection EKU |
| `document` | Document signing | Document Signing EKU |
| `identity-user` | Identity certificates | Auto-fill from identity source |

## Name Constraints

Restrict sub-CA to specific domains:

```bash
pki ca init \
  --name "Web CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --permitted-dns "*.example.com" \
  --excluded-dns "*.internal.example.com" \
  --permitted-emails "@example.com" \
  --out-cert web/ca.pem \
  --out-key web/ca.key
```

## CA Key Rotation

Rotate CA master keys before expiry:

```bash
# Check rotation status
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  https://localhost:4433/api/v1/ca/tls/rotation

# Perform rotation
curl -sk --cert superadmin.pem --key superadmin.key --cacert issuing-ca.pem \
  -X POST https://localhost:4433/api/v1/ca/tls/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

Rotation is atomic with dual-signing transition period.

## Offline Root CA

For maximum security, keep the root CA offline:

1. Initialize root CA on an air-gapped machine
2. Copy only the root CA certificate to the online server
3. Use `pki ca offline-sign` to sign sub-CA CSRs on the offline machine
4. Copy signed sub-CA certificates back to the online server

```bash
# On offline machine
pki ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

## Cold Backup

Create encrypted backup of CA keys:

```bash
# Create backup
pki ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json

# Verify backup
pki ca cold-backup verify \
  --backup backup.json \
  --password "backup-secret"
```

## Cross-Certification

Establish trust between independent CAs:

```bash
# Issue cross-certificate
pki cross-cert issue \
  --issuer-ca "External Root" \
  --subject-ca "My Root" \
  --validity 3650d

# List cross-certificates
pki cross-cert list
```

## Trust Bridge Federation

Federate trust anchors across organizations:

```bash
# Import a trust anchor
pki trust import \
  --cert partner-ca.pem \
  --name "Partner CA"

# List trust anchors
pki trust list

# Establish trust bridge
pki trust bridge issue \
  --ca "My Root" \
  --partner "Partner CA"
```

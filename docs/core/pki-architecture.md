# PKI Architecture: 3-Tier vs 4-Tier Hierarchy

## Overview

The varwof PKI supports two hierarchy modes:

| Mode | Config | Tiers | Use Case |
|------|--------|-------|----------|
| Simple | `--hierarchy simple` | 3-tier | Small-medium organizations |
| Enterprise | `--hierarchy enterprise` | 4-tier | Large enterprises, compliance-heavy |

## Three-Tier Architecture (Simple)

```
                    ┌──────────────┐
                    │   Root CA    │  L1 — Trust Anchor
                    │  (offline)   │  ECDSA P-384, 20 years
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │ TLS CA    │   │ People CA │   │ CodeSign  │  L2 — Issuing CAs
    │ (5 years) │   │ (5 years) │   │ CA (RSA)  │  ECDSA P-256
    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
          │                │                │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │ Servers   │   │ Users     │   │ Software  │  L3 — End Entities
    │ Clients   │   │ AIC Agents│   │ Code      │
    └───────────┘   └───────────┘   └───────────┘
```

### Characteristics

- Root CA signs all sub-CAs directly
- Sub-CAs have `MaxPathLen=0` (cannot issue further CAs)
- Simpler chain verification
- Faster deployment
- Root CA can be kept offline after sub-CAs are issued

### Chain Verification

```bash
# Simple chain
openssl verify -CAfile root/ca.pem -untrusted tls/ca.pem server.pem

# Expected output
server.pem: OK
```

### init-full Command

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --hierarchy simple \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki
```

Creates:
```
/opt/pki/
├── root/           Root CA
├── management/     Management CA
├── tls/            TLS CA
├── people/         People CA
├── codesign/       CodeSign CA
├── tsa/            TSA CA
├── hr/             HR CA
├── vpn/            VPN CA
├── acme/           ACME CA
├── server.pem      Server TLS cert
└── pki.json        Config
```

## Four-Tier Architecture (Enterprise)

```
                    ┌──────────────┐
                    │   Root CA    │  L1 — Trust Anchor
                    │  (offline)   │  ECDSA P-384, 20 years
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Policy CA   │  L2 — Policy Buffer
                    │  (10 years)  │  ECDSA P-384
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │ TLS CA    │   │ People CA │   │ CodeSign  │  L3 — Issuing CAs
    │ (5 years) │   │ (5 years) │   │ CA (RSA)  │  ECDSA P-256
    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
          │                │                │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │ Servers   │   │ Users     │   │ Software  │  L4 — End Entities
    │ Clients   │   │ AIC Agents│   │ Code      │
    └───────────┘   └───────────┘   └───────────┘
```

### Characteristics

- Policy CA acts as a buffer between Root and Issuing CAs
- Root CA remains fully offline (never touches online infrastructure)
- Policy CA can adjust sub-CA policies without touching Root
- Supports Policy Mappings, Policy Constraints, Inhibit anyPolicy
- Required for compliance frameworks (SOC 2, PCI DSS, NIST)

### Why Policy CA?

> "The Policy CA is the only difference between four-tier and three-tier — it acts as a policy buffer: once the Root CA is kept offline, the Policy CA can adjust sub-CA policies without touching the Root."

Benefits:
1. **Offline Root**: Root CA private key never leaves the air-gapped machine
2. **Policy Flexibility**: Policy CA can be rotated/renewed without Root CA involvement
3. **Compliance**: Separation of duties between trust anchor and policy enforcement
4. **Audit Trail**: Policy changes are logged at the Policy CA level

### Chain Verification

```bash
# Four-tier chain requires Policy CA as intermediate
openssl verify \
  -CAfile root/ca.pem \
  -untrusted policy/ca.pem \
  -untrusted tls/ca.pem \
  server.pem

# Expected output
server.pem: OK
```

### init-full Command

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --hierarchy enterprise \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki
```

Creates:
```
/opt/pki/
├── root/           Root CA
├── policy/         Policy CA (NEW)
├── management/     Management CA
├── tls/            TLS CA
├── people/         People CA
├── codesign/       CodeSign CA
├── tsa/            TSA CA
├── hr/             HR CA
├── vpn/            VPN CA
├── acme/           ACME CA
├── server.pem      Server TLS cert
└── pki.json        Config
```

## Comparison

| Aspect | 3-Tier (Simple) | 4-Tier (Enterprise) |
|--------|-----------------|---------------------|
| Depth | Root → Sub-CA → End Entity | Root → Policy CA → Sub-CA → End Entity |
| Root offline | After sub-CA creation | Fully offline always |
| Policy flexibility | Limited | High (Policy CA buffer) |
| Chain verification | 2 intermediates max | 3 intermediates max |
| Compliance | Basic | SOC 2, PCI DSS, NIST |
| Complexity | Low | Medium |
| Deployment | `--hierarchy simple` | `--hierarchy enterprise` |

## Sub-CA Definitions

Both modes create 8 business sub-CAs:

| CA | Purpose | Key Type | Validity |
|----|---------|----------|----------|
| Management | Admin/operator certs | ECDSA P-256 | 5 years |
| TLS | Server/client TLS | ECDSA P-256 | 5 years |
| People | User/employee certs | ECDSA P-256 | 5 years |
| CodeSign | Code signing | RSA-4096 | 5 years |
| TSA | Timestamp signing | RSA-4096 | 5 years |
| HR | HR department | ECDSA P-256 | 5 years |
| VPN | VPN client | ECDSA P-256 | 5 years |
| ACME | Auto-enrollment | ECDSA P-256 | 5 years |

All sub-CAs have `MaxPathLen=0` (cannot issue further CAs).

## Name Constraints

Sub-CAs can be restricted to specific domains:

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

### Supported Constraint Types

| Type | Description |
|------|-------------|
| DNS | Permitted/excluded domains |
| Email | Permitted/excluded email addresses |
| URI | Permitted/excluded URI domains |
| IP | Permitted/excluded IP CIDR ranges |

### Enforcement

Name constraints are enforced during chain validation (`checkNameConstraints`):
- Every DNS name in the child must be within a permitted subtree
- Excluded subtrees always win over permitted
- DNS matching: `example.com` also matches `sub.example.com`

## Policy Constraints

RFC 5280 extensions for policy enforcement:

### Policy Mappings (OID 2.5.29.33)

Maps `issuerDomainPolicy` to `subjectDomainPolicy`:
```json
{
  "defaults": {
    "policy_mappings": ["2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2"]
  }
}
```

### Policy Constraints (OID 2.5.29.36)

```json
{
  "defaults": {
    "require_explicit_policy": 0,
    "inhibit_policy_mapping": 0
  }
}
```

- `require_explicit_policy`: After N intermediates, explicit policy required
- `inhibit_policy_mapping`: After N intermediates, no further mappings

### Inhibit anyPolicy (OID 2.5.29.54)

```json
{
  "defaults": {
    "inhibit_any_policy": 0
  }
}
```

After N intermediates, the `anyPolicy` OID is suppressed.

## Offline Root CA

### Setup

1. Initialize root CA on air-gapped machine
2. Copy only the root certificate to online server
3. Use `pki ca offline-sign` to sign sub-CA CSRs
4. Copy signed sub-CA certificates back

### Offline Signing

```bash
# On offline machine
pki ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

### Import Root Key Security

Root CA private keys are explicitly rejected from import:
- `ErrRootCAImport` returned for any root key import attempt
- System checks if public key matches known root CAs in DB
- Prevents attackers from wrapping root keys in non-self-signed certificates

## Cross-Certificates

Cross-certificates allow trust between independent PKI domains:

```bash
# Issue cross-certificate
pki cross-cert issue \
  --issuer "External Root" \
  --subject "My Root" \
  --validity 3650d

# List cross-certificates
pki cross-cert list

# Revoke
pki cross-cert revoke \
  --issuer "External Root" \
  --serial AB12CD34 \
  --reason keyCompromise
```

### Cross-Certificate Properties

- Target's Subject + Public Key
- Issuer's signature
- `MaxPathLen=0` (restricts further delegation)
- Optional name constraints

## Trust Bridge Federation

Higher-level abstraction over cross-certificates:

```bash
# Establish trust bridge
pki trust-bridge issue "My Root" "Partner Root" 3650

# List trust bridges
pki trust-bridge list

# Federate trust anchors from remote
pki trust-bridge federate https://partner.example.com/ca-bundle.pem
```

### Trust Pool Construction

Federated trust pool built from:
1. Local CA certificates
2. Valid cross-certificate records
3. Trusted trust anchors from database

### Trust Anchor Import

```bash
# Import trust bundle
pki trust import --cert partner-ca.pem --name "Partner CA"

# Fetch from URL (TLS required for non-loopback)
pki trust fetch https://partner.example.com/ca.pem
```

Security:
- TLS required for non-loopback hosts
- 32 MiB size limit
- Must contain at least one valid root CA
- Deduplication by SHA-256 hash

## Certificate Chain Building

### Chain Builder (`BuildChain`)

1. Start with leaf certificate
2. Find issuer candidates by matching `RawIssuer`
3. Prefer trust anchors when available
4. Cycle detection via `seen` map
5. Depth bound (default 16)

### Path Verification (`VerifyPath`)

**Pass 1 — Structural checks (leaf to root):**
- Validity window check for every certificate
- Signature verification
- Issuer must be CA (`IsCA` flag)
- Issuer must have `keyCertSign` KeyUsage
- Name constraint validation

**Pass 2 — Path length constraints:**
- For each CA from root down, intermediates must not exceed `MaxPathLen`

**Pass 3 — Trust anchor check:**
- Terminal certificate must match a known trust anchor

**Pass 4 — Policy processing (optional):**
- RFC 5280 Section 6.1 algorithm
- Policy Mappings, Policy Constraints, Inhibit anyPolicy

### CLI Verification

```bash
# Verify certificate chain
pki verify-path cert.pem --db /var/lib/pki/pki.db

# With policy check
pki verify-path cert.pem --db /var/lib/pki/pki.db --policy-check

# JSON output
pki verify-path cert.pem --db /var/lib/pki/pki.db --json
```

## Key Rotation

Atomic CA key rotation with dual-signing:

```bash
# Check rotation status
curl -sk --cert superadmin.pem --key superadmin.key \
  https://localhost:4433/api/v1/ca/tls/rotation

# Perform rotation
curl -sk --cert superadmin.pem --key superadmin.key \
  -X POST https://localhost:4433/api/v1/ca/tls/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

### Rotation Process

1. New key takes effect atomically (`atomic.Pointer`)
2. Old key retained as "legacy" for dual-signing
3. Transition window for verifying previously issued certs
4. Server checks expiry every 12 hours, warns at 7 days

## Cold Backup

Encrypted backup of CA keys:

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

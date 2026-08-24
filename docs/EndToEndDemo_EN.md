# End-to-End Zero-Trust Gateway Demo

This guide demonstrates the full pipeline of the pki core + pki-gateway: **issue certificates → enforce policy at the gateway → audit traceability**.

## System Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Administrator                  AI Agent                 │
│  varwof issue                   pki-agent (to be built)  │
└─────────┬──────────────────────┬──────────────────────────┘
          │ Issue certs with OU roles │ API calls
┌─────────▼──────────────────────▼──────────────────────────┐
│  pki core (CA)                                           │
│  • Issues short-lived agent-proxy certificates (≤1h)     │
│  • OU required: gateway:<role> → cert-bound permissions  │
│  • CRL publishing: revocations take effect immediately   │
└─────────────────────────┬──────────────────────────────────┘
                          │ Certificates + CRL
┌─────────────────────────▼──────────────────────────────────┐
│  pki-gateway (zero-trust gateway)                        │
│  1. mTLS handshake → verify certificate chain            │
│  2. CRL check → reject revoked certificates              │
│  3. Extract OU roles → compare against allow_roles       │
│  4. Audit log → TSA-signed tamper proof                  │
│  5. Port forwarding → connect to the target service      │
└─────────────────────────┬──────────────────────────────────┘
                          │ mTLS tunnel
┌─────────────────────────▼──────────────────────────────────┐
│  Target services (MySQL / Redis / SSH / HTTP API)        │
└────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Go 1.21+
- openssl CLI (for certificate verification)
- Build artifacts: `pki`, `pki-gateway`

```bash
# Build
go build -o pki ./cmd/pki/
go build -o pki-gateway /path/to/pki-gateway/
```

## Steps

### 1. Create the CA Hierarchy

```bash
# Root CA
varwof init-ca --name "Demo Root CA" --key-type ecdsa-p256 \
  --ca-type root --org "Demo" --country "CN" --out ./ca

# Issuing CA
varwof init-ca --name "Demo Issuing CA" --key-type ecdsa-p256 \
  --ca-type sub --parent-ca ./ca/demo-root-ca \
  --org "Demo" --country "CN" --out ./ca
```

### 2. Issue Gateway Client Certificates

Uses the `agent-proxy` profile—which enforces a mandatory OU and a validity of ≤1 hour:

```bash
varwof issue --ca ./ca/demo-issuing-ca --profile agent-proxy \
  --cn "mysql-agent" \
  --subject "/CN=mysql-agent/OU=gateway:mysql-prod" \
  --out ./certs --name mysql-agent
```

Verify the certificate:

```bash
openssl x509 -in ./certs/mysql-agent.pem -noout -subject
# → subject=CN=mysql-agent, OU=gateway:mysql-prod, ...

openssl x509 -in ./certs/mysql-agent.pem -noout -ext keyUsage,extendedKeyUsage
# → X509v3 Key Usage: Digital Signature
# → X509v3 Extended Key Usage: TLS Web Client Authentication
```

### 3. Configure and Start the Gateway

```json
{
  "mappings": [
    {
      "name": "mysql-prod",
      "listen": "127.0.0.1:9443",
      "target": "127.0.0.1:3306",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "./ca/demo-issuing-ca/ca.pem",
        "cert_file": "./ca/demo-issuing-ca/ca.pem",
        "key_file": "./ca/demo-issuing-ca/ca-key.pem",
        "crl_url": "http://crl.internal:8080/demo-issuing-ca.crl",
        "allow_roles": ["gateway:mysql-prod"],
        "audit_file": "/var/log/pki-gateway/audit.log"
      }
    }
  ]
}
```

```bash
pki-gateway server -config ./gw.json
```

### 4. Client Connection

```bash
# Access MySQL through the gateway (no need to know MySQL's real address)
mysql -h 127.0.0.1 -P 9443 -u app_user -p \
  --ssl-cert ./certs/mysql-agent.pem \
  --ssl-key ./certs/mysql-agent-key.pem \
  --ssl-ca ./ca/demo-issuing-ca/ca.pem
```

### 5. Unauthorized Attempts Are Blocked

Attempt to connect to a mapping with `allow_roles: ["gateway:mysql-prod"]` using a certificate carrying the `gateway:readonly` role:

```bash
# Issue a read-only certificate
varwof issue --ca ./ca/demo-issuing-ca --profile agent-proxy \
  --cn "readonly-agent" \
  --subject "/CN=readonly-agent/OU=gateway:readonly" \
  --out ./certs --name readonly-agent

# Connection rejected by the gateway
mysql -h 127.0.0.1 -P 9443 ... --ssl-cert ./certs/readonly-agent.pem ...
# → ERROR 2013 (HY000): Lost connection to MySQL server
```

Gateway log:
```
denied: src=10.0.0.5 mapping=mysql-prod reason="unauthorized role" roles=["gateway:readonly"]
```

### 6. Revoke a Certificate

```bash
# Revoke
varwof revoke --ca ./ca/demo-issuing-ca --cert ./certs/mysql-agent.pem
varwof crl --ca ./ca/demo-issuing-ca --out ./crl/demo-issuing-ca.crl

# Hot-reload the CRL on the gateway
kill -HUP $(pgrep pki-gateway)
# or
curl -X POST https://admin:9443/api/v1/gateway/crl-reload \
  --cert admin.pem --key admin-key.pem
```

Connections using the revoked certificate are rejected immediately.

### 7. View Audit Logs

```bash
# Query audits via the management API
curl --cert admin.pem --key admin-key.pem \
  https://admin:9443/api/v1/gateway/audit?since=2026-07-05T00:00:00Z
```

Each audit log line contains:
```json
{"entry":{"time":"2026-07-05T12:34:56.123456789Z","action":"connected","client_cn":"mysql-agent","client_serial":"ABC123","roles":["gateway:mysql-prod"],"mapping":"mysql-prod","target":"127.0.0.1:3306"},"tst":"MIIF...TQ=="}
```

The `tst` field is an RFC 3161 TSA signature proving the log entry has not been tampered with.

## Automated Testing

```bash
bash deploy/test-gateway-e2e.sh
```

The script automatically:
1. Creates the CA hierarchy
2. Issues agent-proxy certificates
3. Starts an echo test server
4. Starts the gateway
5. Tests role authentication
6. Tests unauthorized-access rejection
7. Tests revocation enforcement
8. Verifies audit logs

## FAQ

**Q: Issuance reports "requires at least one OU"?**
A: The `agent-proxy` profile requires an OU, in the format:
```bash
--subject "/CN=<name>/OU=gateway:<role>"
```

**Q: Certificate validity too long and got truncated?**
A: `agent-proxy` enforces a maximum of 1 hour. For a temporarily longer validity, use the `tls-client` profile and specify `--ttl` manually.

**Q: Windows config path?**
A: The default path is `%ProgramData%\varwof\pki-gateway\pki-gateway.json`.

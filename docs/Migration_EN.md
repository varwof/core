# PKI Migration Report: pn41 OpenSSL → pki tool + varwof.org → varwof.com

> **Date:** 2026-07-01
> **Source:** Hand-rolled OpenSSL CA (`/etc/pki/`, domain `*.varwof.org`)
> **Target:** Managed by the `pki` tool (`/etc/pki-new/`, domain `*.varwof.com`)

## Background

pn41 hosts all intranet PKI infrastructure—mail, DNS, Web, SVN, Syncthing, NAS, OCSP, TSA. The original PKI was based on manual OpenSSL issuance: 3 CAs (Root / Issuing / TSA) + 9 service certificates, with the domain suffix `varwof.org`.

Problems:
- CRL updates required manual shell scripts
- OCSP used the `openssl ocsp` command (index.txt only refreshed on restart; fragile HTTP header parsing)
- TSA wrapped `openssl ts -reply` in Python
- Issuance relied on the `issue-cert.sh` script with no database audit trail
- The varwof.org domain was inconsistent with the CoreDNS zone varwof.com

## Migration Steps

### 1. Survey the Existing PKI

```bash
# Read all CA certificate information
ssh pn41 "sudo cat /etc/pki/root/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"
ssh pn41 "sudo cat /etc/pki/issuing/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"
ssh pn41 "sudo cat /etc/pki/tsa/certs/ca.pem | openssl x509 -noout -subject -issuer -dates"

# List all service certificates and private keys
ssh pn41 "sudo find /etc -name '*.pem' -o -name '*.key' | grep -v usr/share | grep -v ca-certificates"

# Read certificate paths from the nginx/Postfix/Dovecot/Syncthing configurations
ssh pn41 "sudo cat /etc/nginx/sites-enabled/www-varwof"
ssh pn41 "sudo cat /etc/nginx/sites-enabled/svn-varwof"
ssh pn41 "sudo grep 'smtpd_tls_cert\|ssl_server_cert' /etc/postfix/main.cf /etc/dovecot/conf.d/10-ssl.conf"
```

> Finding: the CoreDNS zone is `varwof.com`, but the certificate subjects are `varwof.org`—the DNS and PKI domains are inconsistent.

### 2. Build the New PKI (generated locally)

```bash
# Create directories
mkdir -p /tmp/pki-migration/pki/{root,issuing,tsa,ocsp,tsa-signer,www,svn,syncthing,nas,coredns}/{certs,private}
mkdir -p /tmp/pki-migration/pki/www/pki/crl

# Create the config (with default_org / default_country)
cat > /tmp/pki-migration/pki.json << 'EOF'
{ "db": "/tmp/pki-migration/pki.db",
  "defaults": { "ca": "issuing", "profile": "tls-server",
    "default_org": "Varwof", "default_country": "CN" },
  "cas": {
    "Varwof Root CA": {"cert":"pki/root/certs/ca.pem","key":"pki/root/private/ca.key"},
    "Varwof Issuing CA": {"cert":"pki/issuing/certs/ca.pem","key":"pki/issuing/private/ca.key"},
    "Varwof TSA CA": {"cert":"pki/tsa/certs/ca.pem","key":"pki/tsa/private/ca.key"}
  },
  "ca": {"crl_url":"http://www.varwof.com/pki/crl/issuing.crl",
         "ocsp_url":"http://ocsp.varwof.com:9080",
         "issuer_url":"http://www.varwof.com/pki/issuing.pem" },
  "serve": {"addr":":4431"} }
EOF

# Root CA (P-384, 20 years)
./varwof init-ca -config pki.json -name "Varwof Root CA" \
  -key-type ecdsa-p384 -validity 7300 -profile root-ca \
  -out-cert pki/root/certs/ca.pem -out-key pki/root/private/ca.key

# Issuing CA (P-384, 10 years, signed by Root)
./varwof init-ca -config pki.json -name "Varwof Issuing CA" \
  -parent "Varwof Root CA" -parent-key pki/root/private/ca.key \
  -key-type ecdsa-p384 -validity 3650 -profile sub-ca \
  -permitted-dns "varwof.com,varwof.org" \
  -out-cert pki/issuing/certs/ca.pem -out-key pki/issuing/private/ca.key

# TSA CA (P-384, 10 years, signed by Root)
./varwof init-ca -config pki.json -name "Varwof TSA CA" \
  -parent "Varwof Root CA" -parent-key pki/root/private/ca.key \
  -key-type ecdsa-p384 -validity 3650 -profile sub-ca \
  -out-cert pki/tsa/certs/ca.pem -out-key pki/tsa/private/ca.key
```

#### Problem 1: Root CA with O=example.com

The first `init-ca` run generated the Root CA with O=example.com because the config field names were wrong.

**Fix:** the organization fields in the config are `default_org` and `default_country` (not `org`/`country`). After correcting the config, rebuild the DB and regenerate.

```json
"defaults": {
    "default_org": "Varwof",
    "default_country": "CN"
}
```

### 3. Issue Service Certificates

```bash
# OCSP signing certificate (Issuing CA, 5 years, EKU=OCSPSigning)
./varwof issue -config pki.json -ca "Varwof Issuing CA" \
  -cn "Varwof OCSP Responder" -profile ocsp-signer -validity 1825 \
  -subject "/C=CN/O=Varwof/OU=OCSP Responder/CN=Varwof OCSP Responder" \
  -out pki/ocsp/certs/ocsp.pem -out-key pki/ocsp/private/ocsp.key

# TSA signing certificate (TSA CA, 5 years, EKU=timeStamping)
./varwof issue -config pki.json -ca "Varwof TSA CA" \
  -cn "Varwof TSA" -profile timestamp -validity 1825 \
  -subject "/C=CN/O=Varwof/OU=Time Stamping Authority/CN=Varwof TSA" \
  -out pki/tsa-signer/certs/tsa-signer.pem -out-key pki/tsa-signer/private/tsa-signer.key

# All service certificates (Issuing CA, P-256, 2 years)
PROF="tls-server -validity 730"
SUBJ="/C=CN/O=Varwof/OU=Services/CN="
CA="Varwof Issuing CA"

# dns
./varwof issue -config pki.json -ca "$CA" -cn "dns.varwof.com" -profile $PROF \
  -subject "${SUBJ}dns.varwof.com" \
  -san "DNS:ns1.varwof.com,IP:TAILSCALE_IP_1,IP:INTERNAL_IP" \
  -out pki/coredns/certs/varwof.pem -out-key pki/coredns/private/varwof.key

# mail
./varwof issue -config pki.json -ca "$CA" -cn "mail.varwof.com" -profile $PROF \
  -subject "${SUBJ}mail.varwof.com" \
  -san "DNS:mail.varwof.com,DNS:smtp.varwof.com,DNS:imap.varwof.com,DNS:autoconfig.varwof.com,DNS:autodiscover.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2" \
  -out pki/mail.pem -out-key pki/mail.key

# www
./varwof issue -config pki.json -ca "$CA" -cn "www.varwof.com" -profile $PROF \
  -subject "${SUBJ}www.varwof.com" \
  -san "DNS:www.varwof.com,DNS:varwof.com" \
  -out pki/www/certs/www.varwof.com.pem -out-key pki/www/private/www.varwof.com.key

# svn
./varwof issue -config pki.json -ca "$CA" -cn "svn.varwof.com" -profile $PROF \
  -subject "${SUBJ}svn.varwof.com" \
  -san "DNS:svn.varwof.com" \
  -out pki/svn/certs/svn.varwof.com.pem -out-key pki/svn/private/svn.varwof.com.key

# syncthing
./varwof issue -config pki.json -ca "$CA" -cn "syncthing.varwof.com" -profile $PROF \
  -subject "${SUBJ}syncthing.varwof.com" \
  -san "DNS:syncthing.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2,IP:127.0.0.1" \
  -out pki/syncthing/certs/syncthing.varwof.com.pem -out-key pki/syncthing/private/syncthing.varwof.com.key

# nas1
./varwof issue -config pki.json -ca "$CA" -cn "nas1.varwof.com" -profile $PROF \
  -subject "${SUBJ}nas1.varwof.com" \
  -san "DNS:nas1.varwof.com,IP:192.168.6.6" \
  -out pki/nas/certs/nas1.varwof.com.pem -out-key pki/nas/private/nas1.varwof.com.key

# nas2
./varwof issue -config pki.json -ca "$CA" -cn "nas2.varwof.com" -profile $PROF \
  -subject "${SUBJ}nas2.varwof.com" \
  -san "DNS:nas2.varwof.com,IP:192.168.6.7" \
  -out pki/nas/certs/nas2.varwof.com.pem -out-key pki/nas/private/nas2.varwof.com.key
```

#### Problem 2: Wildcard SAN DNS:* Not Accepted

The DNS certificate was issued with `DNS:*.varwof.com` included:

```
sign: parse SANs: invalid DNS SAN: DNS:*.varwof.com
```

**Cause:** the `pki` SAN parser performs strict syntax validation; the wildcard prefix `*.` was not accepted.

**Fix:** the `validDNS` regex in `internal/ca/sign.go:548` was fixed to add a `^(\*\.)?` prefix supporting legitimate wildcards. During the migration this was worked around manually (using an explicit SAN list `DNS:ns1.varwof.com,IP:TAILSCALE_IP_1,IP:INTERNAL_IP`); after the fix, `--san "DNS:*.varwof.com"` works directly.

#### Problem 3: CA Name Not in Config

```
CA "Varwof Issuing CA" not found in config
```

**Cause:** `varwof init-ca` stores CAs in the database, but `varwof issue` looks up CA file paths from the `cas` section of the config file (not from the database).

**Fix:** add a `cas` section to `pki.json`:

```json
"cas": {
  "Varwof Root CA": {"cert": "pki/root/certs/ca.pem", "key": "pki/root/private/ca.key"},
  "Varwof Issuing CA": {"cert": "pki/issuing/certs/ca.pem", "key": "pki/issuing/private/ca.key"},
  "Varwof TSA CA": {"cert": "pki/tsa/certs/ca.pem", "key": "pki/tsa/private/ca.key"}
}
```

#### Problem 4: Wildcard DNS SAN Violates Name Constraints

The first version of the syncthing certificate contained the SAN `syncthing` (bare hostname, no domain suffix):

```
openssl verify ... syncthing.varwof.com.pem
error 47 at 0 depth lookup: permitted subtree violation
```

**Cause:** the Issuing CA has Name Constraints set via `-permitted-dns "varwof.com,varwof.org"`; the SAN `syncthing` (without a `.`) falls outside the permitted subtree.

**Fix:**
1. Remove the bare hostname `syncthing` from the SANs
2. Revoke the old certificate version
3. Re-issue (because the `issue` command performs duplicate-CN detection, `revoke` first)

```bash
./varwof revoke -config pki.json -ca "Varwof Issuing CA" -serial <old-serial>
./varwof issue ... -san "DNS:syncthing.varwof.com,IP:TAILSCALE_IP_1,IP:TAILSCALE_IP_2,IP:127.0.0.1"
```

#### Problem 5: Duplicate CN Blocks Re-Issuance

```
sign: insert cert to db: duplicate CN "syncthing.varwof.com": active cert ... already exists
```

**Cause:** the `issue` command checks whether the DB already contains a valid (`status='V'`) certificate with the same CN.

**Fix:** revoke first, then issue.

### 4. Import the Old PKI as Trust Anchors

```bash
# Fetch the old CA certificates from pn41
ssh pn41 "sudo cat /etc/pki/root/certs/ca.pem" > /tmp/pki-migration/old-root.pem
ssh pn41 "sudo cat /etc/pki/issuing/certs/ca.pem" > /tmp/pki-migration/old-issuing.pem
ssh pn41 "sudo cat /etc/pki/tsa/certs/ca.pem" > /tmp/pki-migration/old-tsa.pem

# Import into the DB
./pki trust import -config pki.json -file old-root.pem
./pki trust import -config pki.json -file old-issuing.pem
./pki trust import -config pki.json -file old-tsa.pem
```

> Only the old Root CA (self-signed) was imported. The Issuing CA and TSA CA are not self-signed, so `trust import` skips them automatically.

### 5. Build Chain Files

```bash
cat pki/mail.pem pki/issuing/certs/ca.pem > pki/mail.chain.pem
cat pki/www/certs/www.varwof.com.pem pki/issuing/certs/ca.pem > pki/www/certs/www.varwof.com.fullchain.pem
cat pki/svn/certs/svn.varwof.com.pem pki/issuing/certs/ca.pem > pki/svn/certs/svn.varwof.com.fullchain.pem
cat pki/syncthing/certs/syncthing.varwof.com.pem pki/issuing/certs/ca.pem > pki/syncthing/certs/syncthing.varwof.com.fullchain.pem
```

### 6. Deploy to pn41

```bash
# Cross-compile
GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false go build -o pki-linux-amd64 ./cmd/pki/

# Copy files
scp pki-linux-amd64 pn41:/tmp/pki-new
ssh pn41 sudo mv /tmp/pki-new /usr/local/bin/pki-new
ssh pn41 sudo chmod 755 /usr/local/bin/pki-new

# Create directories
ssh pn41 sudo mkdir -p /etc/pki-new/pki/{root,issuing,tsa,ocsp,tsa-signer,www,svn,syncthing,nas,coredns}/{certs,private}
ssh pn41 sudo mkdir -p /etc/pki-new/pki/www/pki/crl

# Copy all PEM and KEY files + config + DB
scp pki-new.json pn41:/tmp/ && ssh pn41 sudo mv /tmp/pki-new.json /etc/pki-new/pki.json
# ... copy all cert/key/db files one by one
```

### 7. Update the Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name www.varwof.com varwof.com www.varwof.org varwof.org;
    ssl_certificate     /etc/pki-new/pki/www/certs/www.varwof.com.fullchain.pem;
    ssl_certificate_key /etc/pki-new/pki/www/private/www.varwof.com.key;
    ssl_trusted_certificate /etc/pki-new/pki/www/pki/issuing.pem;
    ...
}
```

The old configuration referenced `varwof.org` files under `/etc/pki/www/`; both the domain names and paths needed updating.

### 8. Replace the OCSP/TSA Services

Old services (OpenSSL-based):

```ini
# ocsp-responder.service
ExecStart=/usr/bin/openssl ocsp -port 9080 -index /etc/pki/issuing/index.txt -CA ...

# tsa-responder.service
# Python wrapper around openssl ts -reply
```

New services (pki):

```ini
# pki-ocsp.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json serve ocsp

# pki-tsa.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json serve tsa
```

#### Problem 6: Old OCSP Crashed on HTTP Header Parsing

```
ocsp: cannot parse HTTP header: missing end of line
```

A known issue of the old `openssl ocsp` command—fragile HTTP request header parsing. After migrating to `varwof serve ocsp`, this no longer occurs.

### 9. Configure CRL Automation

```ini
# pki-crl.service
ExecStart=/usr/local/bin/pki-new --config /etc/pki-new/pki.json crl

# pki-crl.timer
OnCalendar=daily
```

The built-in `varwof crl` command generates the CRL from the database and no longer depends on OpenSSL's index.txt.

### 10. Verification Checklist

```bash
# Chain verification (all certificates)
for cert in pki/coredns/certs/varwof.pem pki/mail.pem pki/www/certs/www.varwof.com.pem ...; do
  openssl verify -CAfile root.pem -untrusted issuing.pem "$cert"
done

# TLS handshake
echo "Q" | openssl s_client -connect host:port -starttls smtp -CAfile root.pem -servername sn

# OCSP query
openssl ocsp -issuer issuing.pem -cert mail.pem -url http://...:9080 -CAfile root.pem

# TSA query
echo "test" | openssl ts -query -data /dev/stdin -no_nonce -sha256 | \
  curl -s -H "Content-Type: application/timestamp-query" --data-binary @- http://...:3180 | \
  openssl ts -reply -in /dev/stdin -text
```

## Post-Migration Architecture

```
/usr/local/bin/pki-new          # Single binary
/etc/pki-new/                   # Config + DB + all certificates
├── pki.json                    # Main configuration
├── pki.db                      # SQLite (CA metadata, issuance records, audit logs)
└── pki/
    ├── root/certs/ca.pem       # Root CA (public distribution)
    ├── issuing/certs/ca.pem    # Issuing CA
    ├── tsa/certs/ca.pem        # TSA CA
    ├── www/pki/                # HTTP-accessible PKI files
    ├── ocsp/certs/ocsp.pem     # OCSP signing certificate
    └── tsa-signer/certs/*.pem  # TSA signing certificates

systemd services:
  pki-ocsp.service   :9080     # OCSP responder
  pki-tsa.service    :3180     # TSA timestamping
  pki-crl.timer                # Daily CRL generation
```

## Problem Summary

| # | Problem | Root Cause | Fix |
|---|---------|------------|-----|
| 1 | Root CA had O=example.com | Config field is `default_org`, not `org` | Corrected the config field name |
| 2 | Wildcard SAN `DNS:*` rejected | SAN parser did not support wildcards | Fixed the regex in `internal/ca/sign.go` (`^(\*\.)?`); merged into the source |
| 3 | CA not found in config | `issue` looks up CA paths from config, not the DB | Added the `cas` config section |
| 4 | Name Constraints violation | Bare hostname SAN outside the permitted DNS subtree | Removed the bare SAN |
| 5 | Duplicate CN blocked issuance | Duplicate CN detection | Revoke first, then issue |
| 6 | Old OCSP crashed parsing HTTP | Fragile `openssl ocsp` | Switched to `varwof serve ocsp` |
| 7 | Cross-platform `--config` flag written as `-` instead of `--` | Forgot the double dash | Documented reminder |

## Follow-ups

- Upload NAS certificates via the web interface
- Install the Root CA on clients: `/etc/pki-new/pki/root/certs/ca.pem`
- Deploy `varwof serve api` to provide the REST API
- Offline cold backup of the Root CA key

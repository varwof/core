# varwof Configuration Reference

The configuration file is a single JSON document loaded at startup.
Default location: `/etc/varwof/core/pki.json` (Linux) or `%PROGRAMDATA%/varwof/core/pki.json` (Windows).

Generate a sample with:

```bash
varwof init-config > pki.json
```

---

## Top-level Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `db` | string | `/var/lib/pki/pki.db` | Database path (SQLite recommended; see `db.dialect` for PG/MySQL community support) |
| `db.dialect` | string | `"sqlite3"` | SQL dialect driver: `"sqlite3"` (recommended), `"pgx"` (PostgreSQL, community), `"mysql"` (MySQL/MariaDB, community) |
| `tsa` | object | see below | Time-Stamp Authority settings |
| `ocsp` | object | see below | Online Certificate Status Protocol settings |
| `cas` | object | see below | CA certificate/key definitions |
| `serve` | object | see below | HTTP/HTTPS server settings |
| `defaults` | object | see below | Default values for certificate operations |
| `crl` | object | see below | Certificate Revocation List settings |
| `webhook` | object | see below | Event notification webhook |
| `key_escrow` | object | see below | Key escrow (admin recovery) |
| `ct_log` | object | see below | Certificate Transparency log |
| `ldap` | object | see below | LDAP directory integration |
| `identity` | object | `null` | Identity-source → certificate automation (identity-user profile, see below) |
| `acme` | object | see below | ACME v2 protocol settings |
| `scep` | object | see below | SCEP protocol settings |
| `ra` | object | see below | Registration Authority settings |
| `rate_limit` | object | see below | API rate limiting |
| `authorization_file` | string | `""` | Authorization policy file path (authz.json: OU→role mapping + permission matrix) |
| `routes_file` | string | `""` | URL-level route permission rules file path (routes.json); defaults to `<config_dir>/routes.json` |
| `policy_signing` | object | `null` | Policy file (authz.json / routes.json) PKCS#7 signature verification config (see below) |

---

## `serve` — HTTP/HTTPS Server

Controls the built-in HTTP and optional HTTPS server.

| Field | Type | Default | Description |
|---|---|---|---|
| `addr` | string | `:4430` | HTTP listen address (cert distribution, always on) |
| `tls_addr` | string | `""` | HTTPS listen address (optional, separate port) |
| `tls_cert` | string | `""` | TLS certificate PEM file path |
| `tls_key` | string | `""` | TLS private key PEM file path |
| `static` | string | `/etc/varwof/core/www/pki` | Static file directory for web UI |
| `auth_username` | string | `""` | HTTP Basic Auth username for protected endpoints |
| `auth_password` | string | `""` | HTTP Basic Auth password for protected endpoints |
| `reload_poll_interval` | string | `10s` | Config file polling interval for hot reload (e.g. `10s`, `30s`) |
| `shutdown_timeout` | string | `10s` | Graceful shutdown timeout (e.g. `10s`, `30s`) |
| `log_format` | string | `text` | Structured log format: `text` (key=value) or `json` (JSON Lines, for SIEM/log collectors) |
| `log_dest` | string | `stderr` | Log output target: `stderr` (default), `file:/path/to/pki.log` (append), or `syslog` (local syslog `/dev/log` or UDP `localhost:514`, program name `varwof-core`). Format is unaffected; the syslog target forwards log lines to the system log service |
| `agent_session_max_ttl` | string | `24h` | Max duration of a delegated-agent session. Clients must send `X-Agent-TTL` (RFC3339); missing, expired, or beyond this window is rejected; `0` disables delegated sessions entirely |
| `trusted_gateway_ous` | array | `[]` | OUs of trusted gateway service certificates. Only mTLS certs with one of these OUs may forward delegated identity: `X-Client-Cert-DER` (B2 certificate passthrough, recommended — the core resolves the principal/revocation/permissions from the DB by cert) or `X-Agent-User` (B1, degraded fallback, no certificate identity). Empty rejects gateway-asserted delegation entirely. Direct clients without a gateway OU cannot spoof these headers |
| `audit_salt` | object | see below | Per-day salt masking of PII in the audit log |
| `audit_salt.enabled` | bool | `true` | Whether to HMAC-mask `username`/`remote_addr` in audit entries with a per-day salt. `false` reverts to plaintext (legacy behaviour) |
| `audit_salt.retention_days` | int | `365` | Days each daily salt is kept. Past this window the salt row is purged automatically and the day's masked identities become permanently irrecoverable (GDPR storage limitation, Cybersecurity Law logging retention, etc.). The Merkle hash chain over the masked values remains verifiable |
| `audit_salt.cleanup_interval` | string | `24h` | How often to scan and purge expired salts (e.g. `24h`) |
| `audit_verify` | object | see below | Periodic integrity check of the audit Merkle chain (AUTH-016) |
| `audit_verify.enabled` | bool | `true` | Recompute the audit hash chain on a timer and warn when the chain is broken (tampering/deleted rows). Set `false` to disable |
| `audit_verify.interval` | string | `24h` | Chain verification period (e.g. `1h`, `24h`). Verification reads the whole audit log, so widen the period for very large logs |
| `da_max_timestamp_skew` | string | `30s` | DelegationAuthorization signature timestamp freshness window (max `|now - timestamp|`). Enforced at AIC/agent-proxy issuance; stale submissions are rejected (403 `api.da_timestamp_stale`) since a DA signed long before submission is suspicious (replay/forged). Set `"0"` to disable this defense |

---

## `defaults` — Certificate Defaults

Default values applied when not explicitly specified via CLI flags.

| Field | Type | Default | Description |
|---|---|---|---|
| `ca` | string | `issuing` | Default CA name for signing operations |
| `profile` | string | `tls-server` | Default certificate profile: `root-ca`, `sub-ca`, `tls-server`, `tls-client`, `ocsp-signer`, `timestamp`, `codesigning`, `email`, `document` |
| `key_type` | string | `ecdsa-p256` | Default key type: `ecdsa-p256`, `ecdsa-p384`, `ed25519`, `rsa-2048`, `rsa-4096` |
| `hash` | string | `sha256` | Default hash algorithm: `sha256`, `sha384`, `sha512` |
| `default_country` | string | `CN` | Default subject Country for new certificates |
| `default_org` | string | `example.com` | Default subject Organization for new certificates |
| `cert_validity` | string | `2160h` | Default validity duration for issued certificates (e.g. `168h` = 7 days, `2160h` = 90 days) |
| `ocsp_url` | string | `""` | Default OCSP responder URL for AIA extension in issued certificates |
| `issuer_url` | string | `""` | Default caIssuers URL for AIA extension (points to issuer CA certificate) |
| `issuer_alt_names` | []string | `[]` | Issuer Alternative Name entries (RFC 5280 2.5.29.18), e.g. `["DNS:ca.example.com","URI:https://ca.example.com"]` |
| `subject_info_access` | []string | `[]` | Subject Info Access entries (RFC 5280 1.3.6.1.5.5.7.1.11), e.g. `["ocsp:http://ocsp.example.com","ca_repository:http://ca.example.com","time_stamping:http://tsa.example.com"]` |
| `policy_oids` | []string | `[]` | Certificate Policies OIDs (RFC 5280 2.5.29.32), e.g. `["2.16.840.1.101.3.2.1.48.1"]` |
| `policy_mappings` | []string | `[]` | Policy Mappings (RFC 5280 2.5.29.33, CA certificates only), each `issuerPolicy:subjectPolicy`, e.g. `["2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2"]` |
| `require_explicit_policy` | int | `0` | Policy Constraints explicitPolicyIndicator (RFC 5280 2.5.29.36, CA certificates only); max number of intermediate CAs that may skip policy matching before an explicit policy must appear |
| `inhibit_policy_mapping` | int | `0` | Policy Constraints inhibitPolicyMapping (RFC 5280 2.5.29.36, CA certificates only); max number of intermediate CAs that may map policies |
| `inhibit_any_policy` | int | `0` | Inhibit anyPolicy (RFC 5280 2.5.29.54, CA certificates only); max number of intermediate CAs that may ignore anyPolicy |
| `report_max_rows` | int | `5000` | Max certificate rows in PDF report; truncated with notice when exceeded |
| `agent_proxy_max_validity` | string | `1h` | Validity cap for agent-proxy / authorized-mode AIC certificates (≤24h), e.g. `6h`; values above 24h are ignored and fall back to the default 1h |

---

## `acme` — ACME v2 Protocol

Automatic Certificate Management Environment (RFC 8555).

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Enable ACME v2 protocol support |
| `directory` | string | `/acme` | URL path prefix for ACME endpoints |
| `ca_name` | string | `issuing` | CA used to sign ACME-issued certificates |
| `default_key_type` | string | `ecdsa-p256` | Key type for ACME-issued end-entity certs |
| `default_hash` | string | `sha256` | Hash algorithm for ACME-issued certs |
| `authz_expiry` | string | `24h` | Authorization validity duration |
| `order_expiry` | string | `168h` | Order validity duration (7 days) |
| `cert_validity` | string | `2160h` | Certificate validity duration (90 days) |
| `http01_timeout` | string | `10s` | HTTP-01 challenge fetch timeout |
| `dns01_timeout` | string | `10s` | DNS-01 challenge lookup timeout |
| `external_account_required` | bool | `false` | Require External Account Binding (EAB) |
| `external_account_keys` | array | `[]` | EAB key pairs (see table below) |
| `renewal_info_url` | string | `""` | Optional `explanationURL` returned by the ACME ARI (RFC 9445) `renewalInfo` endpoint |
| `rate_limit` | object | `null` | Rate limiting configuration (see below) |

### `acme.external_account_keys[]`

| Field | Type | Description |
|---|---|---|
| `key_id` | string | EAB key identifier (kid) |
| `hmac_key` | string | HMAC-SHA256 key (Base64 encoded) |
| `description` | string | Optional description |

### `acme.rate_limit`

| Field | Type | Default | Description |
|---|---|---|---|
| `new_account_rps` | float | `0` | New accounts per-IP per-second (0=disabled) |
| `new_order_rps` | float | `0` | New orders per-IP per-second |
| `challenge_rps` | float | `0` | Challenge requests per-IP per-second |
| `burst` | int | `0` | Token bucket burst size (0=RPS value) |

---

## `scep` — SCEP Protocol

Simple Certificate Enrollment Protocol (RFC 8894).

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Enable SCEP support |
| `ca_name` | string | `""` | CA used to sign SCEP-issued certificates |
| `cert_validity` | string | `8760h` | Certificate validity duration (365 days) |

---

## `tsa` — Time-Stamp Authority

RFC 3161 Time-Stamp Protocol server.

| Field | Type | Default | Description |
|---|---|---|---|
| `addr` | string | `:3180` | TSA listen address |
| `signer_cert` | string | `/etc/varwof/core/tsa-signer/tsa-signer.pem` | TSA signer certificate PEM path |
| `signer_key` | string | `/etc/varwof/core/tsa-signer/tsa-signer.key` | TSA signer private key PEM path |
| `chain` | string | `/etc/varwof/core/tsa/certs/ca.pem` | Optional intermediate chain PEM path |
| `tsa_policy` | string | `""` | TSA policy OID (e.g. `1.2.3.4.5`) |
| `ordering` | bool | `false` | Set ordering flag in TSTInfo |
| `accuracy_seconds` | int | `0` | Accuracy in seconds (1-999) |
| `accuracy_millis` | int | `0` | Accuracy in milliseconds (1-999) |
| `accuracy_micros` | int | `0` | Accuracy in microseconds (1-999) |

---

## `ocsp` — OCSP Responder

Online Certificate Status Protocol (RFC 6960) responder.

| Field | Type | Default | Description |
|---|---|---|---|
| `addr` | string | `:9080` | OCSP responder listen address |
| `signer_cert` | string | `/etc/varwof/core/ocsp/ocsp.pem` | OCSP responder certificate PEM path |
| `signer_key` | string | `/etc/varwof/core/ocsp/ocsp.key` | OCSP responder private key PEM path |
| `next_update` | string | `""` | OCSP response nextUpdate duration (e.g. `4h`, `24h`) |
| `cache_size` | int | `0` | Max OCSP response cache entries (0 = disabled) |
| `cache_ttl` | string | `1h` | OCSP response cache TTL (e.g. `1h`, `30m`) |
| `cache_file` | string | `""` | Persisted response cache file; when set, replaces the in-memory cache with a disk-backed one loaded at startup and atomically re-saved after each response (enables stateless OCSP nodes: cold restart does not hammer the shared CA store, and the node may even run without DB access) |

---

## `crl` — Certificate Revocation List

| Field | Type | Default | Description |
|---|---|---|---|
| `validity_days` | int | `30` | CRL validity period in days |
| `output_dir` | string | `""` | Directory to publish CRL files for download |
| `crl_base_url` | string | `""` | Base URL for CRL distribution points (also used as CRLDP in issued certificates) |
| `auto_renew` | string | `""` | CRL auto-renew interval (e.g. `24h`). Requires `--reload` flag. |

---

## `cas` — Certificate Authorities

A map of CA names to their certificate and key paths.

| Field | Type | Default | Description |
|---|---|---|---|
| `<name>.cert` | string | — | CA certificate PEM file path |
| `<name>.key` | string | — | CA private key PEM file path |
| `<name>.chain` | string | `""` | Optional intermediate chain PEM file path |

Default CAs:

```json
"cas": {
  "root":    { "cert": "/etc/varwof/core/root/certs/ca.pem",    "key": "/etc/varwof/core/root/private/ca.key" },
  "issuing": { "cert": "/etc/varwof/core/issuing/certs/ca.pem", "key": "/etc/varwof/core/issuing/private/ca.key" },
  "tsa":     { "cert": "/etc/varwof/core/tsa/certs/ca.pem",     "key": "/etc/varwof/core/tsa/private/ca.key" }
}
```

---

## `webhook` — Event Notifications

Sends HTTP POST JSON payloads on certificate lifecycle events (issue, revoke, expiry).

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | `""` | Primary webhook target URL |
| `timeout` | string | `10s` | HTTP POST timeout for webhook delivery |
| `expiry_check_interval` | string | `24h` | Interval between certificate expiry checks |
| `expiry_thresholds` | []int | `[30, 7, 1]` | Days before expiry to send warning (multiple thresholds allowed) |

---

## `key_escrow` — Key Recovery

Allows an administrator with the escrow private key to decrypt archived certificate private keys.

| Field | Type | Default | Description |
|---|---|---|---|
| `admin_public_key` | string | `""` | Path to admin RSA public key PEM file for key escrow |

---

## `ct_log` — Certificate Transparency

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | `""` | Certificate Transparency log URL for submission |
| `api_key` | string | `""` | API key for the CT log (if required) |
| `public_key` | string | `""` | CT log public key (base64 DER SPKI or PEM). When set, SCT submissions get full RFC 6962 §3.2 signature verification; without it the CLI warns "SCT signature NOT verified" (H11). Also supported per `logs[]` entry |

---

## `ldap` — LDAP Directory Integration

Integrates with an LDAP directory for user authentication and certificate subject DN construction.

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | `""` | LDAP server URL (e.g. `localhost:389`) |
| `bind_dn` | string | `""` | Bind DN for LDAP authentication |
| `bind_password` | string | `""` | Bind password |
| `base_dn` | string | `""` | Base DN for search |
| `filter` | string | `(uid=%s)` | LDAP search filter (`%s` replaced with username) |
| `uid_attr` | string | `uid` | LDAP attribute for user ID |
| `map_cn` | string | `cn` | LDAP attribute mapped to certificate Common Name |
| `map_o` | string | `""` | LDAP attribute mapped to certificate Organization |
| `map_ou` | string | `""` | LDAP attribute mapped to certificate Organizational Unit |
| `map_l` | string | `""` | LDAP attribute mapped to certificate Locality |
| `map_st` | string | `""` | LDAP attribute mapped to certificate State/Province |
| `map_c` | string | `""` | LDAP attribute mapped to certificate Country |
| `map_email` | string | `""` | LDAP attribute mapped to certificate Email |

---

## `identity` — Identity-Source → Certificate Automation (Phase 2)

Configures an identity bridge service so the `identity-user` profile auto-fills
person attributes into issued certificates.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | `ldap` | Identity source kind: `ldap` (bridge-ldap `/api/v1/lookup`) or `oauth` (bridge-oauth password grant + userinfo) |
| `source_url` | string | `""` | **Required.** Identity bridge base URL, e.g. `http://127.0.0.1:8082` |
| `token` | string | `""` | Bridge management API bearer token (empty = no auth) |
| `source` | string | `""` | Default source_tag used when a request does not set `identity_source` |
| `username` | string | `""` | OAuth automation account username (required for `type=oauth`, resource-owner grant) |
| `password` | string | `""` | OAuth automation account password (required for `type=oauth`) |
| `timeout_sec` | int | `10` | Upstream request timeout in seconds |
| `ou_from_groups` | object | `{}` | Identity group → certificate OU (RBAC role) mapping; keys are group names or LDAP group DNs |
| `default_ou` | string | `""` | Fallback OU when no group maps; empty uses the source dept |
| `disabled_ok` | bool | `false` | Allow issuing for disabled accounts (default rejects, fail-closed) |

Example (bridge-ldap + OU mapping):

```json
{
  "identity": {
    "type": "ldap",
    "source_url": "http://127.0.0.1:8082",
    "token": "bridge-token",
    "source": "ad-main",
    "ou_from_groups": {
      "CN=医生,OU=Groups,DC=hospital,DC=local": "gateway:ops"
    }
  }
}
```

Issue with `POST /api/v1/certs` using `profile=identity-user` + `identity_username`.

---

## `ra` — Registration Authority

Controls multi-party approval for certificate issuance.

| Field | Type | Default | Description |
|---|---|---|---|
| `required_approvals` | int | `1` | Number of approvals required for certificate issuance (1 = self-service) |
| `default_ca` | string | `issuing` | Default CA for RA-approved certificates |
| `default_profile` | string | `tls-server` | Default profile for RA-approved certificates |

---

## `rate_limit` — API Rate Limiting

Token-bucket rate limiter for API endpoints.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable rate limiting (AUTH-017: on by default to defend brute-force and DoS; set explicitly to `false` to disable) |
| `rate` | float | `100` | Tokens added per second |
| `burst` | int | `200` | Maximum burst size |

---

## `policy_signing` — Policy File Signature Verification

Prevents local tampering of authz.json / routes.json. When enabled, the policy file's detached signature (`<file>.sig`) is verified before loading. The signature must be a PKCS#7 detached signature (SHA-256 over the policy file bytes) made by an **admin**-role certificate issued by this PKI (OU=admin or gateway:admin). Signatures are produced by `varwof policy sign` or `varwof-cli policy sign`.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable policy signature verification |
| `ca_file` | string | `serve.tls_client_ca` | Trusted CA chain PEM used to verify the signer certificate |
| `require_admin_ou` | bool | `true` | Require the signer certificate to carry an admin OU (nil = default true) |
| `require` | bool | `false` | `true` = reject loading when signature is missing; `false` = warn and load plaintext |
| `sig_suffix` | string | `".sig"` | Signature file suffix |

**Failure behavior**: signature verification failure (tampering / non-admin signer / untrusted CA chain) **rejects loading** (fail-closed); startup skips with a warning, and hot-reload keeps the previous policy.

```json
"policy_signing": {
  "enabled": true,
  "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
  "require_admin_ou": true,
  "require": true,
  "sig_suffix": ".sig"
}
```

---

## Validation

When pki loads a configuration file, the following validations are performed:

1. **Key types** — `defaults.key_type` and `acme.default_key_type` must be one of:
   `ecdsa-p256`, `ecdsa-p384`, `ed25519`, `rsa-2048`, `rsa-4096`; `sm2` is also available (only with the `-tags gmsm` build, producing certs with the pure SM2-with-SM3 signature algorithm OID `1.2.156.10197.1.501`).
2. **Hash algorithms** — `defaults.hash` and `acme.default_hash` must be one of:
   `sha256`, `sha384`, `sha512`
3. **Durations** — All duration fields (ending in `_interval`, `_timeout`, `_expiry`, `_validity`, etc.) must be valid Go `time.Duration` strings (e.g. `10s`, `24h`, `168h`, `2160h`).
4. **Ports** — Listen addresses must include a valid port number (1–65535).

---

## Full Example

```json
{
  "db": "/var/lib/pki/pki.db",
  "serve": {
    "addr": ":4430",
    "static": "/etc/varwof/core/www/pki",
    "reload_poll_interval": "10s",
    "shutdown_timeout": "10s",
    "log_format": "json",
    "log_dest": "syslog"
  },
  "defaults": {
    "ca": "issuing",
    "profile": "tls-server",
    "key_type": "ecdsa-p256",
    "hash": "sha256",
    "default_country": "CN",
    "default_org": "example.com",
    "cert_validity": "2160h",
    "ocsp_url": "http://pki.example.com/ocsp",
    "issuer_url": "http://pki.example.com/ca.pem"
  },
  "acme": {
    "enable": true,
    "directory": "/acme",
    "ca_name": "issuing",
    "default_key_type": "ecdsa-p256",
    "default_hash": "sha256",
    "authz_expiry": "24h",
    "order_expiry": "168h",
    "cert_validity": "2160h",
    "http01_timeout": "10s"
  },
  "cas": {
    "root": {
      "cert": "/etc/varwof/core/root/certs/ca.pem",
      "key": "/etc/varwof/core/root/private/ca.key"
    },
    "issuing": {
      "cert": "/etc/varwof/core/issuing/certs/ca.pem",
      "key": "/etc/varwof/core/issuing/private/ca.key"
    }
  },
  "crl": {
    "validity_days": 30,
    "output_dir": "/etc/varwof/core/www/pki",
    "crl_base_url": "http://pki.example.com/pki",
    "auto_renew": "24h"
  },
  "webhook": {
    "url": "http://hooks.example.com/events",
    "timeout": "10s",
    "expiry_check_interval": "24h",
    "expiry_thresholds": [30, 7, 1]
  }
}
```

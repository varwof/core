# Configuration Reference

The configuration file is a single JSON document loaded at startup.

Default locations (searched in order):
1. `--config <path>` (CLI flag, highest priority)
2. `./pki.json` (current directory)
3. `~/.config/pki/pki.json` (user config)
4. `/etc/varwof/core/pki.json` (system-wide)

Generate a sample:
```bash
pki init-config > pki.json
```

---

## Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `db` | string | `/var/lib/pki/pki.db` | Database path (SQLite recommended) |
| `db.dialect` | string | `"sqlite3"` | SQL driver: `sqlite3`, `pgx` (PostgreSQL), `mysql` (MariaDB) |
| `locale` | string | auto | `"zh"` or `"en"` (auto-detect default) |
| `hierarchy` | string | `"simple"` | `"simple"` (single CA level) or `"complex"` (multi-level CA hierarchy) |
| `serve` | object | see below | HTTP/HTTPS server settings |
| `defaults` | object | see below | Default values for certificate operations |
| `cas` | object | see below | CA certificate/key definitions |
| `tsa` | object | see below | RFC 3161 Time-Stamp Authority |
| `ocsp` | object | see below | RFC 6960 OCSP responder |
| `crl` | object | see below | Certificate Revocation List |
| `acme` | object | see below | ACME v2 protocol (RFC 8555) |
| `scep` | object | see below | SCEP protocol (RFC 8894) |
| `webhook` | object | see below | Webhook notifications |
| `key_escrow` | object | see below | Key escrow/recovery |
| `ct_log` | object | see below | Certificate Transparency |
| `ldap` | object | see below | LDAP directory integration |
| `identity` | object | null | Identity-source to certificate automation |
| `ra` | object | see below | Registration Authority |
| `rate_limit` | object | see below | API rate limiting |
| `authorization_file` | string | `""` | RBAC policy file path (authz.json) |
| `routes_file` | string | `""` | URL-level route permission rules (routes.json) |
| `policy_signing` | object | null | PKCS#7 signature verification for policy files |
| `rbac` | object | see below | RBAC settings |
| `auto_renew` | object | see below | Automatic certificate renewal |
| `archive` | object | see below | Certificate archival |
| `trust_bridge` | object | see below | Cross-CA trust bridge |
| `smtp` | object | see below | SMTP notifications |
| `engine` | object | see below | In-memory engine config |
| `device_profile` | string | `""` | Device tuning preset (`low_mem` / `high_throughput`); see below |
| `persist` | object | see below | Certificate persistence mode |
| `record_buffer` | object | see below | Batch persistence |
| `aggregator` | object | see below | Batch issuance aggregation |
| `key_backend` | object | see below | Remote HSM signer delegation |
| `spiffe` | object | see below | SPIFFE identity integration |
| `k8s_enabled` | bool | false | Enable `/api/v1/k8s/sign` endpoint |
| `policy` | string | `""` | CN/SAN allow/deny policy JSON path |
| `enforce_policy` | bool | false | Make missing policy a hard error |

---

## Performance Decision Guide (which configs matter most)

Load-tested conclusions (`docs/bench/en/benchmark-report-2026-08-27.md` §5–§8). In order of
value, the critical knobs are:

1. **`device_profile` — deployment picker.** Set it once per machine type; it sizes the
   write pipeline and memory budgets (`""` x86/desktop, `low_mem` Pi 5 / SBC, `high_throughput`
   multi-core). Doing nothing else is a valid, well-tuned config.
2. **`record_buffer.max_pending` & `engine.write_max_pending` — the burst/backpressure lever.**
   Both default to 20000; when the limit is hit the server returns HTTP 503. Raising to 100000+
   absorbs bursts: a 3000-agent 30s burst went from 15.1% → 5.5% errors and +32% throughput.
   Trade: more in-flight records in RAM.
3. **`rate_limit` — per-IP abuse protection.** Independent of buffer backpressure; this is the
   injection-side limiter hitting clients that send too fast, not the global 503. When measuring
   raw capacity, disable it.
4. **OS / DB layer (not in this file):** CPU governor + turbo (+43%) and
   MariaDB `innodb_flush_log_at_trx_commit=2` (SD-card iowait −58%) — see report §5§6.

**Do NOT touch** (measurably slower when raised): `record_buffer.threshold` (500),
`engine.write_threshold` (100), `engine.write_workers` (4). The profiles already encode this;
manual overrides only make sense to push `max_pending` deeper.

```json
// "just works" deployment
{ "device_profile": "high_throughput" }

// burst-heavy deployment (deepen the pipeline manually)
{
  "device_profile": "high_throughput",
  "record_buffer": { "max_pending": 300000 },
  "engine": { "write_max_pending": 300000 }
}
```

---

## `serve` — HTTP/HTTPS Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | `:8443` | HTTP listen address |
| `tls_addr` | string | `""` | HTTPS mTLS listen address |
| `api_addr` | string | `""` | Internal API listen address |
| `tls_cert` | string | `""` | TLS certificate PEM path |
| `tls_key` | string | `""` | TLS private key PEM path |
| `tls_client_ca` | string | `""` | Client CA cert for mTLS auth |
| `static` | string | `/etc/varwof/core/www` | Static file directory (Web UI) |
| `auth_username` | string | `""` | HTTP Basic Auth username (fallback) |
| `auth_password` | string | `""` | HTTP Basic Auth password (fallback) |
| `reload_poll_interval` | string | `10s` | Config file polling for hot reload |
| `shutdown_timeout` | string | `10s` | Graceful shutdown timeout |
| `log_format` | string | `text` | `text` (key=value) or `json` (JSON Lines) |
| `log_dest` | string | `stderr` | `stderr`, `file:/path`, or `syslog` |
| `metrics_enabled` | bool | false | Enable Prometheus `/metrics` |
| `agent_session_max_ttl` | string | `24h` | Max delegated-agent session window |
| `trusted_gateway_ous` | []string | `[]` | OUs of trusted gateway service certs |
| `da_max_timestamp_skew` | string | `30s` | DA signature timestamp freshness window |
| `audit_salt` | object | see below | Per-day HMAC salt masking of PII |
| `audit_verify` | object | see below | Periodic Merkle chain integrity verification |

### `serve.audit_salt`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | HMAC-mask username/remote_addr in audit log |
| `retention_days` | int | 365 | Days to keep each daily salt |
| `cleanup_interval` | string | `24h` | How often to purge expired salts |

### `serve.audit_verify`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Recompute audit hash chain on timer |
| `interval` | string | `24h` | Chain verification period |

---

## `defaults` — Certificate Defaults

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ca` | string | `issuing` | Default CA name |
| `profile` | string | `tls-server` | Default certificate profile |
| `key_type` | string | `ecdsa-p256` | Default key type |
| `hash` | string | `sha256` | Default hash algorithm |
| `default_country` | string | `CN` | Default subject Country |
| `default_org` | string | `example.com` | Default subject Organization |
| `cert_validity` | string | `2160h` | Default certificate validity |
| `ocsp_url` | string | `""` | OCSP responder URL for AIA |
| `issuer_url` | string | `""` | caIssuers URL for AIA |
| `issuer_alt_names` | []string | `[]` | Issuer Alternative Name entries |
| `subject_info_access` | []string | `[]` | Subject Info Access entries |
| `policy_oids` | []string | `[]` | Certificate Policies OIDs |
| `policy_mappings` | []string | `[]` | Policy Mappings (CA certs only) |
| `require_explicit_policy` | int | 0 | Policy Constraints explicitPolicy |
| `inhibit_policy_mapping` | int | 0 | Policy Constraints inhibitPolicyMapping |
| `inhibit_any_policy` | int | 0 | Inhibit anyPolicy |
| `report_max_rows` | int | 5000 | Max cert rows in PDF report |
| `agent_proxy_max_validity` | string | `1h` | Max validity for agent-proxy certs |

### Supported Key Types

`ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `rsa-2048`, `rsa-4096`, `rsa-8192`, `sm2` (requires `-tags gmsm`)

### Supported Hash Algorithms

`sha256`, `sha384`, `sha512`

### Supported Profiles

`root-ca`, `sub-ca`, `tls-server`, `tls-client`, `ocsp-signer`, `timestamp`, `codesigning`, `email`, `document`, `identity-user`, `m-admin`, `m-superadmin`, `m-operator`, `m-auto-renew`

---

## `acme` — ACME v2 Protocol

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | false | Enable ACME v2 |
| `directory` | string | `/acme` | URL path prefix |
| `ca_name` | string | `issuing` | CA for ACME-issued certs |
| `default_key_type` | string | `ecdsa-p256` | Key type for ACME certs |
| `default_hash` | string | `sha256` | Hash algorithm |
| `authz_expiry` | string | `24h` | Authorization validity |
| `order_expiry` | string | `168h` | Order validity (7 days) |
| `cert_validity` | string | `2160h` | Certificate validity (90 days) |
| `http01_timeout` | string | `10s` | HTTP-01 challenge timeout |
| `dns01_timeout` | string | `10s` | DNS-01 challenge timeout |
| `external_account_required` | bool | false | Require EAB |
| `external_account_keys` | array | `[]` | EAB key pairs |
| `renewal_info_url` | string | `""` | ARI renewal info URL (RFC 9445) |
| `rate_limit` | object | null | Per-IP rate limiting |

### `acme.external_account_keys[]`

| Field | Type | Description |
|-------|------|-------------|
| `key_id` | string | EAB key identifier (kid) |
| `hmac_key` | string | HMAC-SHA256 key (Base64) |
| `description` | string | Optional description |

---

## `scep` — SCEP Protocol

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | false | Enable SCEP |
| `ca_name` | string | `""` | CA for SCEP-issued certs |
| `cert_validity` | string | `8760h` | Certificate validity (365 days) |

---

## `tsa` — Time-Stamp Authority

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | `:3180` | TSA listen address |
| `signer_cert` | string | `/etc/varwof/core/tsa-signer/tsa-signer.pem` | Signer certificate |
| `signer_key` | string | `/etc/varwof/core/tsa-signer/tsa-signer.key` | Signer private key |
| `chain` | string | `/etc/varwof/core/tsa/certs/ca.pem` | Intermediate chain |
| `tsa_policy` | string | `""` | TSA policy OID |
| `ordering` | bool | false | Set ordering flag in TSTInfo |
| `accuracy_seconds` | int | 0 | Accuracy in seconds |
| `accuracy_millis` | int | 0 | Accuracy in milliseconds |
| `accuracy_micros` | int | 0 | Accuracy in microseconds |

---

## `ocsp` — OCSP Responder

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | `:9080` | OCSP listen address |
| `signer_cert` | string | `/etc/varwof/core/ocsp/ocsp.pem` | Signer certificate |
| `signer_key` | string | `/etc/varwof/core/ocsp/ocsp.key` | Signer private key |
| `next_update` | string | `""` | Response nextUpdate duration |
| `cache_size` | int | 0 | Max cache entries (0=disabled) |
| `cache_ttl` | string | `1h` | Cache TTL |
| `cache_file` | string | `""` | Disk-backed cache file (stateless OCSP nodes) |

---

## `crl` — Certificate Revocation List

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `validity_days` | int | 30 | CRL validity period |
| `output_dir` | string | `""` | Directory for CRL files |
| `crl_base_url` | string | `""` | Base URL for CRL distribution points |
| `auto_renew` | string | `""` | Auto-renew interval (e.g., `24h`) |

---

## `cas` — Certificate Authorities

Map of CA names to certificate and key paths.

```json
"cas": {
  "root": {
    "cert": "/etc/varwof/core/root/certs/ca.pem",
    "key": "/etc/varwof/core/root/private/ca.key"
  },
  "issuing": {
    "cert": "/etc/varwof/core/issuing/certs/ca.pem",
    "key": "/etc/varwof/core/issuing/private/ca.key"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `<name>.cert` | string | CA certificate PEM path |
| `<name>.key` | string | CA private key PEM path |
| `<name>.chain` | string | Optional intermediate chain PEM |

---

## `webhook` — Event Notifications

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `""` | Webhook target URL |
| `timeout` | string | `10s` | HTTP POST timeout |
| `expiry_check_interval` | string | `24h` | Certificate expiry check interval |
| `expiry_thresholds` | []int | `[30, 7, 1]` | Days before expiry to send warning |

---

## `key_escrow` — Key Recovery

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `admin_public_key` | string | `""` | Admin RSA public key PEM for key escrow |

---

## `ct_log` — Certificate Transparency

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `""` | CT log URL |
| `api_key` | string | `""` | API key |
| `public_key` | string | `""` | CT log public key (base64 DER or PEM) |

---

## `ldap` — LDAP Directory Integration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `""` | LDAP server URL |
| `bind_dn` | string | `""` | Bind DN |
| `bind_password` | string | `""` | Bind password |
| `base_dn` | string | `""` | Base DN for search |
| `filter` | string | `(uid=%s)` | Search filter (`%s` = username) |
| `uid_attr` | string | `uid` | User ID attribute |
| `map_cn` | string | `cn` | Mapped to certificate CN |
| `map_o` | string | `""` | Mapped to certificate O |
| `map_ou` | string | `""` | Mapped to certificate OU |
| `map_l` | string | `""` | Mapped to certificate L |
| `map_st` | string | `""` | Mapped to certificate ST |
| `map_c` | string | `""` | Mapped to certificate C |
| `map_email` | string | `""` | Mapped to certificate Email |

---

## `identity` — Identity-Source Automation

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | `ldap` | Source kind: `ldap` or `oauth` |
| `source_url` | string | `""` | Identity bridge base URL |
| `token` | string | `""` | Bridge API bearer token |
| `source` | string | `""` | Default source_tag |
| `username` | string | `""` | OAuth automation account |
| `password` | string | `""` | OAuth automation password |
| `timeout_sec` | int | 10 | Upstream request timeout |
| `ou_from_groups` | object | `{}` | Group → OU (RBAC role) mapping |
| `default_ou` | string | `""` | Fallback OU |
| `disabled_ok` | bool | false | Allow disabled accounts |

---

## `ra` — Registration Authority

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `required_approvals` | int | 1 | Approvals needed (1 = self-service) |
| `default_ca` | string | `issuing` | Default CA for RA certs |
| `default_profile` | string | `tls-server` | Default profile |

---

## `rate_limit` — API Rate Limiting

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable rate limiting |
| `rate` | float | 100 | Tokens per second |
| `burst` | int | 200 | Maximum burst size |

---

## `policy_signing` — Policy File Signatures

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable signature verification |
| `ca_file` | string | `serve.tls_client_ca` | Trusted CA chain PEM |
| `require_admin_ou` | bool | true | Require admin OU on signer |
| `require` | bool | false | Reject when signature missing |
| `sig_suffix` | string | `.sig` | Signature file suffix |

---

## `engine` — In-Memory Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_certs` | int | 100000 | Max certificates in memory |
| `max_nonces` | int | 100000 | Max nonces |
| `max_da_nonces` | int | 100000 | Max DA (delegation-authorization) nonces |
| `max_revoked` | int | 10000 | Max revoked certs |
| `grace` | string | `24h` | Retention window for expired certs in memory |
| `janitor_interval` | string | `60s` | Expired-cert sweep interval |
| `nonce_ttl` | string | `24h` | Unused nonce lifetime |
| `write_threshold` | int | 100 | Pending writes before flush |
| `write_max_pending` | int | 20000 | Hard backpressure ceiling for pending writes |
| `write_max_latency` | string | `500ms` | Max latency before forced flush |
| `write_workers` | int | 4 | Backend writer goroutines (revoke/nonce/meta) |

---

## `device_profile` — Device-Specific Tuning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `device_profile` | string | `""` | Preset of device-sensitive defaults. `""` = x86/desktop baseline; `"low_mem"` for single-board computers / low-RAM (e.g. Raspberry Pi 5); `"high_throughput"` for multi-core servers that absorb bursts. Explicit `engine` / `record_buffer` settings always override the preset. Tuned by load testing (see `docs/bench/en/benchmark-report-2026-08-27.md` §5–§7). |

Exactly what each preset changes (everything else keeps the built-in default):

| Preset | `record_buffer.max_pending` | `engine.max_certs` | `engine.max_da_nonces` | `engine.write_max_pending` |
|--------|---------------------------|--------------------|------------------------|---------------------------|
| `""` (default) | 20000 | 100000 | 100000 | 20000 |
| `low_mem` | 5000 | 50000 | 50000 | 5000 |
| `high_throughput` | 100000 | 100000 | 100000 | 100000 |

Verified by load testing — the profile deliberately does **NOT** touch these, raising them slowed AIC on the 18-core turbo reference box:

- `record_buffer.threshold` (500): 500→1000 made single flushes hold the flush mutex longer; burst throughput dropped ~4%.
- `engine.write_threshold` (100): 100→500 deepened the write pipeline; throughput dropped ~4%.
- `engine.write_workers` (4): 4→8 added DB pool contention; throughput dropped ~25%.

The win for `high_throughput` is purely the deeper `max_pending` ceiling: under a 3000-agent 30s burst (no manual `-maxpending`) it cut the backpressure error rate from 15.1% → 5.5% and lifted throughput +32% (2,996 → 3,945 certs/s). `low_mem` trades burst depth for a ~4× smaller in-flight ceiling, appropriate for Pi 5 / SBC RAM budgets.

---

## `persist` — Certificate Persistence

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `realtime` | `realtime`, `batch`, or `async` |
| `batch_size` | int | 50 | Batch size |
| `batch_interval` | string | `5s` | Batch interval |
| `queue_size` | int | 1000 | Async queue size |

---

## `smtp` — Email Notifications

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `""` | SMTP server host |
| `port` | int | 587 | SMTP server port |
| `username` | string | `""` | SMTP username |
| `password` | string | `""` | SMTP password |
| `from` | string | `""` | Sender email address |
| `tls` | bool | true | Use TLS |
| `events` | []string | `[]` | Events to notify (issue, revoke, expiry) |

---

## `rbac` — Role-Based Access Control

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable RBAC |
| `mode` | string | `simple` | `simple` or `enterprise` |
| `ca_scopes` | object | `{}` | CA scope definitions |

---

## Validation Rules

1. **Key types**: `defaults.key_type` and `acme.default_key_type` must be valid
2. **Hash algorithms**: `defaults.hash` and `acme.default_hash` must be valid
3. **Durations**: All duration fields must be valid Go `time.Duration` strings
4. **Ports**: Listen addresses must have valid port numbers (1–65535)

---

## Full Example

```json
{
  "db": "/var/lib/pki/pki.db",
  "locale": "en",
  "serve": {
    "addr": ":8443",
    "tls_addr": ":4433",
    "tls_cert": "/etc/varwof/core/server.pem",
    "tls_key": "/etc/varwof/core/server.key",
    "tls_client_ca": "/etc/varwof/core/ca.pem",
    "static": "/etc/varwof/core/www",
    "log_format": "json",
    "log_dest": "syslog",
    "reload_poll_interval": "10s",
    "metrics_enabled": true
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
  "tsa": {
    "addr": ":3180",
    "signer_cert": "/etc/varwof/core/tsa-signer/tsa-signer.pem",
    "signer_key": "/etc/varwof/core/tsa-signer/tsa-signer.key"
  },
  "ocsp": {
    "addr": ":9080",
    "signer_cert": "/etc/varwof/core/ocsp/ocsp.pem",
    "signer_key": "/etc/varwof/core/ocsp/ocsp.key",
    "cache_size": 10000,
    "cache_ttl": "1h",
    "cache_file": "/var/lib/pki/ocsp-cache.db"
  },
  "crl": {
    "validity_days": 30,
    "output_dir": "/etc/varwof/core/www/pki",
    "crl_base_url": "http://pki.example.com/pki",
    "auto_renew": "24h"
  },
  "acme": {
    "enable": true,
    "directory": "/acme",
    "ca_name": "issuing",
    "default_key_type": "ecdsa-p256",
    "http01_timeout": "10s",
    "dns01_timeout": "10s"
  },
  "rate_limit": {
    "enabled": true,
    "rate": 100,
    "burst": 200
  },
  "webhook": {
    "url": "http://hooks.example.com/events",
    "timeout": "10s",
    "expiry_check_interval": "24h",
    "expiry_thresholds": [30, 7, 1]
  },
  "device_profile": "high_throughput",
  "engine": {
    "write_max_pending": 200000
  }
}
```

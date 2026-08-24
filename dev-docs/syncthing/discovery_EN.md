# Syncthing Discovery Server Architecture Analysis

**Source**: syncthing v1.30.0 source code

---

## 1. Overall Architecture

```
┌───────────────────┐     HTTPS JSON     ┌───────────────────┐
│ Global discovery  │◄─────────────────►│ Syncthing client   │
│ server (stdiscosrv)│    register/lookup │                   │
│ :8443            │                    ├───────────────────┤
│                   │    ip:port/token   │ Local discovery (LAN) │
└───────────────────┘                    │ (beacon broadcast/multicast) │
                                         └───────────────────┘
```

Two discovery mechanisms work together:
- **Local discovery**: broadcast/multicast within the LAN, millisecond-level response
- **Global discovery**: crosses NAT, registers with and queries a public directory service over HTTPS

---

## 2. Global Discovery Server (stdiscosrv)

### 2.1 Startup Flow (`cmd/stdiscosrv/main.go`)

1. **Parse CLI arguments**: listen address, database path, certificate path, rate limits, HTTP redirect
2. **Load the database**: uses `cockroachdb/pebble` (LSM-tree KV store)
3. **TLS configuration**: server certificate + optional client certificate authentication
4. **Start the HTTP service**: `:8443` (default)

**CLI options**:
- `-db-dir` (default `./discovery-db`) — Pebble database path
- `-http` (default `:8443`) — listen address
- `-cert` / `-key` — TLS certificate paths (by default auto-generates 2048-bit RSA)
- `-db-compression` — Pebble compression algorithm (snappy/zstd/none)
- `-rate-requests` — max lookup requests per second (0 = unlimited)
- `-rate-certs` — upper limit on whitelisted certificates
- `-redirect-http-to` — HTTP redirect target URL
- `-access-control` — whitelist file of certificate fingerprints allowed to register

### 2.2 Storage Architecture (`db.go`)

Based on CockroachDB Pebble (LSM-tree), better suited to write-heavy workloads than BoltDB.

**Storage format**: 3 key spaces:

```
Registration records:    certHash -> encryptedCert (Blake2b-160 + NaCl sealed)
Aging records:           extinctKey -> extinctTime
Address records:         certHash + announcement -> []address (protobuf encoded)
```

**Expiry cleanup**: a timer runs every 2 minutes, deleting expired registrations and aging records.

### 2.3 API Endpoints

The server exposes one endpoint whose behavior depends on the HTTP method and headers:

**Unified endpoint**: `/v2/` (or any path)

#### 2.3.1 Registration (PUT)

```
PUT /v2/<deviceID-hex> HTTP/1.1
Content-Type: application/json
Authorization: <token>

{"instanceID": "<instance>", "addresses": [...]}
```

Handling (`handleRegister`):
1. Parse the device ID from the path (hex)
2. Verify the token (via TLS client certificate or auth header)
3. Extract the client IP
4. Store the address record (with expiry time)
5. Return `204 No Content`

**Authentication methods**:
- **TLS client certificate**: configure `-access-control` to restrict specific certificate fingerprints
- **Authorization header**: used for forwarding from other discovery servers

#### 2.3.2 Lookup (GET)

```
GET /v2/<deviceID-hex> HTTP/1.1
```

Handling (`handleLookup`):
1. Parse the device ID from the path
2. Query the database for the address record
3. Return `200 OK` with a JSON address list
4. Return `404` when not found

**Deduplication protection** (`globals.go`):
Request deduplication via `sync.Map`:
```go
type lookupContext struct {
    lookupResult []byte
    gotResult    chan struct{}
}
```

Concurrent lookups of the same device ID from the same client within 16 seconds are merged.

#### 2.3.3 Access Control (`record.go`)

Returns its own public key and service instance ID:
```
GET /v2/
```
Response:
```json
{"instanceID": "<instanceID>", "publicKey": "<serverPublicKey>"}
```

**Token computation**: `Blake2b-160(certificateFingerprint)` + NaCl sealed encryption of the device ID

### 2.4 Rate Limiting (`rate.go`)

**Token bucket**: implemented with `golang.org/x/time/rate`, `rateRequests` tokens per second.

Additional limit: **maximum number of allowed certificates** = `rateCerts` (whitelist capacity limit).

### 2.5 Data Record Format (`record.go`)

At registration, the device ID is encrypted with NaCl sealed boxes using the server's public key (`box.SealAnonymous`), ensuring only the server can decrypt it.

Address record format:
```go
type record struct {
    InstanceID   string   // Server instance ID
    Addresses    []string // "tcp://ip:port" format
    Certificate  []byte   // Device certificate
    Seen         int64    // Last-seen timestamp (UnixNano)
}
```

Cache control: responses include `Cache-Control: max-age=<ttl>`, where TTL = `announcement.Until - time.Now()`.

---

## 3. Local Discovery (LAN)

### 3.1 Implementation (`lib/discover/local.go`)

**Interface**: the `Discoverer` interface:
```go
type Discoverer interface {
    Lookup(ctx context.Context, deviceID protocol.DeviceID) ([]string, error)
    Error() error
    String() string
    Cache() map[protocol.DeviceID]CacheEntry
}
```

**Local discovery** uses two protocols:
| Protocol | Implementation | Default port | Characteristics |
|---|---|---|---|
| IPv4 broadcast | `lib/beacon/broadcast.go` | 21027/UDP | Sent to `255.255.255.255:21027` |
| IPv6 multicast | `lib/beacon/multicast.go` | 21027/UDP | Sent to `[ff12::8384]:21027` |

**Data format** (protobuf encoded):
```
AnnounceMessage:
  magic: 0x9E79BC39
  deviceID: [32]byte
  addresses: []struct{ port: uint16; ... }
```

**Send interval**: local discovery announcements are sent every 30 seconds (configurable).

**Receive handling**: after receiving an announcement, the peer address is pinged for reachability verification before being added to the local discovery cache.

### 3.2 Cache Management

```go
type CacheEntry struct {
    Addresses  []string
    Seen       time.Time
}
```

- Up to 16 addresses cached per device ID
- Cache entries expire after 15 minutes

---

## 4. Global Discovery Client

### 4.1 Implementation (`lib/discover/global.go`)

**Construction**:
```go
func NewGlobalDiscoverer(server string, cert tls.Certificate, timeout time.Duration) *GlobalDiscoverer
```
- `server`: discovery server URL (e.g. `https://discovery.syncthing.net/v2/`)
- `cert`: device certificate (used for request authentication)
- `timeout`: request timeout

**Lookup flow** (`Lookup`):
1. Build the query URL from the device ID
2. Issue an HTTPS GET request
3. Parse the returned JSON address list
4. Return the address list

**Registration flow** (`announce`):
1. Periodically (every 30 minutes by default) send device addresses to the discovery server
2. Uses `net/http/httpproxy` for HTTP proxy support
3. Sends a JSON payload containing basic device information

### 4.2 End-to-End Flow

```
Client A:
  1. Listen on TCP :22000
  2. Register with the discovery server (tcp://public_ip_1:22000, relay://relay.example.com:22067?id=...)
  3. Refresh registration every 30 minutes

Client B looking up A:
  1. Issue simultaneously:
     a. Local discovery (LAN broadcast/multicast) -> instant response when on the same LAN
     b. Global discovery (HTTPS to stdiscosrv) -> returns A's address and relay URI
  2. First response wins: local discovery is faster, global discovery supplements it
```

---

## 5. Configuration Integration (`lib/config/optionsconfiguration.go`)

```go
type OptionsConfiguration struct {
    // ...
    GlobalAnnEnabled    bool     `default:"true"`
    GlobalAnnServers    []string `default:"default"`
    RelaysEnabled       bool     `default:"true"`
    // ...
}
```

The `GlobalAnnServers` default value expands to:
```go
"default"  // -> "https://discovery.syncthing.net/v2/"
```

Can be configured as:
- `"https://discovery.syncthing.net/v2/"` — official public discovery server
- `"https://my-custom-discosrv:8443/"` — self-hosted discovery server
- `""` — disable global discovery

---

## 6. Key File Index

| File | Role |
|---|---|
| `cmd/stdiscosrv/main.go` | Discovery server entry point, CLI, HTTPS setup |
| `cmd/stdiscosrv/record.go` | Record definitions, token computation, access control |
| `cmd/stdiscosrv/db.go` | Pebble KV store, CRUD, expiry cleanup |
| `cmd/stdiscosrv/globals.go` | Request deduplication (sync.Map), 16-second merge window |
| `cmd/stdiscosrv/rate.go` | Token bucket rate limiting |
| `lib/discover/local.go` | Local discovery (LAN broadcast/multicast) |
| `lib/discover/global.go` | Global discovery client (HTTPS) |
| `lib/beacon/broadcast.go` | IPv4 UDP broadcast implementation |
| `lib/beacon/multicast.go` | IPv6 UDP multicast implementation |
| `lib/config/optionsconfiguration.go` | Discovery configuration options |

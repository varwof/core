# Syncthing Relay Server Architecture Analysis

**Source**: syncthing v1.30.0 source code  
**Analysis date**: 2026-06-23

---

## Table of Contents

1. [Overall Architecture](#1-overall-architecture)
2. [Relay Protocol](#2-relay-protocol)
3. [Relay Server strelaysrv](#3-relay-server-strelaysrv)
4. [Relay Client Library](#4-relay-client-library)
5. [Relay Pool Server strelaypoolsrv](#5-relay-pool-server-strelaypoolsrv)
6. [Main syncthing Integration](#6-main-syncthing-integration)
7. [End-to-End Connection Flow](#7-end-to-end-connection-flow)
8. [Key File Index](#8-key-file-index)

---

## 1. Overall Architecture

The relay system consists of four logical components:

```
┌─────────────────────┐      HTTP/JSON       ┌──────────────────────┐
│   Relay pool server │◄────────────────────►│   Relay server       │
│   (directory service)│  register/heartbeat │   (strelaysrv)       │
│   :80               │                      │   :22067 (TLS relay) │
│                     │                      │   :22070 (status page)│
└─────────┬───────────┘                      └──────────┬───────────┘
          │                                              │
          │ HTTP/JSON                                     │ Relay protocol (XDR)
          │ (clients query the pool)                     │ (TLS-encrypted TCP)
          ▼                                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Syncthing client (main binary)                  │
│  lib/connections/relay_dial.go    -- outbound (dialer)            │
│  lib/connections/relay_listen.go  -- inbound (listener)           │
│  lib/relay/client/                -- client library               │
│  lib/relay/protocol/              -- wire protocol                │
└──────────────────────────────────────────────────────────────────┘
```

**Protocol layering**:

```
BEP (Block Exchange Protocol)     ← syncthing's own sync protocol
┌─────────────────────────────┐
│        TLS                  │ ← mutual TLS (device certificates)
├─────────────────────────────┤
│   Relay protocol (XDR encoding) │ ← custom framing protocol
├─────────────────────────────┤
│   Raw TCP                   │ ← network transport
└─────────────────────────────┘
```

---

## 2. Relay Protocol

### 2.1 Wire Format

**Files**: `lib/relay/protocol/protocol.go`  
**Packet encoding**: `lib/relay/protocol/packets.go`  
**XDR encoding**: `lib/relay/protocol/packets_xdr.go` (auto-generated via `calmh/xdr`)

All messages use a **header + payload** framing format, XDR encoded:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          magic (0x9E79BC40)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       messageType (int32)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      messageLength (int32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                   message payload (variable)                  /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic**: `0x9E79BC40` — verified on both read and write
- **Max payload**: 1024 bytes
- **ALPN**: `"bep-relay"`

### 2.2 Message Types

| Constant | Type | Fields | Direction |
|---|---|---|---|
| `messageTypePing` (0) | `Ping` | (empty) | bidirectional |
| `messageTypePong` (1) | `Pong` | (empty) | bidirectional |
| `messageTypeJoinRelayRequest` (2) | `JoinRelayRequest` | `Token string` | client→relay |
| `messageTypeJoinSessionRequest` (3) | `JoinSessionRequest` | `Key []byte`(max 32) | client→relay (data connection) |
| `messageTypeResponse` (4) | `Response` | `Code int32, Message string` | relay→client |
| `messageTypeConnectRequest` (5) | `ConnectRequest` | `ID []byte`(max 32, device ID) | client→relay |
| `messageTypeSessionInvitation` (6) | `SessionInvitation` | `From, Key, Address []byte, Port uint16, ServerSocket bool` | relay→client |
| `messageTypeRelayFull` (7) | `RelayFull` | (empty) | relay→client |

### 2.3 Standard Responses

```go
ResponseSuccess           = Response{0, "success"}
ResponseNotFound          = Response{1, "not found"}
ResponseAlreadyConnected  = Response{2, "already connected"}
ResponseWrongToken        = Response{3, "wrong token"}
ResponseUnexpectedMessage = Response{100, "unexpected message"}
```

### 2.4 SessionInvitation Structure

```go
type SessionInvitation struct {
    From         []byte // Peer device ID (max 32 bytes)
    Key          []byte // 32-byte random session key
    Address      []byte // Relay IP address
    Port         uint16 // Relay port
    ServerSocket bool   // true=this side should act as the TLS server
}
```

The `ServerSocket` flag is crucial: it tells each end whether to act as TLS server or client when wrapping the data connection in TLS, so that mutual TLS handshake can complete through the relay.

---

## 3. Relay Server strelaysrv

**Key files**:
- `cmd/strelaysrv/main.go` — entry point, CLI, TLS setup
- `cmd/strelaysrv/listener.go` — TCP acceptance, protocol dispatch
- `cmd/strelaysrv/session.go` — session management, data forwarding
- `cmd/strelaysrv/pool.go` — pool registration
- `cmd/strelaysrv/status.go` — HTTP status API
- `cmd/strelaysrv/utils.go` — TCP socket tuning

### 3.1 Startup Flow

`main()` executes in order:

1. **Parse CLI arguments** — listen address (`:22067`), key directory, timeouts, rate limits, pool addresses, NAT options
2. **Load/generate TLS certificate** — uses `tlsutil.NewCertificate()`, CN=`"strelaysrv"`, 20-year validity
3. **Set up TLS config** — ALPN=`"bep-relay"`, request client certificates, specify TLS 1.2+ ciphers
4. **Compute device ID** — `syncthingprotocol.NewDeviceID(cert.Raw)`
5. **NAT setup** — UPnP/PMP (if enabled)
6. **Global rate limiter** — `golang.org/x/time/rate`
7. **Build relay URI** — `relay://<IP>:<port>/?id=<deviceID>&pingInterval=...&networkTimeout=...`
8. **Start pool registration** — launch a goroutine running `poolHandler()` for each pool URL
9. **Start TCP listener** — `listener()` goroutine using `DowngradingListener`
10. **Wait for SIGINT/SIGTERM** — graceful shutdown

### 3.2 Connection Acceptance (`listener.go`)

Uses `DowngradingListener` (`lib/tlsutil/tlsutil.go:175`) to read the first byte and distinguish TLS from raw TCP:

- **If byte == 0x16 (TLS record)**: treated as a **control channel**, handled by `protocolConnectionHandler`
- **If byte != 0x16**: treated as a **data channel**, handled by `sessionConnectionHandler`

**TCP socket options** (`utils.go`):
```go
tcpConn.SetLinger(0)               // disconnect immediately on close
tcpConn.SetNoDelay(true)           // disable Nagle
tcpConn.SetKeepAlive(true)         // enable TCP keepalive
tcpConn.SetKeepAlivePeriod(2min)   // 2 minutes
```

### 3.3 Control Channel Protocol (`protocolConnectionHandler`)

Each connecting client gets one TLS control connection.

**Authentication flow**:
1. The client connects via TLS; the relay verifies:
   - The client must present exactly 1 certificate
   - The device ID is derived from the certificate
2. The connection enters the message dispatch loop

**Message handling**:

| Message | Action |
|---|---|
| `JoinRelayRequest` | Join the relay. Verify token (if set). Check `overLimit`. Check duplicate IDs. Create outbox channel. Send `ResponseSuccess`. |
| `ConnectRequest` | Wants to connect to another peer. Look up the target's outbox channel. Create a `session` with two random 32-byte keys. Send `SessionInvitation` to both requester and target. |
| `Ping` | Reply with `Pong` |
| `Pong` | No-op |
| Unknown | Send `ResponseUnexpectedMessage` and disconnect |

**Keepalive mechanism**:
- `pingTicker` sends `Ping` every `pingInterval` (default 1 minute)
- `timeoutTicker` resets on every received message; if it fires (default 2 minutes), disconnect
- When over limit, clients without active sessions are disconnected with `RelayFull`

**Outbox pattern**:
Every joined client owns an outbox channel (`map[deviceID]chan interface{}`). When a `ConnectRequest` arrives, the server pushes a `SessionInvitation` to the target's outbox; the message dispatch loop writes it to the target's TLS control connection.

### 3.4 Session Management (`session.go`)

A **session** represents a proxied connection between two endpoints.

**Session lifecycle**:

1. **Creation** (`newSession`):
   - Generate two random 32-byte keys: `serverkey` and `clientkey`
   - Store in the `pendingSessions` map (keyed by both keys)
   - Each session has a `connsChan` (buffered channel of size 1)

2. **Invitation** — the server sends `SessionInvitation` to both sides; each side receives a different key

3. **Joining** — each side establishes a raw TCP connection to the relay and sends `JoinSessionRequest{Key: invitation.Key}`

4. **Proxy startup** — once both sides arrive, two goroutines run `session.proxy(c1, c2)`:
   ```go
   func (s *session) proxy(c1, c2 net.Conn) error {
       buf := make([]byte, 65536)
       for {
           c1.SetReadDeadline(time.Now().Add(networkTimeout))
           n, err := c1.Read(buf)
           if err != nil { return err }
           c2.SetWriteDeadline(time.Now().Add(networkTimeout))
           _, err = c2.Write(buf[:n])
           if err != nil { return err }
       }
   }
   ```
   This is a simple **read-from-A → write-to-B** loop with no protocol awareness.

5. **Teardown** — on error or timeout, remove from `pendingSessions` and `activeSessions`, close all connections.

**Timeout**: if both sides do not connect within `messageTimeout` (default 1 minute), the session times out.

### 3.5 Rate Limiting

Two independent token bucket limiters (`golang.org/x/time/rate`):

- **`--per-session-rate`**: per-session `rate.Limiter`, burst = 2x rate
- **`--global-rate`**: global `rate.Limiter`, across all sessions

`makeRateLimitFunc()` optimizes at session creation:
- `nil` — no rate limiting
- Only calls `take(bytes, globalRateLimit)`
- Only calls `take(bytes, sessionRateLimit)`
- Calls both

### 3.6 Resource Management

- **File descriptor limits**: at startup, `osutil.MaximizeOpenFileLimit()` raises the fd limit. 80% is used as `descriptorLimit`. `monitorLimits()` checks every minute.
- **Over-limit behavior**: new `JoinRelayRequest`s are rejected (`RelayFull`). Connected clients without active sessions are disconnected.
- **`numConnections`** — number of TLS control connections
- **`numProxies`** — number of active proxy goroutines (2 per session)

### 3.7 Pool Registration (`pool.go`)

`poolHandler()` goroutine:
1. HTTP POST to the pool server with JSON `{"url": "relay://..."}`
2. If the pool URL is HTTPS, send the relay's own TLS certificate as the client certificate
3. Parse the `evictionIn` duration
4. Sleep for `evictionIn - evictionIn/5` (re-register after 80% of the time)
5. On error, retry after 1 minute
6. On receiving `401 Unauthorized` (IP mismatch), abort permanently

### 3.8 Status Service (`status.go`)

HTTP server on `:22070`:
- `GET /status` — JSON: build info, uptime, session count, connection count, proxied bytes, rate history, options
- `GET /debug/pprof/` — if `-pprof` is enabled

The rate calculator tracks 60 minutes of throughput at 10-second intervals, reporting 10s/1m/5m/15m/30m/60m averages.

---

## 4. Relay Client Library

**Key files**:
- `lib/relay/client/client.go` — interface definitions
- `lib/relay/client/static.go` — static relay client
- `lib/relay/client/dynamic.go` — dynamic pool client
- `lib/relay/client/methods.go` — utility functions

### 4.1 Interface

```go
type RelayClient interface {
    suture.Service
    Error() error
    String() string
    Invitations() <-chan protocol.SessionInvitation
    URI() *url.URL
}
```

Created via `NewClient(uri, certs, timeout)`:
- `relay://...` → `staticClient`
- `dynamic+http://...` or `dynamic+https://...` → `dynamicClient`

### 4.2 Static Client (`staticClient`)

**`serve()` method**:
1. **Connect** (`connect()`): TCP dial + TLS handshake + ALPN `"bep-relay"` + optional relay ID verification
2. **Join** (`join()`): send `JoinRelayRequest` (optional token), expect `Response{0}` or `RelayFull`
3. **Message loop**: read messages on the control connection:
   - `Ping` → reply `Pong`
   - `SessionInvitation` → fix up the address and send to the `invitations` channel
   - `RelayFull` → return an error, triggering reconnect
   - Unknown → return an error
4. Uses a `messageTimeout` timer (2 minutes) as an inactivity timeout

**ID verification** (`performHandshakeAndValidation`):
If the relay URI contains `?id=<deviceID>`, verify that the relay's TLS certificate matches the advertised device ID.

### 4.3 Dynamic Client (`dynamicClient`)

Discovers relays from the pool server.

**`serve()` method**:
1. **Fetch the relay list**: HTTP GET to the pool endpoint
2. **Parse the response**: JSON `{"relays": [{"url": "relay://..."}, ...]}`
3. **Sort by latency**: `relayAddressesOrder()`:
   - Measure latency to each relay
   - Bucket into 50ms latency ranges
   - Shuffle randomly within buckets
   - Return sorted by ascending latency
4. **Try one by one**: create a `staticClient` for each relay and call `Serve()`. If disconnected (e.g. `RelayFull`), try the next.

### 4.4 Utility Functions (`methods.go`)

**`GetInvitationFromRelay(ctx, uri, peerID, certs, timeout)`** — used by the dialer:
1. Establish a TLS connection to the relay
2. TLS handshake + ALPN + ID verification
3. Send `ConnectRequest{ID: peerID[:]}`
4. Read the response: `Response` (error) or `SessionInvitation` (success)
5. Fix up the address if unspecified (use the connection's remote address)

**`JoinSession(ctx, invitation)`** — used by both dialer and listener:
1. Establish a raw TCP connection to the relay address:port
2. Send `JoinSessionRequest{Key: invitation.Key}`
3. Read `Response{0}` indicating success
4. Return the raw TCP connection (not TLS-wrapped)

---

## 5. Relay Pool Server strelaypoolsrv

**Key files**:
- `cmd/infra/strelaypoolsrv/main.go` — all HTTP handling
- `cmd/infra/strelaypoolsrv/stats.go` — relay statistics and Prometheus metrics

### 5.1 Architecture

The pool server is the **directory service** for relays. As an HTTP(S) server it provides these endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/endpoint` | GET | Returns a minimal relay list (URLs only) |
| `/endpoint/full` | GET | Returns the full relay list (with metadata, locations, statistics) |
| `/endpoint` | POST | Relay registration |
| `/` | GET | Status page |

### 5.2 Relay Registration (`handleRegister`)

Flow:
1. **IP extraction**: get the client IP from `RemoteAddr` or the configured `ip-header`
2. **Blacklist check**: per-host error counts are kept in an LRU cache. After 10 consecutive failures, the host receives `401 Unauthorized` (the relay aborts joining permanently)
3. **Certificate verification**: if the connection is TLS and the relay presented a client certificate, verify the advertised device ID matches the certificate
4. **IP verification**: if the relay's advertised IP differs from the connection IP and there is no TLS certificate, return `401`
5. **Deduplication check**: reject if the host matches a permanent relay
6. **Asynchronous testing**: the request is queued; a `requestProcessor` goroutine calls `client.TestRelay()` to verify the relay is reachable
7. **Statistics fetch**: call the relay's `/status` endpoint to collect operational metrics
8. **GeoIP lookup**: resolve the relay location from its IP (MaxMind GeoLite2)
9. **Eviction timer**: set a timer to remove the relay from the list when it expires
10. **Response**: return `{"evictionIn": <duration>}` (default 1 hour)
11. **Persistence**: save the relay URL to `knownRelaysFile`

### 5.3 Client Query Endpoints

**Short endpoint**: returns `{"relays": [{"url": "relay://..."}]}`, at most `maxRelaysReturned` (default 100), shuffled randomly when over the limit.

**Full endpoint**: includes GeoIP location, operational statistics, and rate history.

### 5.4 Statistics Collection (`stats.go`)

A `statsRefresher` goroutine fetches from each relay's `/status` every `statsRefresh` (default 1 minute):
- Uptime, session count, connection count, proxy count, proxied bytes, Go runtime info, rates
- Exposed via Prometheus metrics at `:8081/metrics`
- Gracefully handles counter resets (via `mergeStats()`)

---

## 6. Main syncthing Integration

### 6.1 Priority Connection System

| Connection type | Priority (default) |
|---|---|
| TCP LAN | 10 |
| QUIC LAN | 20 |
| TCP WAN | 30 |
| QUIC WAN | 40 |
| **Relay** | **50** (lowest) |

Relay connections have the **lowest** priority — used only when direct connections fail.

### 6.2 Relay as Listener (`relay_listen.go`)

`relayListenerFactory` registers schemes `relay`, `dynamic+http`, `dynamic+https`.

**`serve()`**: creates `client.NewClient()` and starts a `handleInvitations()` goroutine to process inbound session invitations.

**`handleInvitations()`**: listens on the `Invitations()` channel; for each invitation calls `client.JoinSession()`, then wraps in TLS (depending on the `ServerSocket` flag), and pushes to the shared `conns` channel.

### 6.3 Relay as Dialer (`relay_dial.go`)

**`Dial()`**:
1. Call `client.GetInvitationFromRelay()` — request a connection to the target device through the relay
2. Call `client.JoinSession()` — join the session on the data port
3. Set TCP options and traffic class
4. Wrap in TLS (depending on the `ServerSocket` flag)
5. Return `newInternalConn(tc, connTypeRelayClient, false, wanPriority)`

### 6.4 Relay vs Direct: Decision Flow

**`resolveDialTargets()`** (`service.go:656`):
1. Resolve device addresses (via configuration and/or discovery)
2. For each address:
   - Parse the URI scheme (`tcp://`, `relay://`, etc.)
   - Look up the corresponding dialer factory
   - Check whether the dialer priority beats the cutoff value
   - Build a `dialTarget` (with priority, dialer, URI)

**`dialParallel()`** (`service.go:1139`):
1. Group targets by priority
2. Dial all targets of the same priority level in parallel (max 8 per device, max 64 globally)
3. Return the **first successful connection**
4. Remaining same-level connections are discarded
5. If no connection succeeds at the current priority level, move to the next level

### 6.5 Default Configuration

Default listen addresses:
```go
"default"  // expands to:
    "tcp://0.0.0.0:22000"
    "dynamic+https://relays.syncthing.net/endpoint"
```

By default Syncthing:
- Listens on TCP port 22000
- Connects to the public relay pool `relays.syncthing.net` (accepting inbound relay connections as a client)
- Uses the pool to discover relay servers needed for outbound connections

---

## 7. End-to-End Connection Flow

### Scenario: Client A wants to connect to client B through a relay

```
1. Discovery:
   Client A learns B's addresses via global discovery
   Returned: ["tcp://1.2.3.4:22000", "relay://relay.example.com:22067?id=<B's ID>", ...]

2. Dial loop (service.go:connect):
   - Group targets by priority:
     Priority 10: TCP LAN addresses
     Priority 30: TCP WAN addresses
     Priority 50: relay://relay.example.com

3. Try high priorities first:
   - Attempt TCP connections -- all fail (B is behind NAT)

4. Fall back to relay (priority 50):
   relayDialer.Dial(ctx, B's ID, relayURI):
     a. TLS-connect to relay.example.com:22067
     b. Negotiate ALPN "bep-relay"
     c. Send ConnectRequest{ID: B's device ID bytes}

5. Relay handles the ConnectRequest:
   a. Look up B's outbox channel
   b. Create a new session (random keys)
   c. Send SessionInvitation to A (over A's control connection)
   d. Send SessionInvitation to B (via B's outbox channel)
   e. Close A's control connection

6. Client B receives SessionInvitation over its control connection:
   relayListener.handleInvitations():
     a. Call JoinSession(invitation)
     b. Open TCP to relay:22067 (raw socket)
     c. Send JoinSessionRequest{Key: B's session key}
     d. Receive Response{0}
     e. Wrap as TLS server (ServerSocket=true)
     f. Push to the conns channel

7. Client A (after GetInvitationFromRelay returns):
   a. Call JoinSession(invitation)
   b. Open TCP to relay:22067 (raw socket)
   c. Send JoinSessionRequest{Key: A's session key}
   d. Receive Response{0}
   e. Wrap as TLS client (ServerSocket=false)

8. Relay session.go:
   - Both side connections arrive at the session
   - Session.Serve() starts two proxy goroutines
   - Data flow: A ↔ relay ↔ B (raw TCP relaying)

9. Through the tunnel:
   - A and B perform mutual TLS handshake through the relay
   - TLS handshake succeeds (the ServerSocket flag ensures correct roles)
   - Exchange BEP Hello messages
   - Normal syncthing protocol begins

10. Connection management:
    - When either side disconnects from the relay, the relay detects it via proxy read errors
    - Session cleanup removes it from activeSessions
    - Client B's relay listener detects the disconnect and may try another relay from the pool
    - Priority system monitoring: if a better (TCP/QUIC) connection becomes available, the relay connection is closed with errReplacingConnection
```

---

## 8. Key File Index

| File | Role |
|---|---|
| `cmd/strelaysrv/main.go` | Relay server entry point, CLI, TLS, URI construction |
| `cmd/strelaysrv/listener.go` | TCP acceptance, protocol dispatch, control message handling |
| `cmd/strelaysrv/session.go` | Session lifecycle, data proxy loops, rate limiting |
| `cmd/strelaysrv/pool.go` | Pool server registration (HTTP POST heartbeat) |
| `cmd/strelaysrv/status.go` | HTTP status endpoint, rate calculator |
| `cmd/strelaysrv/utils.go` | TCP socket option tuning |
| `lib/relay/protocol/protocol.go` | Wire protocol: ReadMessage/WriteMessage, magic, standard responses |
| `lib/relay/protocol/packets.go` | Message type definitions (Ping/Pong/JoinRelayRequest etc.) |
| `lib/relay/protocol/packets_xdr.go` | Auto-generated XDR codec |
| `lib/relay/client/client.go` | RelayClient interface + factory (NewClient) |
| `lib/relay/client/static.go` | Static relay client: connect, join, invitation handling |
| `lib/relay/client/dynamic.go` | Dynamic pool client: fetch relay list, latency sorting, failover |
| `lib/relay/client/methods.go` | GetInvitationFromRelay, JoinSession, TestRelay |
| `lib/connections/relay_listen.go` | Relay listener: inbound relay connections |
| `lib/connections/relay_dial.go` | Relay dialer: outbound relay connections |
| `lib/connections/service.go` | Connection service: dial loop, priority system, parallel dialing, authentication |
| `lib/connections/structs.go` | internalConn, connType, dialTarget, commonDialer, priority |
| `lib/connections/dialqueue.go` | Dial queue ordering (newest first, old records shuffled) |
| `lib/connections/tcp_dial.go` | TCP dialer (higher priority than relay) |
| `lib/config/optionsconfiguration.go` | Configuration: RelaysEnabled, ConnectionPriorityRelay, etc. |
| `lib/tlsutil/tlsutil.go` | DowngradingListener TLS/raw-TCP demultiplexing |
| `cmd/infra/strelaypoolsrv/main.go` | Pool server: registration, query endpoints, blacklist, eviction |
| `cmd/infra/strelaypoolsrv/stats.go` | Pool server: statistics collection, Prometheus metrics |

# Varwof Gateway Capability Reference

> scheme_id: `varwof/gateway` · Version `1.1.0` · Vendor `varwof` / Product `gateway`

Varwof gateway operation capabilities (Management API + data plane)

Full capability identifier format: `varwof/gateway:capability_id` (e.g., `varwof/gateway:cert:issue`).

## Capability Catalog

| Capability | Summary | Related Capabilities |
|------|------|----------|
| `admin:agents` | Agent directory and disconnect management | admin:connections |
| `admin:branch` | Policy branch control (canary release) | admin:policy |
| `admin:config` | Read/modify gateway configuration | admin:reload |
| `admin:connections` | Real-time connection/access point view | ops:metrics |
| `admin:plugins` | Manage capability plugins (register/replace/delete) | ops:plugins |
| `admin:policy` | Policy versioning and rollback | admin:branch |
| `admin:reload` | Hot-reload configuration | admin:config |
| `admin:renewal` | Confirmed renewal management (request/confirm/reject) | admin:agents |
| `audit:chain` | Cross-gateway audit chain DAG references | audit:read |
| `audit:read` | Read audit logs | audit:verify, audit:search |
| `audit:search` | Audit full-text search | audit:read |
| `audit:verify` | Verify audit chain/Merkle integrity | audit:read |
| `ops:health` | Health check | ops:metrics |
| `ops:metrics` | Read Prometheus metrics | ops:health |
| `ops:plugins` | View capability plugin list | admin:plugins |
| `proxy:grpc` | gRPC proxy data plane | proxy:http |
| `proxy:http` | HTTP/HTTPS reverse proxy data plane | proxy:websocket, proxy:grpc |
| `proxy:quic` | QUIC/HTTP3 proxy data plane | proxy:udp, proxy:http |
| `proxy:tcp` | TCP transparent proxy data plane | proxy:http |
| `proxy:udp` | UDP forwarding data plane | proxy:quic |
| `proxy:websocket` | WebSocket proxy data plane | proxy:http |

## Detailed Capability Semantics

> Reading guide: the `usage`/`when_not`/`examples` in this section are used to determine **when a capability is needed and when it should not be granted**. AI should use them as the basis for generating least-privilege capability sets.

### `admin:agents`

**Summary**: Agent directory and disconnect management

**Description**: Agent directory and disconnect management

**When needed**: Use when you need to view online agents or actively disconnect misbehaving agents.

**When not to grant**: An agent's own tasks do not require managing other agents.

**Examples**:

- Kick an abnormal agent connection

**Related capabilities**: `admin:connections`

---

### `admin:branch`

**Summary**: Policy branch control (canary release)

**Description**: Policy branch control (canary release)

**When needed**: Use when you need to roll out different policy versions to agent groups in a canary fashion.

**When not to grant**: Not needed when policies are globally uniform.

**Examples**:

- Canary-roll-out a new policy to specific agents

**Related capabilities**: `admin:policy`

---

### `admin:config`

**Summary**: Read/modify gateway configuration

**Description**: Read/modify gateway configuration

**When needed**: Use when adjusting gateway listeners, routes, or upstream configuration.

**When not to grant**: Strictly forbidden for routine data-plane tasks; only operations administrators need it.

**Examples**:

- Modify route mappings

**Parameters**:

| Parameter | Type | Default | Constraints | Description |
|------|------|--------|------|------|
| `config_key` | `string` |  |  | Configuration keys allowed for access (empty = all) |

**Related capabilities**: `admin:reload`

---

### `admin:connections`

**Summary**: Real-time connection/access point view

**Description**: Real-time connection/access point view

**When needed**: Use when monitoring currently active connections or viewing access points. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View current connection count

**Related capabilities**: `ops:metrics`

---

### `admin:plugins`

**Summary**: Manage capability plugins (register/replace/delete)

**Description**: Manage capability plugins (register/replace/delete)

**When needed**: Use when dynamically adjusting capability decision plugins (allowlist/denylist/rbac).

**When not to grant**: Not needed for pure data-plane tasks.

**Examples**:

- Replace the RBAC plugin

**Related capabilities**: `ops:plugins`

---

### `admin:policy`

**Summary**: Policy versioning and rollback

**Description**: Policy versioning and rollback

**When needed**: Use when managing authorization policy versions or performing rollbacks.

**When not to grant**: For read-only policy viewing, `ops:plugins` is sufficient.

**Examples**:

- Roll back to the previous policy version

**Related capabilities**: `admin:branch`

---

### `admin:reload`

**Summary**: Hot-reload configuration

**Description**: Hot-reload configuration

**When needed**: Use when configuration changes need to be applied without interruption.

**When not to grant**: Not needed for tasks without configuration changes.

**Examples**:

- Trigger configuration reload via SIGHUP

**Related capabilities**: `admin:config`

---

### `admin:renewal`

**Summary**: Confirmed renewal management (request/confirm/reject)

**Description**: Confirmed renewal management (request/confirm/reject)

**When needed**: Use when managing the confirmed renewal workflow for short-lived certificates.

**When not to grant**: Not needed when short-lived certificates are not used.

**Examples**:

- Confirm an agent certificate renewal

**Related capabilities**: `admin:agents`

---

### `audit:chain`

**Summary**: Cross-gateway audit chain DAG references

**Description**: Cross-gateway audit chain DAG references

**When needed**: Use when viewing cross-gateway audit chain reference relationships. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View cross-gateway audit chains

**Related capabilities**: `audit:read`

---

### `audit:read`

**Summary**: Read audit logs

**Description**: Read audit logs

**When needed**: Use when viewing gateway access/connection audit records. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View connection audits

**Related capabilities**: `audit:verify`, `audit:search`

---

### `audit:search`

**Summary**: Audit full-text search

**Description**: Audit full-text search

**When needed**: Use when searching audit records by keyword/time range. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- Search audit records of a specific agent

**Related capabilities**: `audit:read`

---

### `audit:verify`

**Summary**: Verify audit chain/Merkle integrity

**Description**: Verify audit chain/Merkle integrity

**When needed**: Use when verifying the hash-chain integrity of audit logs (tamper evidence). Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- Verify the audit chain

**Related capabilities**: `audit:read`

---

### `ops:health`

**Summary**: Health check

**Description**: Health check

**When needed**: Use when probing gateway liveness. Public capability.

**When not to grant**: No restrictions; usually public.

**Examples**:

- Load balancer health checks

**Related capabilities**: `ops:metrics`

---

### `ops:metrics`

**Summary**: Read Prometheus metrics

**Description**: Read Prometheus metrics

**When needed**: Use when scraping gateway monitoring metrics (connection count/PPS/latency). Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- Prometheus metric scraping

**Related capabilities**: `ops:health`

---

### `ops:plugins`

**Summary**: View capability plugin list

**Description**: View capability plugin list

**When needed**: Use when viewing currently loaded plugins and their scheme definitions. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View registered plugins

**Related capabilities**: `admin:plugins`

---

### `proxy:grpc`

**Summary**: gRPC proxy data plane

**Description**: gRPC proxy data plane

**When needed**: Use when proxying gRPC bidirectional streaming services.

**When not to grant**: Not needed for REST/HTTP services.

**Examples**:

- Proxy gRPC microservices

**Related capabilities**: `proxy:http`

---

### `proxy:http`

**Summary**: HTTP/HTTPS reverse proxy data plane

**Description**: HTTP/HTTPS reverse proxy data plane

**When needed**: Use when accessing HTTP/HTTPS backend services (web applications, REST APIs) through the gateway. The most common data-plane capability.

**When not to grant**: Not needed for TCP/UDP-specific protocol services; not needed for pure management operations.

**Examples**:

- Access internal web services through the gateway
- Call backend REST APIs

**Related capabilities**: `proxy:websocket`, `proxy:grpc`

---

### `proxy:quic`

**Summary**: QUIC/HTTP3 proxy data plane

**Description**: QUIC/HTTP3 proxy data plane

**When needed**: Use when QUIC/HTTP3 client access must be supported.

**When not to grant**: Not needed for traditional TCP clients.

**Examples**:

- Web services supporting HTTP3

**Related capabilities**: `proxy:udp`, `proxy:http`

---

### `proxy:tcp`

**Summary**: TCP transparent proxy data plane

**Description**: TCP transparent proxy data plane

**When needed**: Use when forwarding arbitrary TCP protocols (SSH, databases, custom protocols).

**When not to grant**: For HTTP services, `proxy:http` is sufficient.

**Examples**:

- Access SSH services through the gateway
- Forward MySQL connections

**Related capabilities**: `proxy:http`

---

### `proxy:udp`

**Summary**: UDP forwarding data plane

**Description**: UDP forwarding data plane

**When needed**: Use when forwarding UDP traffic (DNS, audio/video, gaming).

**When not to grant**: Not needed for TCP/HTTP services.

**Examples**:

- Forward DNS queries through the gateway

**Related capabilities**: `proxy:quic`

---

### `proxy:websocket`

**Summary**: WebSocket proxy data plane

**Description**: WebSocket proxy data plane

**When needed**: Use when proxying WebSocket long-lived connections (real-time push, chat).

**When not to grant**: Not needed for ordinary HTTP requests.

**Examples**:

- Proxy a real-time message push service

**Related capabilities**: `proxy:http`

---

## Wildcards and Matching Rules

Grant/capability matching supports glob wildcards, used for role authorization and least-privilege validation:

| Pattern | Meaning | Example |
|------|------|------|
| `capability_id` | Exact match | `cert:issue` |
| `domain:*` | Prefix wildcard (all actions under that domain) | `ca:*` matches `ca:list`, `ca:create` |
| `*` / `**` | Full wildcard (all capabilities) | Dangerous; avoid whenever possible |
| `?` | Single-character wildcard | Rarely used |

**Least-privilege principle**: Role grants and AI-generated capability sets should use **exact capabilities** wherever possible; use `domain:*` only when the entire domain is genuinely required.

## Roles and Authorization Mapping

### Role `agent`

**Name**: AI Agent (data plane)

**Profiles**: `agent-proxy`

**Granted capabilities (grants)**:

- `proxy:*`

### Role `gateway:admin`

**Name**: Gateway administrator

**Profiles**: `m-admin`

**Bindable OUs**: `gateway:admin`

**Granted capabilities (grants)**:

- `proxy:*`
- `admin:config`
- `admin:reload`
- `admin:plugins`
- `admin:policy`
- `admin:branch`
- `admin:renewal`
- `admin:agents`
- `admin:connections`
- `ops:metrics`
- `ops:plugins`
- `ops:health`
- `audit:read`
- `audit:verify`
- `audit:search`
- `audit:chain`

### Role `gateway:audit`

**Name**: Gateway auditor

**Profiles**: `m-auditor`

**Bindable OUs**: `gateway:audit`

**Granted capabilities (grants)**:

- `audit:read`
- `audit:verify`
- `audit:search`
- `audit:chain`
- `ops:health`

### Role `gateway:ops`

**Name**: Gateway operator

**Profiles**: `m-operator`

**Bindable OUs**: `gateway:ops`

**Granted capabilities (grants)**:

- `proxy:*`
- `admin:reload`
- `admin:renewal`
- `admin:connections`
- `ops:metrics`
- `ops:plugins`
- `ops:health`

### Role `gateway:read`

**Name**: Gateway read-only

**Profiles**: `m-readonly`

**Bindable OUs**: `gateway:read`

**Granted capabilities (grants)**:

- `ops:metrics`
- `ops:health`

## Least-Privilege Generation Guide (AI/Developers)

Follow these rules when generating capability sets for a task:

1. **Grant only capabilities required by the task**: Judge against each capability's `usage` (when needed); do not grant anything explicitly stated in `when_not`.
2. **Prefer exact matches**: Use exact `capability_id` instead of wildcards; prefer a single capability over domain wildcard `domain:*`.
3. **Narrow parameters**: For capabilities with `parameters`, set defaults/ranges according to actual task needs — narrower is better than broader.
4. **Prefer read-only**: Read-only capabilities (`*:list`, `*:read`, `*:view`) take precedence over write capabilities.
5. **Disable dangerous capabilities**: Sensitive capabilities such as `key:recover`, `ca:delete`, and `config:write` are not granted by default unless the task explicitly requires them.
6. **Remove redundancy**: Exact capabilities already covered by a wildcard may be omitted; delete all capabilities unrelated to the task.

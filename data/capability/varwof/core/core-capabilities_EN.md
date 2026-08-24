# Varwof PKI Core Capability Reference

> scheme_id: `varwof/core` · Version `1.1.0` · Vendor `varwof` / Product `core`

Varwof PKI core engine operation capabilities

Full capability identifier format: `varwof/core:capability_id` (e.g., `varwof/core:cert:issue`).

## Capability Catalog

| Capability | Summary | Related Capabilities |
|------|------|----------|
| `agent:manage` | Manage AI agents (registration/disconnect/configuration) | cert:issue |
| `ca:create` | Create a new certificate authority (CA) | ca:list, ca:info, ca:issue-sub |
| `ca:delete` | Delete an existing certificate authority | ca:create |
| `ca:info` | View details of a single CA | ca:list |
| `ca:issue-sub` | Issue sub-CA certificates (hierarchy extension) | ca:create, cert:issue |
| `ca:list` | List all CAs | ca:info |
| `cert:batch` | Batch-issue multiple certificates | cert:issue |
| `cert:export` | Export certificates (PEM/DER formats) | cert:list |
| `cert:issue` | Issue end-entity certificates | cert:renew, cert:revoke, cert:list |
| `cert:list` | Query certificate list (filterable by CA/status/subject) | ca:list, cert:info |
| `cert:renew` | Renew an existing certificate | cert:issue, cert:revoke |
| `cert:revoke` | Revoke an issued certificate | cert:issue, cert:list |
| `config:read` | Read system configuration | config:write |
| `config:write` | Modify system configuration | config:read |
| `crl:generate` | Generate certificate revocation lists (CRL) | cert:revoke, crl:read |
| `crl:read` | Read CRL contents | crl:generate, cert:list |
| `cross-cert:issue` | Issue cross certificates (cross-trust-domain bridging) | ca:issue-sub |
| `cross-cert:revoke` | Revoke cross certificates | cross-cert:issue |
| `dns:manage` | Manage DNS records (domain validation before issuance) | cert:issue |
| `key:recover` | Key recovery (private key retrieval) | cert:issue |
| `log:export` | Export audit logs | log:read |
| `log:read` | Read audit logs | log:export |
| `ocsp:respond` | OCSP online certificate status responses | cert:revoke, crl:read |
| `ra:approve` | RA approval (registration authority approval) | ra:reject, cert:issue |
| `ra:reject` | RA approval rejection | ra:approve |
| `report:export` | Export report data | report:view, report:generate |
| `report:generate` | Generate new reports | report:view |
| `report:view` | View statistical reports | report:generate, report:export |
| `swagger:view` | View API documentation (Swagger/OpenAPI) | web:view |
| `trust:delete` | Delete trust anchors | trust:import |
| `trust:import` | Import trust anchors/root certificates | trust:list, trust:delete |
| `trust:list` | Query the trust anchor list | trust:import |
| `user:list` | Query the user list | user:manage |
| `user:manage` | Manage user accounts (create/delete/change roles) | user:list, user:revoke-all |
| `user:revoke-all` | Revoke all certificates of a user | user:manage, cert:revoke |
| `web:view` | Access the web console | swagger:view |
| `webhook:manage` | Manage webhook notifications (create/delete/change URL) | cert:issue, cert:revoke |

## Detailed Capability Semantics

> Reading guide: the `usage`/`when_not`/`examples` in this section are used to determine **when a capability is needed and when it should not be granted**. AI should use them as the basis for generating least-privilege capability sets.

### `agent:manage`

**Summary**: Manage AI agents (registration/disconnect/configuration)

**Description**: Manage AI agents

**When needed**: Use when managing identities and sessions of AI agents connected to gateways.

**When not to grant**: An agent executing its own tasks does not need the ability to manage other agents.

**Examples**:

- Kick an abnormal agent connection

**Related capabilities**: `cert:issue`

---

### `ca:create`

**Summary**: Create a new certificate authority (CA)

**Description**: Create a CA

**When needed**: Use when initializing a new PKI hierarchy, establishing a new trust root, or issuing a sub-CA. This is a one-time initialization operation; once creation is complete, repeated authorization is usually unnecessary.

**When not to grant**: Routine certificate issuance/query tasks do not need it; only operations administrators initializing the PKI do.

**Examples**:

- Initialize a Root CA
- Create a new Sub CA

**Related capabilities**: `ca:list`, `ca:info`, `ca:issue-sub`

---

### `ca:delete`

**Summary**: Delete an existing certificate authority

**Description**: Delete a CA

**When needed**: Use when completely removing a decommissioned CA and its associated configuration. Dangerous operation, usually restricted to super administrators.

**When not to grant**: Strictly forbidden for routine issuance and query tasks; deletion affects the entire chain of trust.

**Examples**:

- Clean up a deprecated test CA

**Related capabilities**: `ca:create`

---

### `ca:info`

**Summary**: View details of a single CA

**Description**: View CA details

**When needed**: Use when viewing CA certificate, validity period, status, and other details.

**When not to grant**: No special restrictions; read-only capability.

**Examples**:

- Check CA certificate validity
- View basic CA information

**Related capabilities**: `ca:list`

---

### `ca:issue-sub`

**Summary**: Issue sub-CA certificates (hierarchy extension)

**Description**: Issue sub-CA certificates

**When needed**: Use when extending the PKI hierarchy or creating sub-CAs for independent business domains.

**When not to grant**: Ordinary certificate issuance (cert:issue) does not require this capability; it is only needed when creating new CA levels.

**Examples**:

- Create an independent sub-CA for a department
- Establish multi-level chains of trust

**Parameters**:

| Parameter | Type | Default | Constraints | Description |
|------|------|--------|------|------|
| `ca_scope` | `list` |  |  | Range of sub-CAs that may be issued (limits sub-CA scope) |
| `max_validity_days` | `int` | 1825 | min=1, max=3650 | Maximum validity period (days) |

**Related capabilities**: `ca:create`, `cert:issue`

---

### `ca:list`

**Summary**: List all CAs

**Description**: List CAs

**When needed**: Use when viewing which CAs exist in the system (browsing the PKI structure, choosing an issuance target).

**When not to grant**: No special restrictions; read-only capability suitable as baseline authorization for most roles.

**Examples**:

- Browse the list of available CAs
- Confirm the target issuance CA exists

**Related capabilities**: `ca:info`

---

### `cert:batch`

**Summary**: Batch-issue multiple certificates

**Description**: Batch-issue certificates

**When needed**: Use when issuing certificates for many devices/services at once (bulk onboarding, bulk expansion).

**When not to grant**: For single-certificate issuance, cert:issue suffices; no batch permission needed.

**Examples**:

- Batch-issue certificates for 100 devices

**Related capabilities**: `cert:issue`

---

### `cert:export`

**Summary**: Export certificates (PEM/DER formats)

**Description**: Export certificates

**When needed**: Use when downloading certificate files, delivering them to peers, or backing them up. Read-only capability.

**When not to grant**: No special restrictions, but note that what is exported is the public certificate, not the private key.

**Examples**:

- Export a service certificate for Nginx configuration
- Download a certificate for client deployment

**Related capabilities**: `cert:list`

---

### `cert:issue`

**Summary**: Issue end-entity certificates

**Description**: Issue certificates

**When needed**: Use when issuing new certificates for services, devices, users, or agents. The most common certificate operation.

**When not to grant**: Pure query tasks (list/info) do not need it; renewing an existing certificate should use cert:renew rather than re-issuance.

**Examples**:

- Issue a certificate for an HTTPS service
- Issue an AIC certificate for an AI agent
- Issue client mTLS certificates

**Parameters**:

| Parameter | Type | Default | Constraints | Description |
|------|------|--------|------|------|
| `ca_scope` | `list` |  |  | List of CAs allowed for issuance (limits sub-CA issuance scope) |
| `max_validity_days` | `int` | 365 | min=1, max=3650 | Maximum validity period (days) |

**Related capabilities**: `cert:renew`, `cert:revoke`, `cert:list`

---

### `cert:list`

**Summary**: Query certificate list (filterable by CA/status/subject)

**Description**: Query certificate list

**When needed**: Use when searching issued certificates or checking certificate status (valid/revoked/expired). Read-only capability.

**When not to grant**: No special restrictions; read-only capability suitable as baseline authorization.

**Examples**:

- List all certificates under a CA
- Look up the revocation status of a certificate

**Related capabilities**: `ca:list`, `cert:info`

---

### `cert:renew`

**Summary**: Renew an existing certificate

**Description**: Renew certificates

**When needed**: Use when a certificate is about to expire and the same subject must continue operating. Usually keeps the original public key or regenerates it.

**When not to grant**: New subjects connecting for the first time should use cert:issue; reclaiming expired certificates should use cert:revoke.

**Examples**:

- Automatically renew service certificates
- Renew agent certificates at expiry

**Related capabilities**: `cert:issue`, `cert:revoke`

---

### `cert:revoke`

**Summary**: Revoke an issued certificate

**Description**: Revoke certificates

**When needed**: Use when a certificate's private key is compromised, the subject is no longer legitimate, or a completed task requires certificate reclamation.

**When not to grant**: Read-only tasks do not need it; revocation is a sensitive operation and should be scoped as narrowly as possible.

**Examples**:

- Revoke a certificate after private key compromise
- Revoke a temporary certificate after agent task completion

**Parameters**:

| Parameter | Type | Default | Constraints | Description |
|------|------|--------|------|------|
| `ca_scope` | `list` |  |  | List of CAs allowed for revocation |

**Related capabilities**: `cert:issue`, `cert:list`

---

### `config:read`

**Summary**: Read system configuration

**Description**: Read configuration

**When needed**: Use when viewing current configuration (listen ports, CA paths, etc.). Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View current configuration

**Related capabilities**: `config:write`

---

### `config:write`

**Summary**: Modify system configuration

**Description**: Modify configuration

**When needed**: Use when changing configuration with hot reload. Sensitive operation; changes may affect all services.

**When not to grant**: Strictly forbidden for routine tasks; only operations administrators need it.

**Examples**:

- Modify certificate validity configuration

**Related capabilities**: `config:read`

---

### `crl:generate`

**Summary**: Generate certificate revocation lists (CRL)

**Description**: Generate CRLs

**When needed**: Use when generating/updating CRLs for client validation after a revocation occurs.

**When not to grant**: Pure query tasks do not need it; usually triggered automatically by the revocation workflow.

**Examples**:

- Generate the latest CRL after a revocation

**Related capabilities**: `cert:revoke`, `crl:read`

---

### `crl:read`

**Summary**: Read CRL contents

**Description**: Read CRLs

**When needed**: Use when clients validate certificate revocation status or during audit checks. Read-only capability.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- Check whether a CRL contains a given certificate

**Related capabilities**: `crl:generate`, `cert:list`

---

### `cross-cert:issue`

**Summary**: Issue cross certificates (cross-trust-domain bridging)

**Description**: Issue cross certificates

**When needed**: Use when establishing trust bridges between two PKI domains. Advanced PKI operation.

**When not to grant**: Not needed for issuance within a single domain.

**Examples**:

- Mutual trust between two enterprise PKIs

**Related capabilities**: `ca:issue-sub`

---

### `cross-cert:revoke`

**Summary**: Revoke cross certificates

**Description**: Revoke cross certificates

**When needed**: Use when withdrawing a cross-domain trust bridge.

**When not to grant**: Not needed for single-domain operations.

**Examples**:

- Withdraw inter-enterprise trust

**Related capabilities**: `cross-cert:issue`

---

### `dns:manage`

**Summary**: Manage DNS records (domain validation before issuance)

**Description**: Manage DNS

**When needed**: Use when creating DNS validation records for certificate issuance (ACME challenges, etc.).

**When not to grant**: Not needed for issuance tasks that do not involve domain validation.

**Examples**:

- Create _acme-challenge DNS records

**Related capabilities**: `cert:issue`

---

### `key:recover`

**Summary**: Key recovery (private key retrieval)

**Description**: Key recovery

**When needed**: Use when recovering a private key from key escrow. Extremely sensitive operation.

**When not to grant**: Strictly forbidden for routine tasks; only key escrow administrators should be authorized.

**Examples**:

- Recover a lost service private key

**Related capabilities**: `cert:issue`

---

### `log:export`

**Summary**: Export audit logs

**Description**: Export audit logs

**When needed**: Use when delivering logs to SIEM systems, offline archiving, or compliance audits.

**When not to grant**: For viewing only, log:read is sufficient.

**Examples**:

- Export the last 30 days of logs to the audit system

**Related capabilities**: `log:read`

---

### `log:read`

**Summary**: Read audit logs

**Description**: Read audit logs

**When needed**: Use when reviewing operation records or troubleshooting. Read-only capability.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View recent certificate issuance records

**Related capabilities**: `log:export`

---

### `ocsp:respond`

**Summary**: OCSP online certificate status responses

**Description**: OCSP responses

**When needed**: Use when providing OCSP online revocation status query services. Usually held by the core service itself.

**When not to grant**: Ordinary agent/user tasks do not need this capability.

**Examples**:

- Run the OCSP responder service

**Related capabilities**: `cert:revoke`, `crl:read`

---

### `ra:approve`

**Summary**: RA approval (registration authority approval)

**Description**: RA approval

**When needed**: Use when approving pending certificate requests (manual review workflows).

**When not to grant**: Fully automated issuance does not need RA approval capability.

**Examples**:

- Approve a pending server certificate request

**Related capabilities**: `ra:reject`, `cert:issue`

---

### `ra:reject`

**Summary**: RA approval rejection

**Description**: RA rejection

**When needed**: Use when rejecting non-compliant certificate requests.

**When not to grant**: Same as ra:approve; only approvers need it.

**Examples**:

- Reject a forged certificate request

**Related capabilities**: `ra:approve`

---

### `report:export`

**Summary**: Export report data

**Description**: Export reports

**When needed**: Use when downloading report data (CSV/JSON).

**When not to grant**: For page viewing only, report:view is sufficient.

**Examples**:

- Export reports to the finance system

**Related capabilities**: `report:view`, `report:generate`

---

### `report:generate`

**Summary**: Generate new reports

**Description**: Generate reports

**When needed**: Use when generating statistical reports with custom conditions.

**When not to grant**: For viewing preset reports only, report:view is sufficient.

**Examples**:

- Generate an issuance report for a custom time range

**Related capabilities**: `report:view`

---

### `report:view`

**Summary**: View statistical reports

**Description**: View reports

**When needed**: Use when viewing statistics such as certificate issuance and revocation volumes. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View monthly issuance reports

**Related capabilities**: `report:generate`, `report:export`

---

### `swagger:view`

**Summary**: View API documentation (Swagger/OpenAPI)

**Description**: View API documentation

**When needed**: Use when browsing API interface documentation. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View API interface descriptions

**Related capabilities**: `web:view`

---

### `trust:delete`

**Summary**: Delete trust anchors

**Description**: Delete trust anchors

**When needed**: Use when withdrawing trust in an external CA.

**When not to grant**: Not needed unless external trust management is involved.

**Examples**:

- Remove a CA that is no longer trusted

**Related capabilities**: `trust:import`

---

### `trust:import`

**Summary**: Import trust anchors/root certificates

**Description**: Import trust anchors

**When needed**: Use when trusting a new external CA.

**When not to grant**: Not needed for tasks that do not involve external trust.

**Examples**:

- Import a customer CA certificate

**Related capabilities**: `trust:list`, `trust:delete`

---

### `trust:list`

**Summary**: Query the trust anchor list

**Description**: Query trust anchors

**When needed**: Use when viewing which external CAs are currently trusted. Read-only.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- View trusted CAs

**Related capabilities**: `trust:import`

---

### `user:list`

**Summary**: Query the user list

**Description**: Query the user list

**When needed**: Use when viewing system users or confirming identities. Read-only capability.

**When not to grant**: No special restrictions; read-only.

**Examples**:

- List all users

**Related capabilities**: `user:manage`

---

### `user:manage`

**Summary**: Manage user accounts (create/delete/change roles)

**Description**: Manage users

**When needed**: Use when managing PKI user identities and assigning role permissions. Sensitive administrative operation.

**When not to grant**: Ordinary certificate operation tasks do not need user management permissions.

**Examples**:

- Create a new user
- Assign a role to a user

**Related capabilities**: `user:list`, `user:revoke-all`

---

### `user:revoke-all`

**Summary**: Revoke all certificates of a user

**Description**: Revoke all certificates of a user

**When needed**: Use when a user leaves the organization or an account is compromised and all certificates under their name must be revoked.

**When not to grant**: For single-certificate revocation, cert:revoke is sufficient.

**Examples**:

- Revoke all certificates after a user departs

**Related capabilities**: `user:manage`, `cert:revoke`

---

### `web:view`

**Summary**: Access the web console

**Description**: Access the web console

**When needed**: Use when logging into the web management interface.

**When not to grant**: Not needed for pure API-call tasks.

**Examples**:

- Log into the management console

**Related capabilities**: `swagger:view`

---

### `webhook:manage`

**Summary**: Manage webhook notifications (create/delete/change URL)

**Description**: Manage webhooks

**When needed**: Use when configuring certificate event notifications (issuance/revocation/expiry) to external systems.

**When not to grant**: Not needed for tasks that do not subscribe to notifications.

**Examples**:

- Configure a certificate expiry reminder webhook

**Related capabilities**: `cert:issue`, `cert:revoke`

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

### Role `admin`

**Name**: Administrator

**Profiles**: `m-admin`

**Bindable OUs**: `admin`, `Admin`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:issue`
- `cert:revoke`
- `cert:renew`
- `cert:list`
- `cert:export`
- `cert:batch`
- `crl:generate`
- `log:read`
- `log:export`
- `report:view`
- `report:export`
- `report:generate`
- `ra:approve`
- `ra:reject`
- `cross-cert:issue`
- `cross-cert:revoke`
- `webhook:manage`
- `key:recover`
- `dns:manage`
- `trust:import`
- `trust:list`
- `trust:delete`
- `agent:manage`
- `swagger:view`
- `web:view`

### Role `agent`

**Name**: AI Agent

**Profiles**: `agent-proxy`

**Granted capabilities (grants)**:

- `gateway:*`

### Role `auditor`

**Name**: Auditor

**Profiles**: `m-auditor`

**Bindable OUs**: `auditor`, `Auditor`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:list`
- `log:read`
- `log:export`
- `report:view`
- `report:export`
- `swagger:view`
- `web:view`

### Role `auto-renew`

**Name**: Auto-renewal service

**Profiles**: `m-auto-renew`

**Bindable OUs**: `auto-renew`, `AutoRenew`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:list`
- `cert:renew`
- `cert:export`
- `log:read`
- `web:view`

### Role `console`

**Name**: Console user

**Profiles**: `m-console`

**Bindable OUs**: `console`, `Console`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:issue`
- `cert:revoke`
- `cert:renew`
- `cert:list`
- `cert:export`
- `crl:generate`
- `log:read`
- `report:view`
- `report:generate`
- `ra:approve`
- `ra:reject`
- `trust:list`
- `swagger:view`
- `web:view`

### Role `operator`

**Name**: Operations operator

**Profiles**: `m-operator`

**Bindable OUs**: `operator`, `Operator`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:issue`
- `cert:revoke`
- `cert:renew`
- `cert:list`
- `cert:export`
- `cert:batch`
- `crl:generate`
- `log:read`
- `report:view`
- `web:view`

### Role `readonly`

**Name**: Read-only user

**Profiles**: `m-readonly`

**Bindable OUs**: `readonly`, `ReadOnly`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:list`
- `swagger:view`
- `web:view`

### Role `reporter`

**Name**: Report user

**Profiles**: `m-reporter`

**Bindable OUs**: `reporter`, `Reporter`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:list`
- `log:read`
- `report:view`
- `report:export`
- `report:generate`
- `web:view`

### Role `revoker`

**Name**: Auto-revoker

**Profiles**: `m-revoker`

**Bindable OUs**: `revoker`, `Revoker`

**Granted capabilities (grants)**:

- `ca:list`
- `ca:info`
- `cert:list`
- `cert:revoke`
- `log:read`
- `report:view`
- `web:view`

### Role `superadmin`

**Name**: Super administrator

**Profiles**: `m-superadmin`

**Bindable OUs**: `SuperAdmin`

**Granted capabilities (grants)**:

- `ca:create`
- `ca:delete`
- `ca:list`
- `ca:info`
- `cert:issue`
- `cert:revoke`
- `cert:renew`
- `cert:batch`
- `cert:list`
- `cert:export`
- `crl:generate`
- `user:manage`
- `user:list`
- `user:revoke-all`
- `log:read`
- `log:export`
- `config:read`
- `config:write`
- `report:view`
- `report:export`
- `report:generate`
- `ra:approve`
- `ra:reject`
- `cross-cert:issue`
- `cross-cert:revoke`
- `webhook:manage`
- `key:recover`
- `dns:manage`
- `trust:import`
- `trust:list`
- `trust:delete`
- `agent:manage`
- `swagger:view`
- `web:view`

## Least-Privilege Generation Guide (AI/Developers)

Follow these rules when generating capability sets for a task:

1. **Grant only capabilities required by the task**: Judge against each capability's `usage` (when needed); do not grant anything explicitly stated in `when_not`.
2. **Prefer exact matches**: Use exact `capability_id` instead of wildcards; prefer a single capability over domain wildcard `domain:*`.
3. **Narrow parameters**: For capabilities with `parameters`, set defaults/ranges according to actual task needs — narrower is better than broader.
4. **Prefer read-only**: Read-only capabilities (`*:list`, `*:read`, `*:view`) take precedence over write capabilities.
5. **Disable dangerous capabilities**: Sensitive capabilities such as `key:recover`, `ca:delete`, and `config:write` are not granted by default unless the task explicitly requires them.
6. **Remove redundancy**: Exact capabilities already covered by a wildcard may be omitted; delete all capabilities unrelated to the task.

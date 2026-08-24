# RFC Known Deviations

Known inconsistencies with relevant RFC standards (including intentional design decisions and bugs to be fixed), for integrators to assess compatibility.

---

## 1. RFC 5280 — Certificates and CRL

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | serialNumber may be negative (high bit not cleared) | **bug** | `crypto/rand` 20 bytes fully random, missing `buf[0] & 0x7f`, violates §4.1.2.2 "positive integer" |
| 2 | CRL thisUpdate lacks monotonicity guarantee | **bug** | No `Round(time.Second)` + `max(lastThisUpdate, now)`, clock rollback can cause thisUpdate regression |
| 3 | CRL nextUpdate only uses thisUpdate + validityDays | **low** | Does not account for issuance delay |
| 4 | Critical flag depends on profile template | **usability** | `keyUsage`/`basicConstraints`/`eku` extension critical flags manually defined per profile, no unified RFC 5280 §4.2.1.3-9 validation |
| 5 | Policy Mappings not implemented | **intentional** | Only used between CAs, no business scenario |
| 6 | Name Constraints implemented but path validation not integrated | **phase** | Extension embedded in sub-CA certs, but Go `x509.Verify` does not auto-validate (requires custom validator) |
| 7 | Subject Directory Attributes not implemented | **intentional** | Rarely used |
| 8 | CRL Issuer Alternative Name not implemented | **intentional** | Rarely used in CRLs |
| 9 | Delta CRL / Freshest CRL not implemented | **intentional** | Complex deployment, unnecessary at small scale |
| 10 | Issuing Distribution Point not implemented | **intentional** | Only needed for partitioned CRLs |
| 11 | CRL Indirect CRL Certificate Issuer not implemented | **intentional** | Only needed for indirect CRLs |

## 2. RFC 3161 — TSA Timestamp Protocol

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | Response includes full CA chain instead of TSA signing cert only | **bug** | Violates §2.4.2 response minimization, oversized responses may be rejected by gateways |
| 2 | Email/File/Socket transport not implemented | **intentional** | Only HTTP implemented (§3.4), no practical need for other transports |
| 3 | systemFailure returns HTTP 500 instead of PKIFailureInfo | **low** | RFC preferred over HTTP status codes, but practically compatible |
| 4 | badDataFormat / timeNotAvailable / addInfoNotAvailable failure codes not implemented | **intentional** | Scenarios not triggered |

## 3. RFC 6960 — OCSP

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | Nonce not echoed at request length (may pad/truncate) | **bug** | Violates §4.4.1 "echo the same value in the request" — should copy byte-by-byte |
| 2 | responseExtensions not populated | **blocking** | Go `x/crypto/ocsp` does not export `ResponseExtensions` field, requires fork |
| 3 | singleExtensions only Nonce, no other extensions | **low** | Only Nonce has practical need |
| 4 | Archive Cutoff not implemented | **intentional** | Optional extension |
| 5 | CRL reference not implemented | **intentional** | Response itself is real-time status |
| 6 | Signed request verification not implemented | **intentional** | Not enforced in deployment |
| 7 | OCSP responseStatus only successful is used | **low** | `malformedRequest`/`internalError`/`tryLater`/`sigRequired`/`unauthorized` constants defined but not triggered in current code |

## 4. RFC 8555 — ACME

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | HTTPS not enforced (relies on reverse proxy) | **intentional** | Application layer does not enforce HTTPS, deployment docs specify reverse proxy TLS termination |
| 2 | Content-Type not checked | **low** | Lenient receiving policy |
| 3 | Subproblems array not implemented | **intentional** | RFC 8555 §6.7.1 optional, no practical need |
| 4 | initialIp / createdAt not recorded | **intentional** | Audit log already captures request source IP |
| 5 | Public key lookup account URL not implemented | **intentional** | RFC 8555 §7.3.1 recommended, not mandatory |
| 6 | Pre-authorization not implemented | **intentional** | Can be achieved via newOrder |
| 7 | Terms of service change notification not implemented | **intentional** | Notification mechanism beyond ACL scope |
| 8 | tls-alpn-01 / device-attest-01 not implemented | **intentional** | No practical need |

## 5. RFC 8894 — SCEP

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | GetNextCACert returns same CA (no rotation) | **low** | Correct behavior when CA cert not rotated; manual update needed after rotation |
| 2 | PENDING status not supported, always synchronous issuance | **design decision** | RFC 8894 §4.4 allows synchronous mode |
| 3 | GetCertInitial/GetCert/GetCRL return synchronously | **design decision** | Same as #2 |
| 4 | SCEP revocation message not implemented | **intentional** | Can revoke via REST API |

## 6. RFC 3628 — TSA Policy Requirements

| # | Deviation | Type | Reason/Notes |
|---|-----------|------|-------------|
| 1 | TSA practice statement not published | **phase** | Planned for v1.1 |
| 2 | TSA key rotation not implemented | **phase** | Planned for v1.2 |
| 3 | No HSM support | **intentional** | Pure software implementation, HSM can be deployed independently |

---

## Severity Definitions

| Level | Meaning | Handling Principle |
|-------|---------|-------------------|
| **bug** | Violates RFC MUST/SHOULD, may cause interoperability issues | P0-P1 fix target |
| **blocking** | Known but requires upstream fix | Create workaround documentation |
| **low** | Violates RFC MAY/optional clause, does not affect mainstream interop | P2 or lower priority |
| **intentional** | Design decision, explicitly not implemented | No fix, document reason |
| **phase** | Planned, to be implemented in future version | Note expected version |
| **usability** | Does not violate RFC but harms usability | Best practice improvement |

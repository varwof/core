# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/core`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the PKI/CA server package. Issues of interest include:

- Authentication / authorization (RBAC) bypass on issuance, revocation,
  key recovery and administrative endpoints
- Cryptographic misuse (key handling, signing, encryption/escrow)
- Injection (SQL, command, template, path traversal)
- Resource-exhaustion / DoS on network-facing handlers (HTTP API, OCSP, TSA)
- Revocation / re-issue lifecycle correctness
- Delegation (AIC / agent-proxy) verification bypass

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Funding note: no paid third-party audit

This is an individual / open-source project; no paid third-party
security audit has been conducted. Validation relies on internal
AI-assisted review, automated tests (race-enabled), and independent
cross-implementation exercise where available.

## Security Audit History

Review practice: development includes AI-assisted security review and
RFC compliance cross-checks (X.509 / PKIX (RFC 5280), OCSP (RFC 6960), TSA (RFC 3161), PKCS#7 (RFC 5652)). Consolidated findings are
logged below; each is retained as a historical record after resolution.

### Development audit rounds (2026-06 -- 2026-08)

| Date | Scope | Method | Status |
|---|---|---|---|
| 2026-06-29 | core security review | AI-assisted internal review | iterative; superseded by the 2026-09-01 pass |
| 2026-07-23 | permission model | AI-assisted internal review | iterative; superseded by the 2026-09-01 pass |
| 2026-07-25 | authentication | AI-assisted internal review | iterative; superseded by the 2026-09-01 pass |
| 2026-08-01 | authentication | AI-assisted internal review | iterative; superseded by the 2026-09-01 pass |
| 2026-08-11 | AIC issuance pipeline | AI-assisted internal review | iterative; superseded by the 2026-09-01 pass |

These rounds were conducted during development; findings were addressed
as development progressed. The 2026-09-01 pass below is the consolidated
resolved baseline for `main` at that commit.

### 2026-09-01 -- internal security review (AI-assisted), resolved

Method: internal security/correctness review of the current `main`,
assisted by AI tooling, with RFC cross-checks against X.509 / PKIX (RFC 5280), OCSP (RFC 6960), TSA (RFC 3161), PKCS#7 (RFC 5652).
Status: all findings below were resolved in the 2026-09-01 security
pass (commit d4bbb6d) and verified by the full test suite (race-enabled).

Next scheduled review: quarterly (next: 2026-12-01).
Independent exercise: independent implementation (EMILIA crossing, 13/13) exercised AIC/X.509 issuance and delegation semantics.

### Resolved findings (2026-09-01)

### Security (high)

1. **Unauthorized certificate issuance via `/api/v1/csr/sign` and
   `/api/v1/k8s/sign` (RBAC bypass through the fallback rule)**
   (`internal/serve/routes_default.json:91`,
   `internal/serve/api_csr.go:40`, `internal/serve/api_k8s.go:36`).
   The route table declares a catch-all
   `{"method":"*","path":"/api/**","permission":"ca:list"}`. Neither
   endpoint has an explicit rule, so requests fall through to
   `ca:list` — and every role, including `readonly`, `auditor`,
   `revoker`, `reporter`, holds `ca:list`
   (`auth/permissions.go`). `apiCSRSign` / `apiK8sSign` perform **no**
   in-handler authorization check and sign an arbitrary attacker-supplied
   CSR (attacker-controlled CN/SAN/profile/CA/validity) against the live
   CA key. A read-only account can mint valid certificates at will.
   (The `k8s_enabled` flag in `apiK8sSign` is a deployment feature
   toggle, not an authorization gate.) Fix: add explicit
   `cert:issue`-gated rules for both endpoints and stop relying on a
   `ca:list` catch-all for `/api/**` issuance routes.

2. **Revoke-then-re-issue bypass in `cmdReSign`**
   (`cmd/pki/resign.go:49-115`). `database.GetCert` returns the stored
   certificate regardless of `Status` ("V"/"R"/"E"), and `cmdReSign`
   re-issues it with no status check, reusing the original
   `CommonName` / `SAN` / public key. `--profile` additionally lets the
   caller switch to a higher-privilege profile and `--target-ca` can
   re-issue under a different CA. A revoked certificate's identity /
   public key can be silently resurrected as a fresh valid cert,
   defeating key-compromise / cessation revocation. Fix: reject unless
   `rec.Status == "V"` and re-validate authorization.

3. **DelegationAuthorization principal binding can be skipped (empty
   KeyHash)** (`internal/ca/delegation_auth_verify.go:85-90`). The SPKI
   cross-check that binds the DA signer certificate to
   `PrincipalUid.KeyHash` runs only when
   `len(aic.PrincipalUid.KeyHash) > 0`. When KeyHash is empty, the DA is
   verified against whatever `userCert` the caller supplies — the caller
   can supply a fresh self-signed cert whose key they own, so the DA is
   "verified" with the attacker's own key. An attacker can self-delegate
   arbitrary AIC capabilities (agent-proxy / PA grants) with no real
   principal binding. Fix: reject the empty-KeyHash path (fail-closed),
   and the cross-check should use the declared
   `PrincipalUid.HashAlgo` rather than a hardcoded SHA-256.

4. **Gateway management endpoints unguarded (broken access control +
   SSRF amplification)** (`internal/serve/api_gateway.go:98,113,123`).
   `/api/v1/gateway/list`, `/disconnect-agent` and `/disconnect-user`
   have no route rule and no in-handler auth (unlike register/heartbeat
   which gate on admin). Any `ca:list` holder (e.g. `readonly`) can list
   all registered gateway addresses and POST arbitrary bodies to every
   gateway via `proxyDisconnectToGateways`, forcing disconnects and
   issuing requests to internal addresses (SSRF). Fix: add explicit
   `agent:manage`/`user:revoke-all` rules.

### Medium

5. **Unbounded request-body reads on OCSP and TSA (memory DoS)**
   (`internal/ocsp/handler.go:153`, `internal/tsa/handler.go:38`).
   Both use `io.ReadAll(r.Body)` with no `http.MaxBytesReader` /
   `io.LimitReader` (compare the correct `serve/rbac.go:1056` /
   `api_gateway.go:134` pattern). The endpoints are in `public_paths`
   (unauthenticated). An unauthenticated remote attacker can exhaust heap
   with arbitrarily large POST bodies.

6. **OCSP cache serves stale `good` for revoked certs for up to 24 h**
   (`internal/ocsp/handler.go:183-191,100`). On a cache hit the stored
   response is returned without re-checking current DB status; TTL is
   24 h and `PurgeSerial` only runs on a cache miss. After revocation,
   clients served from cache keep receiving `good` for up to 24 h, with
   no revocation-triggered purge path.

7. **`CheckPublicKeyStrength` fails open on unknown key types**
   (`internal/ca/sign.go:273-274`). Keys that are not RSA / ECDSA /
   Ed25519 return `nil` (accepted) instead of an error, bypassing
   RSA-bit-length and EC-curve strength checks.

8. **Name-constraint bypass for hostless URI SANs**
   (`internal/ca/pathval.go:642-645`). URI SANs are checked only via
   `u.Hostname()`; URIs with an empty authority (`urn:...`, `spiffe://`)
   `continue` and are never matched against
   `PermittedURIDomains`/`ExcludedURIDomains`.

9. **SSRF in trust import (loopback allowed)** (`api_trust.go:135-141`,
   `ca/trust.go:125`). `FetchCACertBundle` permits plain-HTTP to
   `localhost`, `127.*`, `::1` and any `https://` host. A
   `trust:import` holder can reach internal loopback / internal hosts.

10. **Webhook subscription stores an arbitrary URL verbatim (SSRF on
    event delivery)** (`webhook.go:44,58`). Requires `webhook:manage`
    but the URL is not restricted against loopback / private ranges.

11. **Sub-CA creation returns the freshly generated private key in
    plaintext** (`api_subca.go:150`). The new sub-CA key is returned in
    the HTTP response; bounded to superadmin, but the key should ideally
    never leave the server.

12. **Missing audit logging on sensitive operations.** `apiRecoverKey`
    (exports escrowed key, `api_admin.go:446`), `apiCSRSign`,
    `apiIssueCert`, `apiRevokeCert`, `apiCreateSubCA`, `apiImportCA` and
    the cross-cert ops never call `LogAudit`. Key export and
    issuance/revocation are exactly the operations a PKI must audit.

13. **Open, unauthenticated DNS resolver** (`api_ops.go:1207`).
    `/api/v1/dns-query` is in `public_paths` and forwards queries to
    hardcoded upstream resolvers with no auth / rate limit — usable as
    an open recursive resolver (reflection / probing).

### Low / robustness

14. **`cmdReSign` drops scope / authorization** (`cmd/pki/resign.go:67-90`).
    The re-sign path never sets `Scope` / `CAScope` /
    `PrincipalAuthorization` / `AIC`; management and agent/AIC certs are
    re-issued without the constraints of the original. Amplifies #2.

15. **Weak PKCS#12 protection on export** (`cmd/pki/export.go:25,70`,
    `internal/pkcs12/encode.go:24`). Empty/arbitrary `--password`
    accepted with no strength check, and PBKDF2 uses only 2048
    iterations, so a low-entropy PFX password is trivially brute-forced
    offline.

16. **Global CRL-number counter shared across CAs** (`internal/ca/crl.go:24,244`).
    `crlNumber` is process-global not per-CA; two CAs in one process
    contend for the same monotonic counter, breaking per-CA RFC 5280
    §5.2.4 monotonicity.

17. **`SkipDB` mode has no serial-uniqueness enforcement**
    (`internal/ca/sign.go:575-578,601-603`). With `SkipDB` the 10-attempt
    retry never detects collisions; concurrent issuers can produce
    identical serials (160-bit randomness makes this unlikely).

18. **PKCS#7 padding not fully validated on decrypt**
    (`internal/ca/pbes2.go:218-221`). Only `padLen` bounds are checked,
    not that every padding byte equals `padLen` (padding-oracle surface).

19. **Predictable JWT `jti` fallback** (`internal/ca/jwtissue.go:316-321`).
    `randomTokenID()` falls back to `time.Now().UnixNano()` if
    `rand.Read` fails, yielding a guessable JWT ID.

20. **Ed25519 CT SCT verification double-hashes** (`internal/ca/ct.go:227-230`).
    RFC 6962 Ed25519 signs the raw message, but the code pre-hashes with
    SHA-256, so valid Ed25519-log SCTs always fail verification
    (availability; fails closed).

21. **`cmdImport` path traversal via `index.txt`** (`cmd/pki/import.go:207-216`).
    A `certRelPath` from a malicious `index.txt` is joined with
    `filepath.Join`, allowing `../` reads of arbitrary PEM files.

22. **No global security headers / method-case normalization.**
    `ServeHTTP` (`mux.go:911`, `web.go:72`) sets no CSP /
    `X-Frame-Options` / `X-Content-Type-Options`; `matchMethod`
    (`rules.go:207`) uses `EqualFold`, accepting non-standard method case.

### Environment (not a code bug)

23. `go.mod` declares `go 1.26` while the available toolchain is
    1.25.10; `go test -race` / some analysis tooling fails in this
    environment.

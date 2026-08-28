# varwof Full Test Report

**Date**: 2026-08-27  
**Version**: v1.1.1  
**Environment**: Linux, Go 1.26.2

---

## Build Results

| Repo | Type | Status |
|------|------|--------|
| pkcs7 | library | ✅ |
| types | library | ✅ |
| engine | library | ✅ |
| gateway-core | library | ✅ |
| client | library | ✅ |
| types/aic | binary | ✅ |
| register/gen-authz | binary | ✅ |
| core/varwof | binary | ✅ |
| gateway/gateway-http | binary | ✅ |
| gateway/gateway-tcp | binary | ✅ |
| gateway/gateway-udp | binary | ✅ |

**Builds**: 11/11 passed

---

## Unit Tests (test-all.sh)

| Repo | Status | Duration |
|------|--------|----------|
| pkcs7 | ✅ PASS | 1.290s |
| types | ✅ PASS | 1.395s |
| capability | SKIP (no test files) | — |
| register | ✅ PASS | — |
| engine | ✅ PASS | 10.374s |
| gateway-core | ✅ PASS | 43.454s |
| core | ✅ PASS | 0.164s |
| gateway | ✅ PASS | 26.422s |

**Unit tests**: 7/7 passed

---

## Core Detailed Tests

| Package | Status | Duration |
|---------|--------|----------|
| auth | ✅ PASS | 0.036s |
| cmd/pki | ✅ PASS | 54.179s |
| internal | ✅ PASS | 0.024s |
| internal/ca | ✅ PASS | 22.682s |
| internal/capregistry | ✅ PASS | 0.016s |
| internal/i18n | ✅ PASS | 0.027s |
| internal/notifier | ✅ PASS | 0.346s |
| internal/ocsp | ✅ PASS | 0.718s |
| internal/pkcs12 | ✅ PASS | 0.041s |
| internal/provisioner | ✅ PASS | 0.026s |
| internal/remotesigner | ✅ PASS | 0.206s |
| internal/routing | ✅ PASS | 0.013s |
| internal/secrets | ✅ PASS | 0.019s |
| internal/serve | ✅ PASS | 97.191s |
| internal/signer | ✅ PASS | 0.163s |
| internal/tsa | ✅ PASS | 0.273s |
| tools/gen-testdata | ✅ PASS | 0.036s |

**Core detailed tests**: 17/17 passed

---

## Integration Tests (smoke.sh)

### 1. Prerequisites

| Check | Status |
|-------|--------|
| pki binary | ✅ |
| openssl | ✅ |
| python3 | ✅ |
| pkcs7 repo | ✅ |
| types repo | ✅ |
| register repo | ✅ |
| engine repo | ✅ |
| gateway-core repo | ✅ |
| client repo | ✅ |
| core repo | ✅ |
| gateway repo | ✅ |

### 2. CA Hierarchy Initialization

| Step | Status |
|------|--------|
| CA hierarchy init | ✅ |
| Full chain certificates created | ✅ |

### 3. Server Startup

| Check | Status |
|-------|--------|
| Server started (PID) | ✅ |
| HTTP listener :8443 | ✅ |
| HTTPS listener :9443 | ✅ |

### 4. Basic Functions

| Test | Status |
|------|--------|
| version command | ✅ |
| healthz endpoint | ✅ |
| ca list command | ✅ |

### 5. Certificate Issuance

| Profile | Status |
|---------|--------|
| tls-server | ✅ |
| tls-client | ✅ |
| m-admin | ✅ |
| vpn-client | ✅ |
| codesigning | ✅ |

### 6. Certificate Structure Verification

| Check | Status |
|-------|--------|
| KU: DigitalSignature | ✅ |
| KU: KeyEncipherment | ✅ |
| EKU: ServerAuth | ✅ |
| Key algorithm: ECDSA | ✅ |
| Extension: CRL DP | ✅ |
| Basic constraints: CA:FALSE | ✅ |
| Cert/key match | ✅ |

### 7. Certificate Chain Verification

| Cert | Status |
|------|--------|
| tls-server | ✅ |
| tls-client | ✅ |
| m-admin | ✅ |
| vpn-client | ✅ |
| codesigning | ✅ |

### 8. Certificate Lifecycle

| Operation | Status |
|-----------|--------|
| revoke (revocation) | ✅ |
| CRL gen (generate revocation list) | ✅ |
| CRL verify (verify revocation list) | ✅ |

### 9. PFX/PKCS#12 Export

| Check | Status |
|-------|--------|
| PFX export | ✅ |
| P12: cert readable | ✅ |
| P12: wrong password rejected | ✅ |

### 10. TSA Timestamp

| Check | Status |
|-------|--------|
| TSA query created | ✅ |
| TSA response | ✅ |
| TSA: granted | ✅ |

### 11. REST API (mTLS)

| Endpoint | Status |
|----------|--------|
| GET /cas | ✅ |
| GET /certs | ✅ |
| POST /api/v1/certs | ✅ |
| metrics | ✅ |

### 12. RBAC

| Check | Status |
|-------|--------|
| rbac mode | ✅ |

### 13. Code Signing

| Operation | Status |
|-----------|--------|
| sign | ✅ |
| verify | ✅ |

### 14. Trust Anchors

| Operation | Status |
|-----------|--------|
| trust list | ✅ |
| trust import | ✅ |

### 15. Cross Certificates

| Operation | Status |
|-----------|--------|
| cross-cert issue | ✅ |

### 16. Post-Operation Health Check

| Check | Status |
|-------|--------|
| healthz after all ops | ✅ |

**Integration tests**: 56/56 passed

---

## Test Summary

| Test type | Passed | Failed | Total |
|-----------|--------|--------|-------|
| Builds | 11 | 0 | 11 |
| Unit tests (all repos) | 7 | 0 | 7 |
| Core detailed tests | 17 | 0 | 17 |
| Integration tests (smoke) | 56 | 0 | 56 |
| **Total** | **91** | **0** | **91** |

---

## Conclusion

✅ **All passed**

All builds, unit tests, and integration tests pass. The system is functionally complete,
including:

- CA hierarchy initialization
- Certificate issuance (tls-server, tls-client, m-admin, vpn-client, codesigning)
- Certificate structure verification (KeyUsage, ExtendedKeyUsage, basic constraints, CRL DP)
- Certificate chain verification
- Certificate revocation and CRL generation
- PFX/PKCS#12 export
- TSA timestamps
- REST API (mTLS auth)
- RBAC access control
- Code signing and verification
- Trust anchor management
- Cross certificates
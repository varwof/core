# Dual Carrier: X.509 and AIC-JWT

Varwof core issues and verifies AIC in **two certificate forms** sharing the **same trust root**: the X.509 AIC certificate and the AIC-JWT (draft-wei-aic-jwt-00).

## Same Trust Root

- **X.509**: standard certificate chain validation, trust anchor = root CA.
- **JWT**: `GET /.well-known/jwks.json` publishes every configured CA as a JWKS; `kid` = SHA-256 of the CA certificate SPKI. Verifiers validate AIC-JWTs with keys from the same trust root.

Both carriers are cryptographically bound to the same agent key pair: X.509 via the certificate public key, AIC-JWT via `cnf.jkt` (RFC 7800 JWK thumbprint); the gateway checks dual-carrier coherence (mTLS certificate key == `cnf.jkt`).

## Implementation (L0–L4)

| Layer | Capability |
|-------|------------|
| L0 | `/.well-known/jwks.json` — publish each configured CA as JWKS |
| L1 | `ca.SignJWT` — mint AIC-JWTs reusing all X.509 issuance validation |
| L2 | Bearer AIC-JWT validation — kid → trust-root CA, capabilities flow into RBAC, dual-carrier coherence |
| L3 | `/oauth/token` — RFC 8693 x509→JWT exchange, RFC 7523 JWT-bearer, RFC 9068 access tokens, DPoP/mTLS binding |
| L4 | Dual-carrier end-to-end matrix (ES256 / RS256 / EdDSA, incl. tamper detection) |

## Related

- Design: [dev-docs AIC 09](https://github.com/varwof/dev-docs/blob/main/aic/en/09-aic-iam-unification.md)
- Support matrix: [aic-jwt-repo-matrix](https://github.com/varwof/dev-docs/blob/main/aic/aic-jwt-repo-matrix.md)
- Drafts: [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) · [draft-wei-aic-jwt](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

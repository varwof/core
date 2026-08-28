# Security & RBAC

This directory documents the varwof-core permission security model and its
authorization verification results for security audits and compliance.

## Index

| Document | Description |
|----------|-------------|
| [RBAC Security Model (cert-first)](en/rbac-security-model.md) | Trusted authority, non-cert credential limits, management sub-CA gate, CA scopes, route fail-closed, role matrix, audit guide |
| [RBAC Verification Report 2026-08-28](en/rbac-verification-2026-08-28.md) | Full measured matrix (378×2 checks) across simple/enterprise modes plus P0 probes and reproduction steps |
| [Deployment Hardening](en/deployment-hardening.md) | Pre-flight/maintenance checklist: authorization, TLS, keys, limits, audit, ops |
| [Private Key Hygiene](en/private-key-hygiene.md) | Key classes, permissions, the cert-vs-key trap, at-rest encryption, rotation, backup, anti-pattern checklist |

## Reading path

1. Start with the **security model**: the three authority rules — superadmin is
   certificate-only, accounts are always operator, management sub-CA is
   hard-excluded for non-superadmin.
2. Then the **verification report**: measured HTTP codes for the 378×2 matrix
   and the P0 probes.
3. To change permissions, edit `routes.json` and
   `internal/serve/routes_default.json` (keep them in sync) and run
   `scripts/verify-rbac-api.sh`.
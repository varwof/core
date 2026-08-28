# Private Key Hygiene

Key material is the crown jewels of a PKI. These rules apply to every varwof-core
deployment and every operator that touches its keys.

## 1. Key classes

| Class | Location | Publication |
|-------|----------|-------------|
| Root CA key | offline / `keys/root/private/` | must never live on a server path that is web-reachable |
| Issuing/management keys | `keys/issuing/private/`, `management/users/private/` | `0600` only |
| Serve TLS pair | `keys/server.key` | `0600` root-owned |
| TSA / OCSP / codesign keys | `keys/<service>/private/` | service-user-only |
| Certificates (public) | `certs/` dirs | `0644` – public, not secret |

## 2. Permission rules

- Private keys: `chmod 600`, owned by the serve user (`varwof`).
- Public cert PEM files: `0644` — they are **public**, but must never be passed
  to `--key` / TLS key slots.
- Directories holding private material: non-trawable (`700`-style), no `+x` for
  others on the leaf dirs.
- The deploy script locks `management/users/private/` to `0600` automatically
  (verified each `--deploy`).

## 3. The cert-vs-key trap

`management/users/certs/*.pem` is the **public certificate**; the private key
lives under `management/users/private/`:

```
certs/user-superadmin-alice.pem   ← certificate (public)
private/user-superadmin-alice.key ← key (secret, 0600)
```

**A PEM cert file contains no private key.** mTLS clients must pair the
certificate with the matching key from `private/`. Scripts must derive the key
path from the cert name (deploy `helpers.py` does this) and never substitute the
cert file as key material.

## 4. At rest

- Encrypt stored keys with `pki encrypt-key` / `pki key encrypt`, or rely on
  `key_escrow` (recovery) for operator-mintable material.
- The secrets backend resolves CA key passwords (see `secrets` config).
- Cold backups of keys must be encrypted (GPG/KMS) before leaving the host.

## 5. Rotation

- CA key rotation: `POST /api/v1/ca/{name}/rotate` (+ `/rotation` status),
  superadmin only (certificate-first).
- Re-sign/re-issue affected certs on the new key; retire old keys after the
  cross-over window and revoke where the CA discipline requires it.
- TSA key rotation: `POST /api/v1/tsa/cert/rotate`.
- Management cert re-issuance: mint a fresh `m-*` cert (superadmin), rebind the
  operator-cert where applicable, then retire the old one.

## 6. Backup & recovery

| Tool | Notes |
|------|-------|
| `pki db backup` | online DB snapshots (contain cert records) |
| `pki cold-backup` | CA keys + records, offline-capable |
| `deploy/backup-root-ca.sh` | root-key offline vault workflow |
| `recover` / `key_escrow` | recover escrowed keys under strict admin control |

Restore procedure: restore DB + keys together (records reference keys by hash);
verify `pki ca list` and issue a test cert.
Recovery events must be logged to the authorization audit trail.

## 7. Anti-patterns checklist

- [ ] Private keys committed to git / images — forbidden (`.gitignore` + LFS only for public certs).
- [ ] Cert file used as a key — forbidden.
- [ ] `management/users/private/` mode looser than `0600` — forbidden.
- [ ] Root CA key stored on the API host — avoid; prefer offline vault or `key_backend`.
- [ ] Backup set includes unencrypted key material — forbidden.
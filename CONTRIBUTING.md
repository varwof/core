# Contributing to pki

Thank you for considering contributing to pki!

## How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing`)
3. Make your changes
4. Run tests: `GOPROXY=https://goproxy.cn,direct GONOSUMCHECK=* go test -count=1 ./...`
5. Commit with a clear message (`git commit -m "feat: add amazing feature"`)
6. Push and open a Pull Request

## Code style

- Follow standard Go formatting (`gofmt -s`)
- Run `go vet ./...` before committing
- All exported types/functions must have doc comments
- Keep functions small and focused
- Use existing patterns (see `internal/` packages for reference)

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Type     | Usage                        |
|----------|------------------------------|
| `feat:`  | New feature                  |
| `fix:`   | Bug fix                      |
| `docs:`  | Documentation changes        |
| `refactor:` | Code restructuring        |
| `test:`  | Adding/modifying tests       |
| `chore:` | Build/config/tooling changes |

## Testing

- All tests must pass: `go test -count=1 ./...`
- DB tests use in-memory SQLite (no external deps)
- For PostgreSQL tests: `go test -tags postgres`
- LDAP tests use mock connections

## Project structure

```
cmd/pki/       — CLI entry point (thin wrappers)
internal/       — All implementation packages
  db/           — SQLite/PostgreSQL storage + migrations
  ca/           — Certificate operations
  ocsp/         — OCSP responder
  tsa/          — Time-stamp authority
  acme/         — ACME v2 protocol
  scep/         — SCEP protocol
  pkcs7/        — PKCS#7/CMS signing
  serve/        — HTTP server + API
  signer/       — Crypto signer abstraction
deploy/         — Docker, systemd, scripts
docs/ + dev-docs/            — Documentation
```

## Developer Certificate of Origin

By contributing, you agree to the [Developer Certificate of Origin](https://developercertificate.org/).
Each commit must include a `Signed-off-by` line (`git commit -s`).

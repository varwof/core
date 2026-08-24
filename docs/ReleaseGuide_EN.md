# Release Guide

## Version Number

**Format**: `major.minor.patch`

| Position | Meaning | Example |
|---|---|---|
| major | Incompatible API/CLI changes | 2.0.0 |
| minor | Backward-compatible feature additions | 1.1.0 |
| patch | Backward-compatible bug fixes | 1.0.1 |

## Source Definition

The `version` variable in `main.go` is a hardcoded default value, usable directly with `go build`:

```go
var version = "1.0.0"
```

During CI/CD, override it via ldflags injection without modifying the source file:

```bash
go build -ldflags "-X main.version=1.0.1" -o pki ./cmd/pki/
```

## Build Script

`deploy/build.sh` implements a one-click release process:

```bash
deploy/build.sh 1.0.1
```

Execution steps:
1. Compile binary with ldflags → `pki`
2. Create Git tag via `git tag trunk tags/1.0.1`
3. Package `pki-src-1.0.1.tar.gz`
4. SFTP upload to NAS `/sata1-17080036766a/home/src/`

## Git Tag Convention

Each release creates one tag, one-to-one with the version number:

```bash
git tag file:///home/varwof/svn/pki/trunk \
         file:///home/varwof/svn/pki/tags/1.0.0 \
         -m "tag 1.0.0"
```

## Artifact Naming

| Artifact | Naming Format | Example |
|---|---|---|
| Source package | `pki-src-<version>.tar.gz` | `pki-src-1.0.0.tar.gz` |
| Binary | `pki` | `pki` |
| Git tag | `tags/<version>` | `tags/1.0.0` |

## Release Checklist

- [ ] All tests pass (`go test ./...`)
- [ ] Zero warnings (`go vet ./...`)
- [ ] Version number updated
- [ ] Archived on NAS
- [ ] Git tag created

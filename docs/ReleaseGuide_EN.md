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

## Tag & Release

1. Build and test:
   ```bash
   go build ./... && go vet ./... && go test ./...
   ```
2. Create a Git tag:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```
3. CI (`release.yml`) builds the release binaries and creates a GitHub Release on the tag.

## Artifact Naming

| Artifact | Naming Format | Example |
|---|---|---|
| Source archive | `pki-src-<version>.tar.gz` | `pki-src-1.0.0.tar.gz` |
| Binary | `pki` | `pki` |
| Git tag | `v<version>` | `v1.0.0` |

## Release Checklist

- [ ] All tests pass (`go test ./...`)
- [ ] Zero warnings (`go vet ./...`)
- [ ] Version number updated
- [ ] Git tag created and pushed
- [ ] Release binaries verified

# 版本管理

## 版本号

**格式**：`major.minor.patch`

| 位 | 含义 | 示例 |
|---|---|---|
| major | 不兼容的 API/CLI 变更 | 2.0.0 |
| minor | 向下兼容的功能新增 | 1.1.0 |
| patch | 向下兼容的 Bug 修复 | 1.0.1 |

## 源码定义

`main.go` 中 `version` 变量为硬编码默认值，`go build` 可直接使用：

```go
var version = "1.0.0"
```

CI/CD 时通过 ldflags 注入覆盖，不修改源文件：

```bash
go build -ldflags "-X main.version=1.0.1" -o pki ./cmd/pki/
```

## Tag 与发布

1. 构建与测试：
   ```bash
   go build ./... && go vet ./... && go test ./...
   ```
2. 打 Git tag 并推送：
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```
3. CI（`release.yml`）在 tag 上构建发布二进制并创建 GitHub Release。

## 产物命名

| 产物 | 命名格式 | 示例 |
|------|---------|------|
| 源码包 | `pki-src-<version>.tar.gz` | `pki-src-1.0.0.tar.gz` |
| 二进制 | `pki` | `pki` |
| Git tag | `v<version>` | `v1.0.0` |

## 发布检查清单

- [ ] 测试全过（`go test ./...`）
- [ ] 零警告（`go vet ./...`）
- [ ] 版本号已更新
- [ ] Git tag 已打并推送
- [ ] 发布二进制已验证

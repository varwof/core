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

## 构建脚本

`deploy/build.sh` 实现一键发版流程：

```bash
deploy/build.sh 1.0.1
```

执行步骤：
1. ldflags 编译二进制 → `pki`
2. `git tag v1.0.1` 打 Git tag
3. 打包 `pki-src-1.0.1.tar.gz`
4. SFTP 上传 NAS `/sata1-17080036766a/home/src/`

## Git tag 规范

每发一版打一个 tag，与版本号一一对应：

```bash
git tag v1.0.0 && git push origin v1.0.0
         -m "tag 1.0.0"
```

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
- [ ] NAS 已存档
- [ ] Git tag 已打

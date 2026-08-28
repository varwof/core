# 私钥卫生

密钥材料是 PKI 的核心资产。以下规则适用于每个 varwof-core 部署与其操作者。

## 1. 密钥分类

| 类别 | 位置 | 发布规则 |
|------|------|----------|
| 根 CA 私钥 | 离线 / `keys/root/private/` | 禁止存在可被 Web 访问的服务器路径 |
| 签发/管理密钥 | `keys/issuing/private/`、`management/users/private/` | 仅 `0600` |
| 服务端 TLS 对 | `keys/server.key` | `0600`，root 属主 |
| TSA / OCSP / 代码签名 | `keys/<service>/private/` | 仅服务用户可读 |
| 证书（公开） | `certs/` 目录 | `0644`，公开非秘密 |

## 2. 权限规则

- 私钥 `chmod 600`、属主为服务用户（`varwof`）。
- 公钥证书 PEM `0644` —— **公开**，但绝不能当 `--key` / TLS 密钥槽使用。
- 存放私钥的目录不可遍历（`700` 风格），叶子目录对其他用户无 `+x`。
- 部署脚本自动将 `management/users/private/` 锁为 `0600`（每次 `--deploy` 校验）。

## 3. 证书≠密钥陷阱

`management/users/certs/*.pem` 是**公开证书**；私钥在 `management/users/private/`：

```
certs/user-superadmin-alice.pem   ← 证书（公开）
private/user-superadmin-alice.key ← 密钥（秘密，0600）
```

**PEM 证书文件不含私钥。** mTLS 客户端必须用 `private/` 中对应密钥配对。
脚本应从证书名推导密钥路径（部署 `helpers.py` 已如此），绝不把证书文件当密钥。

## 4. 静态加密

- 用 `pki encrypt-key` / `pki key encrypt` 加密存储密钥，或依赖 `key_escrow`
  托管恢复（operator 可签发的材料）。
- secrets 后端解析 CA 密钥口令（见 `secrets` 配置）。
- 密钥冷备份离开主机前必须加密（GPG/KMS）。

## 5. 轮换

- CA 密钥轮换：`POST /api/v1/ca/{name}/rotate`（+ `/rotation` 状态），仅 superadmin（证书优先）。
- 新密钥上重签/重发受影响证书；交叉期后退役旧密钥，CA 纪律要求处吊销。
- TSA 密钥轮换：`POST /api/v1/tsa/cert/rotate`。
- 管理证书重发：superadmin 签发新 `m-*` 证书，必要时重绑操作员证书，再退役旧证。

## 6. 备份与恢复

| 手段 | 说明 |
|------|------|
| `pki db backup` | 在线 DB 快照（含证书记录） |
| `pki cold-backup` | CA 密钥 + 记录，可离线 |
| `deploy/backup-root-ca.sh` | 根密钥离线保险工作流 |
| `recover` / `key_escrow` | 严格管理下恢复托管密钥 |

恢复：DB 与密钥一起恢复（记录按哈希引用密钥）；先用 `pki ca list` 校验并试签发，
再接入流量。恢复事件必须记入授权审计。

## 7. 反模式检查表

- [ ] 私钥提交进 git / 镜像 —— 禁止（公开证书才进 LFS）。
- [ ] 证书文件当密钥用 —— 禁止。
- [ ] `management/users/private/` 权限宽于 `0600` —— 禁止。
- [ ] 根 CA 密钥存放于 API 主机 —— 避免；优选用离线保险库或 `key_backend`。
- [ ] 备份集含未加密密钥材料 —— 禁止。
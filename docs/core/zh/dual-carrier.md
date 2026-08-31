# 双载体：X.509 与 AIC-JWT

varwof core 以**两种证书形态**签发和验证 AIC，共享**同一个信任根**：X.509 AIC 证书与 AIC-JWT（draft-wei-aic-jwt-00）。

## 同一个信任根

- **X.509**：标准证书链验证，信任锚 = 根 CA。
- **JWT**：`GET /.well-known/jwks.json` 将每个配置的 CA 发布为 JWKS；`kid` = CA 证书 SPKI 的 SHA-256。验证方用同一信任根的公钥验签 AIC-JWT。

两个载体密码学绑定到同一个 agent 密钥对：X.509 使用证书公钥，AIC-JWT 使用 `cnf.jkt`（RFC 7800 JWK 指纹）；网关做双载体一致性检查（mTLS 证书密钥 == `cnf.jkt`）。

## 实现状态（L0–L4）

| 层 | 能力 |
|----|------|
| L0 | `/.well-known/jwks.json` — 每个配置的 CA 发布为 JWKS |
| L1 | `ca.SignJWT` — 签发 AIC-JWT，复用 X.509 签发全部校验 |
| L2 | Bearer AIC-JWT 校验 — kid → 信任根 CA，capabilities 汇入 RBAC，双载体一致性 |
| L3 | `/oauth/token` — RFC 8693 x509→JWT 兑换、RFC 7523 JWT-bearer、RFC 9068 access token，DPoP/mTLS 绑定 |
| L4 | 双载体端到端矩阵（ES256 / RS256 / EdDSA，含篡改检测） |

## 相关

- 设计文档：[dev-docs AIC 09](https://github.com/varwof/dev-docs/blob/main/aic/zh/09-aic-iam-unification.md)
- 支持矩阵：[aic-jwt-repo-matrix](https://github.com/varwof/dev-docs/blob/main/aic/aic-jwt-repo-matrix.md)
- 草案：[draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) · [draft-wei-aic-jwt](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

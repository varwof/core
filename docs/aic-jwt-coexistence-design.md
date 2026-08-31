# 一个信任根 × 双载体：core 接入 AIC-JWT 与标准 OAuth 的设计与规划

- 日期：2026-08-31
- 范围：`core`（标准 PKI + AIC X.509 完整实现）接入 AIC-JWT，使 X.509 与 JWT 在同一信任根下共存、互相验证，并支持标准 OAuth
- 相关草案/实现：`draft-wei-aic-identity-cert-00`（X.509 AIC）、`draft-wei-aic-jwt-00`（AIC-JWT）、`types/aicjwt`（JWT+OAuth 参考实现）、`aic-jwt`（浏览器/TS 实现）

---

## 1. 现状盘点（已核实）

### 1.1 core：X.509 AIC 载体 + 外部 OIDC 校验，非签发方

| 能力 | 位置 | 现状 |
|---|---|---|
| 根 CA / 证书链 | `internal/ca/sign.go` `Sign` | 完整：模板、序列号、有效期、能力、扩展创建 |
| AIC 扩展签发/解析 | `internal/ca/aic.go` `internal/ca/principal_auth.go` `identity.go` | `ParseAIC`、`PrincipalAuthorization`、DelegationAuthorization、PrincipalUid 齐备 |
| serve 层身份判定 | `internal/serve/rbac.go` | mTLS → `ParseAIC`（优先级最高）；Bearer → `provisioner.Registry` |
| provisioner 插件 | `internal/provisioner/{token,oidc,mtls}.go` | `Registry` 插件式：`token`（X-Auth-Token/API token）、`oidc`（**校验外部 IdP 的 JWT**，JWKS 从外部拉取）、`mtls` |
| OAuth AS 角色 | — | **无**：不签 JWT、无 JWKS 端点、无 token 端点 |
| 根配置/JWKS | `internal/config.go` | 无 JWKS、无 issuer 声明 |

结论：core 目前在 JWT 世界是**纯消费者**（校验外部 OIDC token），不是签发票据方，也没有"发行人即根 CA"的概念。

### 1.2 types/aicjwt：AIC-JWT 引擎已完备（待集成）

| 能力 | 位置 | 状态 |
|---|---|---|
| claims 模型 | `types/aicjwt/claims.go` | Header(alg/typ/kid/crit/jwk)、Audience、Cnf(jkt)、StatusRef、Principal、Capability、Extension、PA/DA 齐备 |
| 11 步验证 | `types/aicjwt/validate.go` | `Validate(token, VerifyOptions)` 完整（含 fail-closed 未知 scheme） |
| 能力匹配/约束 | `capmatch.go` `constraints.go` | `MatchCapabilities`、`EvaluateConstraints` |
| 密钥哈希 | `keyhash.go` | SPKI hash、JWK thumbprint（jkt）、KeyHashOf |
| **x509↔JWT 双向映射** | `types/aicjwt` `CapToPKI`/`PKIToCap` | **已存在** — JWT Capability ↔ pki.Capability |
| OAuth 协议层 | `aic-jwt/oauth.go` | AS（JWT-bearer R7523 / auth-code / token-exchange R8693）、RS、DPoP R9449、Token Status List、OBO；9 个 e2e 场景已测 |

### 1.3 关键对应关系（"互相验证"的锚点）

| X.509（types/pki） | JWT（types/aicjwt） |
|---|---|
| `PrincipalUid{Realm,Identifier,KeyHash,HashAlgo}` | `Principal{realm,id,key_hash,hash_alg}` |
| AIC ext `capabilities`（`SchemeId`+`CapabilityId`） | `aic.capabilities`（`scheme`+`id`） |
| 证书 subject public key | `cnf.jkt`（RFC 7800，JWK thumbprint） |
| 证书链信任锚 = 根 CA | issuer JWKS（kid 可派生自证书 SKI/指纹） |
| 失败默认：无 AIC → 无能力 → deny | fail-closed：未知 scheme → deny |

---

## 2. 目标架构：一个信任根，双载体

```
                    信任根 = core 根 CA（唯一公钥 P）
                    同一签名密钥，两条表达
        ┌───────────────────────────┬───────────────────────────┐
        │ X.509 载体                │ JWT 载体                  │
  签发   │ Sign() → AIC 证书          │ 新增 SignJWT() → AIC-JWT    │
        │   Cert{ AIC ext, PA, DA }  │   JWS{ cac, cnf.jkt,     │
        │   ├ PrincipalUid           │        principal,        │
        │   └ capabilities           │        capabilities,     │
        │                            │        pa/da, status }   │
  验证   │ mTLS → ParseAIC            │ Bearer → aicjwt.Validate │
        │   → PrincipalUid+CapList   │   → Principal+CapList    │
        └───────────────────────────┴───────────────────────────┘
                    授权判定合并：Location → Role → CapMatch
        OAuth AS（R7523/R8693/9068/9449）：用根 P 签发/验证 AIC-JWT
```

**"一个信任根"的实现方式**：core 根 CA（或指定的 agent 中间 CA）的私钥同时作为 JWS 签名密钥（EC→ES256、RSA→RS256/PS256）。信任关系绑定到**同一个公钥/同一条证书链**：
- JWT issuer 的 JWKS 中，`kid` = 该 CA 证书的 SKI/base64url(sha256(SPKI))；JWK 可携带 `x5c`（证书链），让 JWT 验证也能走链到根。
- 因此 X.509 链验证与 JWS 验证最终锚定同一公钥 = 字面意义的"一个信任根"。

---

## 3. 缺口（gap）清单

| # | 缺口 | 影响 |
|---|---|---|
| G1 | core 不签发 AIC-JWT（缺 AS/CA 的 JWT 铭牌） | 无法作为 JWT 载体发行人 |
| G2 | core 无 JWKS 端点 / issuer 声明 | JWT 验证方（如 gateway）无处取信任密钥 |
| G3 | core 的 Bearer 分支只能走外部 OIDC/token，不识别 native AIC-JWT | x509 与 JWT 不能"共存互验" |
| G4 | 无 x509↔JWT 身份/能力一致性核验路径 | "互相验证"落不了地 |
| G5 | gateway-core 决策层只认 x509 AIC（`ParseAIC`） | 若 AIC-JWT 也要进 gateway，需扩展决策输入 |

---

## 4. 分层实施规划

### L0 — 信任根打通（最小、纯增量）
- `internal/ca/` 新增密钥→JWK 工具：`CertToJWK(cert, key)`（`kty`/`kid`/`alg`/`x5c`），kid 由证书派生。
- 配置 `config.go`：可选声明 `jwt_issuer`（默认 = 根 CA 名称 + 公钥指纹）。
- 新端点 `GET /.well-known/jwks.json`：从根/agent CA 证书在线生成 JWKS。
- 测试：`CertToJWK` ↔ `JWKToPublic` 往返；kid 与证书 SKI 一致性。

### L1 — 签发 AIC-JWT（复用现有签发管线）
- 新增 `internal/ca/jwtissue.go`：把 `SignConfig` 的产物（Subject=PrincipalUid、capabilities、有效期、PA/DA）映射到 AIC-JWT claims（`typ: aic+jwt`，`iss`=issuer，`sub`=principal.id，`cnf.jkt`=主体公钥 thumbprint，`aic.capabilities`=CapToToken，携带 `jti`/`exp`）。
- 复用 `sign.go` 的模板/参数校验；序列号/有效期语义与 x509 一致。
- **关键约束**：对同一（身份+能力+约束），x509 与 JWT 两载体表达必须一致 — goldens：`PKIToCap(CapToPKI(c))==c` 与 `CapToPKI(PKIToCap(c))==c` 循环测试。

### L2 — 验证统一（core 作为 RS）
- 新增 `internal/provisioner/aicjwt.go`：实现 `Provisioner` 接口（`Name="aicjwt"`），Bearer 分支解析 → `types/aicjwt.Validate`（11 步，kid→本地根 JWKS，可选 x5c 链验证）→ 产出 `Principal` + `Capability` 列表。
- `rbac.go`：注册 `aicjwt` provisioner；授权判定处把 JWT capabilities 经 `PKIToCap` 转 `pki.Capability`，**走现有 `MatchCapability`/Location→Role 逻辑**（与 mTLS 共用）。
- G4 互验：新增可选 `strict` 交叉核验 — 当请求同时携带 mTLS 证书与 AIC-JWT，比较 `PrincipalUid`（key_hash 必须一致）与 capabilities 交集，不一致即 deny。默认宽松（单载体即可），strict 由策略开启。

### L3 — 标准 OAuth（引入 aic-jwt/oauth.go 参考层）
- 把 `aic-jwt/oauth.go` 中的协议逻辑作为内部参考库挂到 core 的 `serve`，提供 OAuth 认证端点：
  - **RFC 8693 token exchange**：`subject_token`=x509 AIC（证书链/credential bundle）→ 兑换 `AIC-JWT`（`token_type: urn:ietf:params:oauth:token-type:aic+jwt`）——这是 **x509→JWT 的"标准 OAuth"化路径**，也是 G3/G4 的协议入口。
  - **RFC 7523 JWT bearer**：client 以 AIC-JWT 为 `client_assertion` 申请 access token。
  - **RFC 9068**：access token 即 AIC-JWT（携带 `cnf.jkt`）。
  - **RFC 9449 DPoP**：presenter proof 绑定 `cnf`。
  - **Token Status List**（RFC 9457 系）：撤销/吊销映射（呼应现有 CRL 语义）。
- 端点无需重写——`types/aicjwt` + `oauth.go` + 现有 mux 挂载即可。

### L4 — 端到端验证
- e2e：core 签 x509 AIC 证书 + AIC-JWT，同一根、同一主题；
  1) mTLS 直通授权 OK；2) Bearer AIC-JWT 授权 OK；3) 双载体 strict 互验一致通过、篡改之一被拒；4) token-exchange x509→JWT 成功。
- algorithm 矩阵：EC P-256(ES256)、RSA(RS256/PS256)（现有 core 已支持相应密钥强度校验）。

---

## 5. 关键设计决策（需确认）

| # | 决策点 | 建议 | 备选 |
|---|---|---|---|
| D1 | 信任根绑定方式 | **同一私钥签 x509 + JWS**（kid=证书指纹，JWK 带 x5c）→ 字面"一个信任根" | JWKS 独立子密钥、由根《认证/派生》（更"OAuth 正统"，但公钥不再与 x509 相同） |
| D2 | alg 策略 | EC→ES256，RSA→RS256/PS256，Ed25519→EdDSA（若 core 允许） | 强制 ES256 最小集 |
| D3 | 互验严格度 | 默认宽松（任一载体即可），`strict` 可选 | 强制双载体一致才放行 |
| D4 | 授权判定归属 | JWT capabilities → `PKIToCap` → 复用现有 `MatchCapability`+RBAC（不新建判定树） | 在 aicjwt 内独立判定（会分叉） |
| D5 | OAuth 引入方式 | 复用 `aic-jwt`（`types/aicjwt` + `oauth.go`）作为内部参考库，不改其包路径 | 复制进 core（避免依赖但丧失单一事实源） |
| D6 | gateway 是否同步接入 | 消费端（gateway-core 决策）后续单独安排；core 先行 | 本次一起改 gateway（范围扩大） |

---

## 6. 建议实施顺序与工作量预估

1. **L0**（信任根 + JWKS 端点）— 1 天，纯增量，可独立合入。
2. **L1**（签发 AIC-JWT + 双载体 golden 测试）— 2–3 天，核心新能力。
3. **L2a**（`aicjwt` provisioner）+ **G4 strict 互验** — 2 天，验证统一。
4. **L3**（OAuth 端点挂载，R8693 先行）— 2 天，优先 token-exchange（x509→JWT 路径）。
5. **L4**（e2e 双载体矩阵）— 1 天。
合计约 8–9 天（单人）。

**先行利润点**：L0 + L1 + L2a 即可达成"一个信任根、x509 与 AIC-JWT 共存互验"，L3 在其上叠加标准 OAuth 而不改变骨架。

---

## 附：草案对信任的描述（draft-wei-aic-jwt-00）

- §1.2：AIC-JWT 是 X.509 AIC 的**companion而非替代**：X.509 管 transport 层，JWT 管 application 层；签名框架 X.509/RFC5280 vs JWS/RFC7515；key binding = subject public key vs `cnf`；trust bootstrap = certificate chain vs JWKS/`x5c`/credential bundle。
- §3.4 角色：Issuer = CA（PKI 模式）或 AS（OAuth 模式）；PKI 部署下 issuer 密钥来自 credential bundle/证书链，可在 `x5c` 中携带 → 天然支持"与 x509 同一信任根"。
- §5：主体绑定 `cnf`（RFC 7800, `jkt`）；验证者可进一步核对 mTLS 客户端证书公钥的 JWK thumbprint 与 `jkt` 一致 — 即本设计 G4/strict 互验在草案中的依据。
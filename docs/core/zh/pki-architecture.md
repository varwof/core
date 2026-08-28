# PKI 架构：3 层 vs 4 层层级

## 概览

varwof PKI 支持两种层级模式：

| 模式 | 配置 | 层数 | 适用场景 |
|------|------|------|---------|
| 简单 | `--hierarchy simple` | 3 层 | 中小型组织 |
| 企业 | `--hierarchy enterprise` | 4 层 | 大型企业、合规要求高 |

## 三层架构（简单）

```
                    ┌──────────────┐
                    │   Root CA    │  L1 — 信任锚点
                    │  (offline)   │  ECDSA P-384, 20 年
                    └──────┬───────┘
                           │
           ┌────────────────┼────────────────┐
           │                │                │
     ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
     │ TLS CA    │   │ People CA │   │ CodeSign  │  L2 — 签发 CA
     │ (5 年)    │   │ (5 年)    │   │ CA (RSA)  │  ECDSA P-256
     └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
           │                │                │
     ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
     │ Servers   │   │ Users     │   │ Software  │  L3 — 终端实体
     │ Clients   │   │ AIC Agents│   │ Code      │
     └───────────┘   └───────────┘   └───────────┘
```

### 特性

- 根 CA 直接签署所有子 CA
- 子 CA 的 `MaxPathLen=0`（不能签发进一步的 CA）
- 更简单的链验证
- 更快的部署
- 子 CA 签发后根 CA 可保持离线

### 链验证

```bash
# 简单链
openssl verify -CAfile root/ca.pem -untrusted tls/ca.pem server.pem

# 预期输出
server.pem: OK
```

### init-full 命令

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --hierarchy simple \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki
```

创建：
```
/opt/pki/
├── root/           根 CA
├── management/     管理 CA
├── tls/            TLS CA
├── people/         People CA
├── codesign/       CodeSign CA
├── tsa/            TSA CA
├── hr/             HR CA
├── vpn/            VPN CA
├── acme/           ACME CA
├── server.pem      服务器 TLS 证书
└── pki.json        配置文件
```

## 四层架构（企业）

```
                    ┌──────────────┐
                    │   Root CA    │  L1 — 信任锚点
                    │  (offline)   │  ECDSA P-384, 20 年
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Policy CA   │  L2 — 策略缓冲层
                    │  (10 年)     │  ECDSA P-384
                    └──────┬───────┘
                           │
           ┌────────────────┼────────────────┐
           │                │                │
     ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
     │ TLS CA    │   │ People CA │   │ CodeSign  │  L3 — 签发 CA
     │ (5 年)    │   │ (5 年)    │   │ CA (RSA)  │  ECDSA P-256
     └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
           │                │                │
     ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
     │ Servers   │   │ Users     │   │ Software  │  L4 — 终端实体
     │ Clients   │   │ AIC Agents│   │ Code      │
     └───────────┘   └───────────┘   └───────────┘
```

### 特性

- Policy CA 作为根 CA 和签发 CA 之间的缓冲
- 根 CA 始终完全离线（从不接触在线基础设施）
- Policy CA 可以在不接触根 CA 的情况下调整子 CA 策略
- 支持策略映射、策略约束、抑制 anyPolicy
- 合规框架需要（SOC 2、PCI DSS、NIST）

### 为什么需要 Policy CA？

> "Policy CA 是四层和三层之间的唯一区别——它作为策略缓冲层：一旦根 CA 保持离线，Policy CA 就可以在不接触根 CA 的情况下调整子 CA 策略。"

优点：
1. **离线根 CA**：根 CA 私钥永远不会离开气隙机器
2. **策略灵活性**：Policy CA 可以在不涉及根 CA 的情况下轮换/续期
3. **合规性**：信任锚点和策略执行之间的职责分离
4. **审计跟踪**：策略更改在 Policy CA 级别记录

### 链验证

```bash
# 四层链需要 Policy CA 作为中间证书
openssl verify \
  -CAfile root/ca.pem \
  -untrusted policy/ca.pem \
  -untrusted tls/ca.pem \
  server.pem

# 预期输出
server.pem: OK
```

### init-full 命令

```bash
pki init-full \
  --root-name "MyCorp Root CA" \
  --hierarchy enterprise \
  --org "MyCorp" \
  --country US \
  --base-dir /opt/pki
```

创建：
```
/opt/pki/
├── root/           根 CA
├── policy/         Policy CA (新增)
├── management/     管理 CA
├── tls/            TLS CA
├── people/         People CA
├── codesign/       CodeSign CA
├── tsa/            TSA CA
├── hr/             HR CA
├── vpn/            VPN CA
├── acme/           ACME CA
├── server.pem      服务器 TLS 证书
└── pki.json        配置文件
```

## 对比

| 方面 | 3 层（简单） | 4 层（企业） |
|------|------------|------------|
| 深度 | Root → Sub-CA → 终端实体 | Root → Policy CA → Sub-CA → 终端实体 |
| 根 CA 离线 | 子 CA 创建后 | 始终完全离线 |
| 策略灵活性 | 有限 | 高（Policy CA 缓冲层） |
| 链验证 | 最多 2 个中间证书 | 最多 3 个中间证书 |
| 合规性 | 基础 | SOC 2、PCI DSS、NIST |
| 复杂度 | 低 | 中 |
| 部署 | `--hierarchy simple` | `--hierarchy enterprise` |

## 子 CA 定义

两种模式都创建 8 个业务子 CA：

| CA | 用途 | 密钥类型 | 有效期 |
|----|------|---------|--------|
| 管理 | 管理员/操作员证书 | ECDSA P-256 | 5 年 |
| TLS | 服务器/客户端 TLS | ECDSA P-256 | 5 年 |
| People | 用户/员工证书 | ECDSA P-256 | 5 年 |
| CodeSign | 代码签名 | RSA-4096 | 5 年 |
| TSA | 时间戳签名 | RSA-4096 | 5 年 |
| HR | 人力资源部门 | ECDSA P-256 | 5 年 |
| VPN | VPN 客户端 | ECDSA P-256 | 5 年 |
| ACME | 自动注册 | ECDSA P-256 | 5 年 |

所有子 CA 的 `MaxPathLen=0`（不能签发进一步的 CA）。

## 名称约束

子 CA 可以限制为特定域名：

```bash
pki ca init \
  --name "Web CA" \
  --profile sub-ca \
  --parent "Root CA" \
  --permitted-dns "*.example.com" \
  --excluded-dns "*.internal.example.com" \
  --permitted-emails "@example.com" \
  --out-cert web/ca.pem \
  --out-key web/ca.key
```

### 支持的约束类型

| 类型 | 描述 |
|------|------|
| DNS | 允许/排除的域名 |
| Email | 允许/排除的邮箱地址 |
| URI | 允许/排除的 URI 域名 |
| IP | 允许/排除的 IP CIDR 范围 |

### 执行

名称约束在链验证期间执行（`checkNameConstraints`）：
- 子证书中的每个 DNS 名称必须在允许的子树内
- 排除的子树始终优先于允许的子树
- DNS 匹配：`example.com` 也匹配 `sub.example.com`

## 策略约束

RFC 5280 用于策略执行的扩展：

### 策略映射（OID 2.5.29.33）

将 `issuerDomainPolicy` 映射到 `subjectDomainPolicy`：
```json
{
  "defaults": {
    "policy_mappings": ["2.16.840.1.101.3.2.1.48.1:2.16.840.1.101.3.2.1.48.2"]
  }
}
```

### 策略约束（OID 2.5.29.36）

```json
{
  "defaults": {
    "require_explicit_policy": 0,
    "inhibit_policy_mapping": 0
  }
}
```

- `require_explicit_policy`：经过 N 个中间证书后，要求显式策略
- `inhibit_policy_mapping`：经过 N 个中间证书后，不再有进一步的映射

### 抑制 anyPolicy（OID 2.5.29.54）

```json
{
  "defaults": {
    "inhibit_any_policy": 0
  }
}
```

经过 N 个中间证书后，`anyPolicy` OID 被抑制。

## 离线根 CA

### 设置

1. 在气隙机器上初始化根 CA
2. 仅将根证书复制到在线服务器
3. 使用 `pki ca offline-sign` 签署子 CA CSR
4. 将签署的子 CA 证书复制回来

### 离线签名

```bash
# 在离线机器上
pki ca offline-sign \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --csr sub.csr \
  --out sub-ca.pem \
  --validity 3650d
```

### 导入根密钥安全

根 CA 私钥导入被明确拒绝：
- 任何根密钥导入尝试都返回 `ErrRootCAImport`
- 系统检查公钥是否与数据库中已知的根 CA 匹配
- 防止攻击者将根密钥包装在非自签名证书中

## 交叉证书

交叉证书允许独立 PKI 域之间的信任：

```bash
# 签发交叉证书
pki cross-cert issue \
  --issuer "External Root" \
  --subject "My Root" \
  --validity 3650d

# 列出交叉证书
pki cross-cert list

# 吊销
pki cross-cert revoke \
  --issuer "External Root" \
  --serial AB12CD34 \
  --reason keyCompromise
```

### 交叉证书属性

- 目标的主体 + 公钥
- 颁发者的签名
- `MaxPathLen=0`（限制进一步委托）
- 可选名称约束

## 信任桥联邦

交叉证书的更高级抽象：

```bash
# 建立信任桥
pki trust-bridge issue "My Root" "Partner Root" 3650

# 列出信任桥
pki trust-bridge list

# 从远程联邦信任锚点
pki trust-bridge federate https://partner.example.com/ca-bundle.pem
```

### 信任池构建

联邦信任池由以下构建：
1. 本地 CA 证书
2. 有效的交叉证书记录
3. 数据库中的可信信任锚点

### 信任锚点导入

```bash
# 导入信任包
pki trust import --cert partner-ca.pem --name "Partner CA"

# 从 URL 获取（非回环主机需要 TLS）
pki trust fetch https://partner.example.com/ca.pem
```

安全要求：
- 非回环主机需要 TLS
- 32 MiB 大小限制
- 必须包含至少一个有效的根 CA
- 通过 SHA-256 哈希去重

## 证书链构建

### 链构建器 (`BuildChain`)

1. 从叶证书开始
2. 通过匹配 `RawIssuer` 查找颁发者候选
3. 可用时优先使用信任锚点
4. 通过 `seen` map 进行循环检测
5. 深度限制（默认 16）

### 路径验证 (`VerifyPath`)

**第 1 轮 — 结构检查（从叶到根）：**
- 每个证书的有效期窗口检查
- 签名验证
- 颁发者必须是 CA（`IsCA` 标志）
- 颁发者必须具有 `keyCertSign` KeyUsage
- 名称约束验证

**第 2 轮 — 路径长度约束：**
- 对于从根向下的每个 CA，中间证书不得超过 `MaxPathLen`

**第 3 轮 — 信任锚点检查：**
- 终端证书必须匹配已知的信任锚点

**第 4 轮 — 策略处理（可选）：**
- RFC 5280 Section 6.1 算法
- 策略映射、策略约束、抑制 anyPolicy

### CLI 验证

```bash
# 验证证书链
pki verify-path cert.pem --db /var/lib/pki/pki.db

# 带策略检查
pki verify-path cert.pem --db /var/lib/pki/pki.db --policy-check

# JSON 输出
pki verify-path cert.pem --db /var/lib/pki/pki.db --json
```

## 密钥轮换

支持双签名的原子 CA 密钥轮换：

```bash
# 检查轮换状态
curl -sk --cert superadmin.pem --key superadmin.key \
  https://localhost:4433/api/v1/ca/tls/rotation

# 执行轮换
curl -sk --cert superadmin.pem --key superadmin.key \
  -X POST https://localhost:4433/api/v1/ca/tls/rotate \
  -H 'Content-Type: application/json' \
  -d '{"cert": "/path/new-ca.pem", "key": "/path/new-ca.key"}'
```

### 轮换过程

1. 新密钥原子生效（`atomic.Pointer`）
2. 旧密钥保留为"遗留"用于双签名
3. 验证先前签发证书的过渡窗口
4. 服务器每 12 小时检查过期，7 天时发出警告

## 冷备份

CA 密钥的加密备份：

```bash
# 创建备份
pki ca cold-backup create \
  --ca-name "Root CA" \
  --ca-cert root/ca.pem \
  --ca-key root/ca.key \
  --password "backup-secret" \
  --out backup.json

# 验证备份
pki ca cold-backup verify \
  --backup backup.json \
  --password "backup-secret"
```

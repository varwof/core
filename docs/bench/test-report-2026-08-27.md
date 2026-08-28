# varwof 全面测试报告

**日期**: 2026-08-27  
**版本**: v1.1.1  
**环境**: Linux, Go 1.26.2

---

## 构建结果

| 仓库 | 类型 | 状态 |
|------|------|------|
| pkcs7 | 库 | ✅ |
| types | 库 | ✅ |
| engine | 库 | ✅ |
| gateway-core | 库 | ✅ |
| client | 库 | ✅ |
| types/aic | 二进制 | ✅ |
| register/gen-authz | 二进制 | ✅ |
| core/varwof | 二进制 | ✅ |
| gateway/gateway-http | 二进制 | ✅ |
| gateway/gateway-tcp | 二进制 | ✅ |
| gateway/gateway-udp | 二进制 | ✅ |

**构建**: 11/11 通过

---

## 单元测试 (test-all.sh)

| 仓库 | 状态 | 耗时 |
|------|------|------|
| pkcs7 | ✅ PASS | 1.290s |
| types | ✅ PASS | 1.395s |
| capability | SKIP (无测试文件) | — |
| register | ✅ PASS | — |
| engine | ✅ PASS | 10.374s |
| gateway-core | ✅ PASS | 43.454s |
| core | ✅ PASS | 0.164s |
| gateway | ✅ PASS | 26.422s |

**单元测试**: 7/7 通过

---

## Core 详细测试

| 包 | 状态 | 耗时 |
|----|------|------|
| auth | ✅ PASS | 0.036s |
| cmd/pki | ✅ PASS | 54.179s |
| internal | ✅ PASS | 0.024s |
| internal/ca | ✅ PASS | 22.682s |
| internal/capregistry | ✅ PASS | 0.016s |
| internal/i18n | ✅ PASS | 0.027s |
| internal/notifier | ✅ PASS | 0.346s |
| internal/ocsp | ✅ PASS | 0.718s |
| internal/pkcs12 | ✅ PASS | 0.041s |
| internal/provisioner | ✅ PASS | 0.026s |
| internal/remotesigner | ✅ PASS | 0.206s |
| internal/routing | ✅ PASS | 0.013s |
| internal/secrets | ✅ PASS | 0.019s |
| internal/serve | ✅ PASS | 97.191s |
| internal/signer | ✅ PASS | 0.163s |
| internal/tsa | ✅ PASS | 0.273s |
| tools/gen-testdata | ✅ PASS | 0.036s |

**Core 详细测试**: 17/17 通过

---

## 集成测试 (smoke.sh)

### 1. 前置条件

| 检查项 | 状态 |
|--------|------|
| pki 二进制 | ✅ |
| openssl | ✅ |
| python3 | ✅ |
| pkcs7 仓库 | ✅ |
| types 仓库 | ✅ |
| register 仓库 | ✅ |
| engine 仓库 | ✅ |
| gateway-core 仓库 | ✅ |
| client 仓库 | ✅ |
| core 仓库 | ✅ |
| gateway 仓库 | ✅ |

### 2. CA 层级初始化

| 步骤 | 状态 |
|------|------|
| CA hierarchy 初始化 | ✅ |
| Full chain 证书创建 | ✅ |

### 3. 服务器启动

| 检查项 | 状态 |
|--------|------|
| 服务器启动 (PID) | ✅ |
| HTTP 监听器 :8443 | ✅ |
| HTTPS 监听器 :9443 | ✅ |

### 4. 基础功能

| 测试项 | 状态 |
|--------|------|
| version 命令 | ✅ |
| healthz 端点 | ✅ |
| ca list 命令 | ✅ |

### 5. 证书签发

| 配置 | 状态 |
|------|------|
| tls-server | ✅ |
| tls-client | ✅ |
| m-admin | ✅ |
| vpn-client | ✅ |
| codesigning | ✅ |

### 6. 证书结构验证

| 检查项 | 状态 |
|--------|------|
| KU: DigitalSignature | ✅ |
| KU: KeyEncipherment | ✅ |
| EKU: ServerAuth | ✅ |
| 密钥算法: ECDSA | ✅ |
| 扩展: CRL DP | ✅ |
| 基本约束: CA:FALSE | ✅ |
| 证书/密钥匹配 | ✅ |

### 7. 证书链验证

| 证书 | 状态 |
|------|------|
| tls-server | ✅ |
| tls-client | ✅ |
| m-admin | ✅ |
| vpn-client | ✅ |
| codesigning | ✅ |

### 8. 证书生命周期

| 操作 | 状态 |
|------|------|
| revoke (吊销) | ✅ |
| CRL gen (生成吊销列表) | ✅ |
| CRL verify (验证吊销列表) | ✅ |

### 9. PFX/PKCS#12 导出

| 检查项 | 状态 |
|--------|------|
| PFX 导出 | ✅ |
| P12: 证书可读 | ✅ |
| P12: 错误密码拒绝 | ✅ |

### 10. TSA 时间戳

| 检查项 | 状态 |
|--------|------|
| TSA 查询创建 | ✅ |
| TSA 响应 | ✅ |
| TSA: granted | ✅ |

### 11. REST API (mTLS)

| 端点 | 状态 |
|------|------|
| GET /cas | ✅ |
| GET /certs | ✅ |
| POST /api/v1/certs | ✅ |
| metrics | ✅ |

### 12. RBAC

| 检查项 | 状态 |
|--------|------|
| rbac mode | ✅ |

### 13. 代码签名

| 操作 | 状态 |
|------|------|
| sign (签名) | ✅ |
| verify (验证) | ✅ |

### 14. 信任锚

| 操作 | 状态 |
|------|------|
| trust list | ✅ |
| trust import | ✅ |

### 15. 交叉证书

| 操作 | 状态 |
|------|------|
| cross-cert issue | ✅ |

### 16. 操作后健康检查

| 检查项 | 状态 |
|--------|------|
| healthz after all ops | ✅ |

**集成测试**: 56/56 通过

---

## 测试汇总

| 测试类型 | 通过 | 失败 | 总计 |
|----------|------|------|------|
| 构建 | 11 | 0 | 11 |
| 单元测试 (全仓库) | 7 | 0 | 7 |
| Core 详细测试 | 17 | 0 | 17 |
| 集成测试 (smoke) | 56 | 0 | 56 |
| **总计** | **91** | **0** | **91** |

---

## 结论

✅ **全部通过**

所有构建、单元测试和集成测试均通过。系统功能完整，包括：

- CA 层级初始化
- 证书签发 (tls-server, tls-client, m-admin, vpn-client, codesigning)
- 证书结构验证 (KeyUsage, ExtendedKeyUsage, 基本约束, CRL DP)
- 证书链验证
- 证书吊销与 CRL 生成
- PFX/PKCS#12 导出
- TSA 时间戳
- REST API (mTLS 认证)
- RBAC 权限控制
- 代码签名与验证
- 信任锚管理
- 交叉证书

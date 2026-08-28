# 部署加固

生产 varwof-core 部署的预检与维护清单。配合
[rbac-security-model.md](rbac-security-model.md) 与
[private-key-hygiene.md](private-key-hygiene.md) 使用。

## A. 授权与 RBAC

- [ ] `rbac.enabled = true`
- [ ] 多 CA 用 `rbac.mode = enterprise`（无作用域用户拒绝，fail-closed）
- [ ] 配置 `routes_file` → 活动表为权威（fail-closed，无宽松内嵌回退）
- [ ] 长期 routes/authz 启用 `policy_signing.enabled=true`（`require:true`）
- [ ] 无路由漂移：部署时校验活动表与仓库 `routes.json` 一致
- [ ] superadmin 权威仅来自 mTLS 证书；密码账号为 operator
- [ ] 非证书解析器永不给 `superadmin`（`resolveBasicAuth`/`resolveAPIToken`）
- [ ] 管理（`m-*`）签发：superadmin 角色 + mTLS 在场（否则 401/403）

## B. TLS 与传输

- [ ] `serve` TLS + `RequireAndVerifyClientCert` + `serve.ca_file` 信任池
- [ ] 不对外暴露明文监听（内部 HTTP 管理接口亦需收敛）
- [ ] 反向代理复验客户端证书，`/acme/`+`/dns/` 加白名单
- [ ] 边缘 TLS ≥ 1.2、强套件

## C. 密钥与机密

- [ ] 私钥 `0600`、服务用户属主；`management/users/private/` 锁定
- [ ] 根 CA 密钥离线 / `key_backend`(HSM)，绝不在 API 主机 Web 路径
- [ ] 备份集加密；冷备份 `pki cold-backup`/`backup-root-ca.sh`
- [ ] 审计证书≠密钥（certs/* 绝不用于密钥槽）
- [ ] `key_escrow` 恢复仅限 superadmin（证书优先）

## D. 限额与限流

- [ ] `rate_limit` 开启，合理按 IP 预算
- [ ] 请求体积上限（默认 10MB）完好
- [ ] `k8s_enabled` 保持 `false`（除非确需）
- [ ] `device_profile`/`engine`/`record_buffer` 按容量调优（已基准）

## E. 可观测与审计

- [ ] `/healthz`、`/readyz`、`/metrics` 纳入监控抓取
- [ ] 授权审计开启（`audit_salt`），经 `pki audit` / `GET /api/v1/audit` 复核
- [ ] `pki report` 生成 SOC 2/PCI DSS/NIST/ISO 合规证据
- [ ] 归档部署矩阵结果与 P0 断言（见 `rbac-verification-2026-08-28.md`）

## F. 运维卫生

- [ ] 热重载路径已演练（SIGHUP）；`routes_file` 不可读 → 启动中止（fail-closed）
- [ ] 备份定时器（`pki-backup.service`）已装；每季度恢复演练一次
- [ ] CA 密钥轮换流程已演练（`/api/v1/ca/{name}/rotate`）
- [ ] 每次密钥恢复都生成审计记录
- [ ] 版本/补丁节奏：每环境固定 `pki version`
# 测试待办事项

**日期**: 2026-08-27  
**状态**: 待完成

---

## 当前覆盖率

| 项目 | 包 | 覆盖率 | 状态 |
|------|-----|--------|------|
| core | auth | 88.0% | ✅ |
| core | cmd/pki | 74.7% | ⚠️ |
| core | internal | 90.4% | ✅ |
| core | internal/ca | 78.4% | ⚠️ |
| core | internal/capregistry | 79.5% | ⚠️ |
| core | internal/i18n | 91.2% | ✅ |
| core | internal/notifier | 87.3% | ✅ |
| core | internal/ocsp | 84.2% | ✅ |
| core | internal/pkcs12 | 84.2% | ✅ |
| core | internal/provisioner | 79.6% | ⚠️ |
| core | internal/remotesigner | 89.9% | ✅ |
| core | internal/routing | 91.7% | ✅ |
| core | internal/secrets | 95.7% | ✅ |
| core | internal/serve | 78.5% | ⚠️ |
| core | internal/signer | 80.4% | ✅ |
| core | internal/tsa | 87.8% | ✅ |
| client | client | 70.2% | ⚠️ |
| gateway | capreg | 94.1% | ✅ |
| gateway | http | 76.2% | ⚠️ |
| gateway | tcp | 68.6% | ❌ |
| gateway | udp | 64.5% | ❌ |

**目标**: 所有包 ≥ 80%

---

## 待办事项

### 1. 补充 gateway/udp 测试 (覆盖率 64.5%)

- [ ] 添加 DTLS 握手失败测试
- [ ] 添加 mTLS 认证失败测试
- [ ] 添加 QUIC 连接超时测试
- [ ] 添加非法数据包处理测试
- [ ] 添加连接限制触发测试
- [ ] 添加 nonce 重放过期测试

### 2. 补充 gateway/tcp 测试 (覆盖率 68.6%)

- [ ] 添加 tunnel 连接失败测试
- [ ] 添加 mesh 节点断开测试
- [ ] 添加端口映射冲突测试
- [ ] 添加审计日志写入失败测试
- [ ] 添加证书过期断开测试
- [ ] 添加并发连接限制测试

### 3. 补充 client 测试 (覆盖率 70.2%)

- [ ] 添加 AIC 批量签发边界测试
- [ ] 添加加密密钥解密失败测试
- [ ] 添加配置文件权限拒绝测试
- [ ] 添加网络超时重试测试
- [ ] 添加跨主机重定向拦截测试 (CL2)
- [ ] 添加策略签名伪造检测测试

### 4. 补充 core/cmd/pki 测试 (覆盖率 74.7%)

- [ ] 添加 `init-full` 层级模式测试
- [ ] 添加 `ca offline-sign` 流程测试
- [ ] 添加 `cold-backup` 加密验证测试
- [ ] 添加 `verify-path` 策略验证测试
- [ ] 添加 `benchmark` 输出格式测试
- [ ] 添加 `report` PDF 生成测试

### 5. 补充 core/internal/ca 测试 (覆盖率 78.4%)

- [ ] 添加名称约束违反测试
- [ ] 添加策略约束违反测试
- [ ] 添加路径长度超限测试
- [ ] 添加交叉证书吊销链测试
- [ ] 添加信任桥联邦失败测试
- [ ] 添加密钥轮换原子性测试

### 6. 补充 core/internal/serve 测试 (覆盖率 78.5%)

- [ ] 添加 RBAC 企业模式 CA scope 拒绝测试
- [ ] 添加委派代理会话过期测试
- [ ] 添加配置热重载原子性测试
- [ ] 添加审计日志 Merkle 链完整性测试
- [ ] 添加速率限制触发测试
- [ ] 添加 CORS 跨域拒绝测试

### 7. 补充 core/internal/provisioner 测试 (覆盖率 79.6%)

- [ ] 添加 OIDC 认证流程测试
- [ ] 添加 Basic Auth Argon2id 验证测试
- [ ] 添加 mTLS 证书链不完整测试
- [ ] 添加 token 过期/撤销测试
- [ ] 添加 AIC 能力交集为空测试

### 8. 补充 core/internal/routing 测试 (覆盖率 91.7%)

- [ ] 添加通配符路径匹配边界测试
- [ ] 添加 allow_aic=false 拒绝测试
- [ ] 添加 require_role 后缀匹配测试

### 9. 负面测试 (全部项目)

- [ ] 认证失败场景 (无效 token, 过期证书, 错误密码)
- [ ] 权限拒绝场景 (角色不足, CA scope 不匹配)
- [ ] 无效输入场景 (畸形 JSON, 超长字段, 空必填项)
- [ ] 并发冲突场景 (同时吊销同一证书)
- [ ] 资源耗尽场景 (内存, 连接数, 文件句柄)

### 10. 安全测试 (全部项目)

- [ ] SQL 注入防护测试
- [ ] 路径遍历防护测试
- [ ] 证书伪造检测测试
- [ ] 私钥泄露防护测试
- [ ] 策略文件篡改检测测试
- [ ] 重放攻击防护测试 (nonce)

### 11. 压力测试

- [ ] 并发证书签发 (100+ 并发)
- [ ] 并发 API 请求 (1000+ QPS)
- [ ] 大量证书吊销 (10000+ 条)
- [ ] CRL 生成性能
- [ ] OCSP 响应缓存命中率

### 12. 大规模 Agent 模拟 (5万人 × 10 agent × 24小时)

**现有工具**（varwof 各仓库中）：
- `engine/engine/aic_sim_bench_test.go` — 20万/100万/200万证书模拟
- `engine/engine/scale_bench_test.go` — 索引扩展 0/1万/10万 × 1/16 并发
- `core/cmd/pki/benchmark.go` — 加密算法基准
- `core/deploy/enterprise-full-test.sh` — 14 CA + 80+ 证书全栈集成

**缺失工具**:
- [x] 开发大规模 agent 并发模拟器 (Go 程序) — 已完成: `bench/` (嵌入式 serve.NewFull + SQLite, regular/AIC 双场景, stress/random 双模式)
- [x] 支持配置: 企业数、每企业 agent 数、请求间隔、持续时间 — `-agents/-users/-interval/-duration`
- [x] 支持指标采集: QPS、延迟 P50/P95/P99、错误率、DB 大小 — JSON + 文本报告 (`../results/`)
- [ ] 支持多机分布式压测 (SSH 调度)
- [ ] 生成 HTML 报告 (图表)
- [ ] 基线对比功能 (与上次结果比较)

**首轮基准测试** (2026-08-27, 18 核 / 32 GB 内存, SQLite 文件 DB; 标题误标 48 核——勘误见[性能工作日志](performance-worklog-2026-08-27.md) §1):
- 报告: `./benchmark-report-2026-08-27.md` | 工程记录: `./performance-worklog-2026-08-27.md` | 原始 JSON: `../results/*.json`
- 关键发现: 默认 record_buffer (max_pending=20000) 下持续签发被背压限制到 ~560/s (大量 503); 调大 max_pending 后 regular 达 ~5,600/s; AIC 并发提升后因每次签发的同步 `da_nonces` 写入 + SQLite 单写锁争用, 2500 agent 时退化到 533/s。

**待办 — 首轮基准发现的跟进项**:
- [x] 验证默认 `record_buffer.max_pending=20000` 背压语义: 确认 503 是 P1 设计中的有意图全链路限流, 补充配置文档 (max_pending/阈值调优指南)
- [x] AIC 写路径优化 ①: 启用内存引擎 (`EnableEngine`) 使 `da_nonces` 走内存
- [x] AIC 写路径优化 ②: Postgres DSN 对比测试 (引擎已支持 pgx 方言)
- [ ] 存储模型: 估算 3.6 亿证书的磁盘/行数模型 (1.9KB/行), 制定 SQLite WAL 生命周期与归档策略
- [x] bench 工具增强: 增加 `-engine` (内存引擎模式) 与 Postgres DSN (`postgres://`) 支持, 记录 WAL 峰值
- [x] 复测基线: 修复 record buffer 关闭时 flush (2026-08-27 已修) 后重跑矩阵
- [x] **argon2 根因**: 每请求 Basic Auth → `authByBasic`→`db.HashPassword`→`argon2.IDKey` 占 CPU 44%; bench 改 login-once + Bearer token, AIC/regular 各 +60% (详见[性能工作日志](performance-worklog-2026-08-27.md) §1)
- [x] engine 遗留: PG 上 `StoreDANonce` 同步单行 INSERT 改造为批量 (见下 "DA nonce 批量写"); **MariaDB+engine 写管线崩溃 (21GB/conn reset) 修复** —— 详见下 "MariaDB+engine 写管线崩溃根因与修复"
- [ ] `BulkInsertAICExtensions` 落地; engine 启动 LOAD 改分批 (替代 LIMIT/OFFSET)
- [x] **AIC 剩余墙定位**: 非 ECDSA/argon2。除 argon2 后 ECDSA 验签仅 ~3 核 (CPU 利用率 65% 未满), 真瓶颈 = 每请求同步单行 `INSERT INTO da_nonces` 同步过 WAL fsync (pg_stat_activity 采样实证), 修复方向见报告
- [x] **DA nonce 批量写 (engine 侧已修)**: `StoreDANonce` 非 WAL 分支改走 `RecordBuffer.AddDANonce` 批量收敛 + 满刷; AIC 复测 3,529/s、p50 47ms ([性能工作日志](performance-worklog-2026-08-27.md) §2 表)
- [x] **User/Token 内存索引 (engine + serve 双仓已落地)**: engine 新增 User/Token 索引 + 启动载入; serve 认证读路径 `getUserByUsername`/`getToken` engine 优先回退 DB; 写路径写穿 (login/create/delete/password-rotate)。AIC @600ms 达 **4,111 certs/s (注入上限)**, p50 2.7ms; DB 活动仅剩批量 `INSERT INTO certificates`。新增测试均绿 (engine 4 项 + core rbac_engine_test 4 项, race 通过)
- [x] **MariaDB+engine 写管线崩溃根因与修复 (R12, engine 仓已落地)**: 双层根因 —— ① 文档记录的 21GB 经 dmesg 实证为 **OOM 击杀** (`oom-kill bench-smoke anon-rss ~21GB`, 现版本 2GiB `MaxResidentBytes` 预算兜底, 不再复现); ② 真实缺陷 = **MariaDB 无读超时**, 半开连接让 `bulkInsertChunk→Exec→readPacket` 永久阻塞并持有 `flushMu` → drain 卡死 (pending 钉 maxPending, 全 503) → `Stop()→FlushAll()` 死锁挂死。修复: mysql DSN 注入 `timeout=10s&readTimeout=30s&writeTimeout=30s` (`ensureMariaDBTimeouts`) + `ExecContext` + `BulkInsertCertRecordsCtx`/`BulkStoreDANoncesCtx` + recordbuffer `flushDBTimeout=2min` ctx 兜底。**顺带 PG/MariaDB 批量分块 39→500 行/条** (`certChunkSize`, 往返降 ~13×)。复测 (均 exit=0 打印报告): MariaDB regular @100ms **7,575/s**、AIC @100ms **6,034/s** (修复前 4,325)、AIC @600ms 4,114/s; PG AIC @600ms 4,054/s 无回归。`-race` 全绿; 新单测 `TestEnsureMariaDBTimeouts`/`TestBulkInsertCertRecordsCtxCancelled`/`TestBulkStoreDANoncesCtxCancelled`
- [ ] 下一个墙: **write pipeline 批量落库吞吐** —— 已随 R12 分块优化提升 (MariaDB AIC 4,325→6,034/s), 但 100ms 高注入下仍可能背压 (503); 继续评估更大 chunk/批量 AIC 扩展
- [ ] engine 遗留: `BulkInsertAICExtensions` 落地; 启动 LOAD 改分批 (替代 LIMIT/OFFSET)

### 13. 模糊测试 (Fuzz)

- [ ] 证书解析器 fuzz
- [ ] CSR 解析器 fuzz
- [ ] JSON 请求体 fuzz
- [ ] 配置文件解析 fuzz
- [ ] PEM 编解码 fuzz

---

## 优先级

| 优先级 | 任务 | 影响 |
|--------|------|------|
| P0 | 负面测试 | 防止生产环境错误行为 |
| P0 | 安全测试 | 防止安全漏洞 |
| P1 | gateway/udp 补充 | 覆盖率 < 70% |
| P1 | gateway/tcp 补充 | 覆盖率 < 70% |
| P1 | client 补充 | 覆盖率 < 75% |
| P2 | core/cmd/pki 补充 | CLI 完整性 |
| P2 | core/internal/ca 补充 | CA 核心逻辑 |
| P2 | core/internal/serve 补充 | API 服务层 |
| P3 | 压力测试 | 性能验证 |
| P3 | 模糊测试 | 鲁棒性验证 |
| P3 | 大规模 Agent 模拟 | 生产环境验证 |
| P3 | 基准跟进: AIC 写路径优化 (engine/Postgres) | 生产 4,167 req/s 承载能力 |

---

## 进度跟踪

| 任务 | 负责人 | 开始日期 | 完成日期 | 状态 |
|------|--------|----------|----------|------|
| | | | | |

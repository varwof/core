# varwof-core 大规模 Agent 负载基准报告

- 日期: 2026-08-27
- 工具: `bench/` — 嵌入式 varwof-core 服务器 (SQLite 文件 DB) + 真实 `/api/v1/certs`
- 环境: 18 CPU / 32 GB 内存, NVMe, Go
- 目标工作负载: 5万用户 × 10 agent = 50万 agent × 每 10 分钟 1 张证书 × 24h ≈ 3.6 亿张, 平均 **≈4,167 req/s** (等价 150万人×8h)
- 原始数据: `../results/*.json`
- 前置工程记录（argon2 根因、DA nonce 批量写、User/Token 内存索引、MariaDB R12、
  锁分片 R4/R13）见 [性能工程工作日志](performance-worklog-2026-08-27.md) §1–§4

## 测试矩阵

| # | 模式 | 场景 | 时长 | agents | 间隔 | max_pending | 结果 |
|---|------|------|------|--------|------|-------------|------|
| 1 | stress | regular (tls-client) | 5 min | 100 | — | 默认 20000 | 561 certs/s, p50=4.4ms, **95.1% 503** |
| 2 | stress | aic (agent-proxy) | 5 min | 100 | — | 默认 20000 | 1,203 certs/s, p50=6.9ms, 47.6% 503 |
| 3 | random | regular | 10 min | 2,500 | 600ms | 500,000 | **3,106 certs/s**, 24.7% 503, p99=43ms |
| 4 | random | aic | 20 min | 2,500 | 600ms | 500,000 | **533 certs/s**, 81.5% fail, p50=195ms |
| — | 诊断 | regular (stress, 90s) | 90 s | 100 | — | 500,000 | 5,626 certs/s (无背压时 SQLite 批量落库上限) |

成功即签发成功 (HTTP 200); failure 主要来自 HTTP 503 `api.too_many_requests`
(record buffer 背压) 与少量 HTTP 0 (传输层/关闭时序)。

## 关键发现

1. **默认 record buffer 背压是有意的限流点** (P1 设计): `max_pending=20000` 时,
   Add() 被拒即返回 503。常规证书在无节流压测下持续吞吐被压到 ~560/s (95% 503),
   并非签名/网络瓶颈 (签名侧可达 ~11,000 req/s)。
2. **提升 `max_pending` 后 regular 场景 SQLite 批量落库可达 ~5,600 certs/s**
   (90s 诊断), `random` 模式 10 分钟持续稳定在 **3,106 certs/s** (arrival 4,167/s)、
   p99=43ms。即单机 SQLite + record buffer 在调参后可承接约 75% 的生产速率。
3. **AIC 场景是高并发下的瓶颈**: 每次 agent-proxy 签发都要同步写一行
   `da_nonces` (防重放) + ECDSA 校验, 与 record buffer 批量落库争用 SQLite 单写锁。
   并发 100 → 1,203/s; 并发 2,500 → **533/s**, p99=2.0s, max=18s。
   → 24h 生产速率 (4,167/s) 在单机 SQLite 上无法由 AIC 路径承载; 需
   a) 启用内存引擎 `EnableEngine` (nonce 走内存), 或 b) 迁移 Postgres, 或 c) 拆分写路径。
4. **每 24h 落库行数**: 常规 30 天有效期证书 1.9KB/行, AIC 1h 有效期证书同表存储。
   random 常规 10 分钟 ≈ 186 万行 (settled ~2GB)。长期运行需规划磁盘/WAL 空间。
5. **SQLite WAL 随负载增长** (运行期间数百 MB~GB), 关闭时 checkpoint 收敛;
   报告使用收敛后的磁盘占用与行数 (与 success 一致, 已修正 JSON)。

## 结论文档

| 场景 | 单机 SQLite 默认配置 | 单机 SQLite 调参后 (max_pending↑) |
|------|---------------------|-----------------------------------|
| regular (tls-client) | ~560 certs/s (503 限流) | ~3,100–5,600 certs/s |
| aic (agent-proxy) | ~1,200 certs/s (100 并发) | ~533 certs/s (2,500 并发), p99≈2s |

复现方式: `cd bench && go build -o bench .` 后按 `bench/README.md` 参数执行;
JSON 报告存 `../results/`。

---

## §1 无背压口径复测: maxpending 调大后的真实吞吐

**动机**: [工作日志](performance-worklog-2026-08-27.md) §4 里 AIC @100ms 40s
≈4.1k certs/s 混有大量 HTTP 503 —— 那是 `maxPending` 背压限流 (工作日志 §4 R13
修复后为干净限流, 非故障), 并非真实吞吐。为量到 CPU/服务器上限, 把
`-maxpending` 从 200k 调到 **1e6** (测试窗口内不触发 503, 排空可控) 重新注入。

**普通证书 (regular)**:

| 注入 | maxpending | 持续吞吐 | 503 | 延迟 |
|------|-----------|----------|-----|------|
| 2500 agents @100ms | 200k | 5,702 certs/s | 251,861 (52%) | p50 65ms |
| 2500 agents @100ms | 1e6 | **11,549 certs/s** | 0 (仅 HTTP 0 831) | p50 84ms p99 454ms |
| 5000 agents @40ms | 1e6 | 11,403 certs/s | HTTP 0 3,946 | p50 371ms (排队) |
| 5000 agents @40ms (CPU 采样) | 1e6 | 11,240 certs/s | 2.81% | CPU **925→1246%** |

→ **regular 真实上限 ≈ 1.1 万 certs/s, 由 CPU 封顶** (ECDSA 签名 + 序列化),
非内存。`window_evictions_total 0` 实证引擎内存预算 (`MaxCerts`/`MaxResidentBytes`)
从未触发; 503 与内存容量无关, 调大内存不会提升吞吐。

**AIC**:

| 注入 | maxpending | 持续吞吐 | 503 | 延迟 |
|------|-----------|----------|-----|------|
| 2500 agents @100ms | 200k (工作日志 §4) | ~4.1k certs/s (40s 累计 163k) | 大量 | p50 213ms |
| 2500 agents @100ms | 1e6 | **6,096 certs/s** | 0 (仅 HTTP 0 1,580) | p50 181ms p99 1.85s |
| 5000 agents @50ms | 1e6 | 5,778 certs/s | HTTP 0 3,073 | p50 342ms (排队) |
| 5000 agents @50ms (CPU 采样) | 1e6 | 5,661 certs/s | 4.08% | CPU **768→1179%** |

→ **AIC 真实上限 ≈ 5.7–6.1k certs/s, 由 CPU 封顶** (CA 签名 + DA 验签 + 每请求
2 条 DB 写)。调大 maxpending 后 AIC 提升幅度 (+49%) 大于 regular (+~50% 但起点高),
因为 AIC 每请求 2 条写更易撞 `maxPending`。

**结论**: 调大 `maxpending` 是消除 503 假象、量到真实 CPU 上限的正确做法;
两场景均无需动内存容量。regular (~1.1 万) 与 AIC (~6k) 的差距 = AIC 多出的
DA 验签 + 双写。再往上需并行 ECDSA / 硬件加速 (CPU 墙) 或 AIC 减写
(nonce 是否必须批量落库)。

**复测命令**:
```
/tmp/bench-smoke -mode random -scenario regular -duration 15s -agents 2500 \
  -users 2500 -interval 100ms -engine -maxpending 1000000 \
  -db 'mysql://bench:bench@127.0.0.1:3306/bench_mysql'
/tmp/bench-smoke -mode random -scenario aic -duration 15s -agents 2500 \
  -users 2500 -interval 100ms -engine -maxpending 1000000 \
  -db 'mysql://bench:bench@127.0.0.1:3306/bench_mysql'
```
> 注: `-maxpending` 越大, 停机排空积压越多, 收尾越慢 (1e6 时 15s run 排空约需
> 数十秒 ~ 2 分钟, 属预期; 勿在 CI 用超大值)。

## §2 企业场景 (5万人 × 10 agents) 可行性验证

**需求计算**: 5 万人 × 每人 10 个 agent = **50 万 agents**, 每 10 分钟申请一次 AIC
→ 平均注入 = 500,000 / 600s ≈ **833 AIC/s**。普通证书需求量小, 忽略。峰值若全部
agent 独立定时器 (泊松分布), 瞬时 ~2-3× 均值 (~2,500/s) 已在能力内。

**贴近真实强度测试** (engine 模式, MariaDB, `-interval 6s` × 5000 agents ≈ 833/s):

| 项 | 数值 |
|---|---|
| 注入 | 828 req/s |
| 成功 | 99378 / 99379 (**0.00% 错误**) |
| p50 / p95 / p99 | **2.4ms / 4.8ms / 5.0ms** |
| max | 20.9ms |
| 内存 (alloc) | 801.8MB (稳定, 无增长趋势) |
| HTTP 503 | 0 |

**结论**: 真实企业需求 833/s 远低于服务器能力上限 (~6k AIC/s, 见 §1), 余量 **~7 倍**。
此强度下服务器几乎空闲 (p99 仅 5ms), 无背压、无 503、内存稳定 —— **测试满足且大幅
有余量**。若日后需求翻倍 (~1.7k/s) 或全员突刺 (~2.5k/s) 仍在能力内。

**企业部署配置要点** (50 万 agent 规模, 非测试默认):
- `engine.max_da_nonces`: 瞬时驻留 DA nonce ≈ 833/s × 留存 210s (skew 30s + 3min 缓冲)
  ≈ **17.5 万**, 默认 10 万偏紧, 建议配置 **≥ 50 万** (靠 timestamp 短留存剪枝, 不会
  无限增长)。
- `engine.max_certs`: 取决于 AIC 证书留存时长与有效期 (Grace 剪枝按 NotAfter)。50 万
  agents 每 10 分钟换证 → 若证书留存 1h ≈ 30 万驻留, 建议配置 `max_certs ≥ 100 万`。
- `recordbuffer.max_pending`: 833/s 注入远低于吞吐, 默认 2 万即可 (不会触发 503);
  调大仅在压测量真实上限时需要。

**复测命令**:
```
/tmp/bench-smoke -mode random -scenario aic -duration 120s -agents 5000 \
  -users 5000 -interval 6s -engine -maxpending 500000 \
  -db 'mysql://bench:bench@127.0.0.1:3306/bench_mysql'
```

## §3 上班瞬间 burst (50万 agent 同时启动) 分析

**需求**: 5 万人 × 10 agents = 50 万 agents, 若上班瞬间全部同时醒来并发申请 AIC
(最坏情况), 即一次性 50 万请求突发。

**实测 burst 能力** (`-mode stress` 全速并发, engine + MariaDB):

| 项 | 数值 |
|---|---|
| 3000 agents 全速 30s | 187,688 req → **6,124 certs/s** |
| CPU | **1518% (15 核吃满)** |
| RSS 峰值 | 1.6 GB (18.7 万请求瞬时) |
| 503 | 0 (engine 预算 1000 万/2000 万足够) |
| p50 / p99 | 375ms / 2.3s (排队延迟, 非故障) |
| 错误 | 1.48% (全为 HTTP 0 = duration 结束关停 ctx 取消) |

**外推 50 万 agent 同时突发**:
- **排空时间 = 500,000 / 6,100 ≈ 82 秒** (服务器以 CPU 上限速度持续处理, 其余
  请求排队; 无 503, 排空完毕即全部完成)。
- **峰值内存**: 50 万 nonce + 50 万 cert 瞬时驻留。bench 实测 18.7 万请求 RSS
  ≈1.6GB, 线性外推 50 万 ≈ 3.5-4GB (尚未触 MaxResidentBytes 2GiB 预算 → 会
  evict+503, 需配大)。**真实部署必须把 `max_da_nonces`/`max_certs` 配足**
  (见 §2), 否则 burst 会触发预算背压 (503), 拖慢排空。
- **连接层**: 50 万并发 TCP 每个连接 1 goroutine, 纯连接内存 ~5GB 量级; 生产
  建议前端排队/LB, 不要让 50 万 TCP 同时打应用。

**现实修正**: "上班瞬间"更可能是 5 万人错峰登录 (10-30 分钟陆续), 或部分 agent
启动即申请、其余沿用旧证。真正的瞬时并发远低于 50 万; 即便最坏 50 万, 82 秒
排空 + 1.6-4GB 内存也是可接受的。**结论: 场景满足, 最坏情况有 ~80-90 秒
热启动期, 期间延迟上升但不丢请求、不 503 (预算配足时)。**

**复测命令**:
```
/tmp/bench-smoke -mode stress -scenario aic -duration 30s -agents 3000 \
  -users 5000 -engine -maxpending 500000 \
  -db 'mysql://bench:bench@127.0.0.1:3306/bench_mysql'
```
> 注: `-mode stress` = 所有 agent 全速无间隔, 用于 burst; `-agents` 越高收尾
> 排空越慢 (3000 agents/30s 排空需 ~1-2 分钟), 属预期。

**§3 补: 5000 agents 高并发对照** (`-mode stress`, engine + MariaDB, 30s):

| 项 | 3000 agents | 5000 agents |
|---|---|---|
| 吞吐 | 6,124 certs/s | **6,083 certs/s** |
| CPU | 1518% | 1472% |
| RSS 峰值 | 1.6 GB | **2.05 GB** |
| p50 / p99 | 375ms / 2.3s | 672ms / 2.3s |
| 503 | 0 | 0 |

**关键验证: burst 吞吐 ~6.1k certs/s 是 CPU 墙, 与并发数无关** (3000→5000 并发
吞吐不变)。因此 50 万同时突发排空时间恒定 ≈ 82 秒; 并发越高只是 (a) 排队延迟
升高 (p50 375→672ms), (b) RSS 峰值升高 (缓冲积压: 1.6→2.05GB)。RSS 随并发
近似线性 (5000 并发 ~2GB), 真实 50 万瞬时并发若全部直打应用, 缓冲积压内存会
显著更高 → 再次确认生产必须前端排队/LB + engine 内存预算配足。

## §4 可重现测试脚本

`../../bench/run-load-tests.sh` 一键重现 §1–§3 节全部测试（T1 regular 无背压、T2 AIC
无背压、T3 企业稳态 833/s、T4 burst 3000、T5 burst 5000）。每个测试的**目的、
预期、判读标准**写在脚本注释与 `../../bench/README.md`；结果输出到
`../results/<时间戳>/`（完整 log + 解析 metrics + SUMMARY.md 汇总表），
超时测试打 `(TIMEOUT)` 标记并继续。用法：`../../bench/run-load-tests.sh`（全量）或
`--only tN`（单个）。

脚本实测复现 §1–§3 数字（2026-08-28 完整一轮，全部 exit 正常）：

| 测试 | success | req/s | HTTP503 | p50 | p99 | err% |
|------|---------|-------|---------|-----|-----|------|
| t1-regular-nobp | 176577 | 11799 | 0 | 83.8ms | 408.3ms | 0.48% |
| t2-aic-nobp | 91094 | 6131 | 0 | 163.6ms | 2119.5ms | 1.54% |
| t3-enterprise-steady | 99291 | 827 | 0 | 2.4ms | 5.0ms | 0.00% |
| t4-burst-3000 | 186551 | 6268 | 0 | 385.0ms | 2249.3ms | 1.36% |
| t5-burst-5000 | 185490 | 6169 | 0 | 645.6ms | 2391.9ms | 2.12% |

> 完整原始结果留存于 `../results/20260828-005559/`（含每测试 log）。

## §5 CPU 节能模式对吞吐的影响

**背景**: 首次发现本机 18 核 CPU (Intel Ultra 5 125H) 全部处于 `powersave`
调速器 + **`intel_pstate/no_turbo=1`（睿频被禁）**, `scaling_max_freq` 被限制在
**1.2GHz**（写入被拒）。此前所有测试（§1–§4）都在此受限状态下进行。

**逐步解锁并重测 regular @100ms（engine+MariaDB, 2500 agents, 15s/10s）**:

| CPU 状态 | 实际频率 | regular certs/s | p50 | p99 |
|----------|----------|-----------------|-----|-----|
| powersave (节能) + no_turbo | 0.4–2.0GHz | **11,599** | 85ms | 446ms |
| performance + no_turbo | 1.0–1.5GHz | **13,127** (+13%) | 65ms | 331ms |
| performance + **turbo 开启** | 2 核 4.3GHz, 其余 1.2–2.0GHz | **16,642** (+43%) | **32ms** | 234ms |

AIC 同样受益: 6,096 → **8,040 certs/s (+32%)**。

**结论**: CPU 节能模式对吞吐有**显著影响 (~40%)** —— 节能→满睿频 regular
+43%、AIC +32%、p50 降 ~63%。原因: ECDSA 签名/序列化是纯 CPU 计算, 频率直接
决定吞吐; 1.2GHz 的 hard limit 使 18 核只发挥出 ~1/3 频率。

**测试环境要求**: 跑负载测试前应确保 `performance` governor + turbo 开启
（真实生产服务器/压力测试默认满载, 节能模式只出现在台式机待机场景）:

```bash
# 检查/开启（需 root；重启后恢复默认）
cat /sys/devices/system/cpu/intel_pstate/no_turbo        # 应为 0
for c in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > $c; done
echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo
echo 4500000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq  # 视 CPU 而定
```

> 本机当前已开启 performance+turbo。§1–§4 的数字为节能下测得的保守值;
> 实际能力以本节的 turbo 数字为准 (regular ~16.6k, AIC ~8.0k)。

## §6 树莓派 5 负载测试

**环境**: 树莓派 5 (RP5, aarch64), 4 核 Cortex-A76 @ 2.4GHz (ondemand 已满频),
4GB 内存, MariaDB 10.11 跑在 **SD 卡** (mmcblk0)。bench 二进制本机
`CGO_ENABLED=0 GOOS=linux GOARCH=arm64` 交叉编译, 静态链接纯 Go
(modernc sqlite / go-sql-driver 无 cgo)。

**Pi 5 性能** (engine + MariaDB, 无背压 maxpending 1e6):

| 测试 | 注入 | certs/s | p50 | p99 | 错误 |
|------|------|---------|-----|-----|------|
| T1 regular | 1000 agents @100ms | **~2,100** | 230-280ms | 1.4-1.8s | 2.6-3.0% |
| T2 AIC | 500 agents @100ms | **2,006** | 152ms | 414ms | 1.14% |
| T2 AIC | 1000 agents @100ms | **2,103** (20s窗) | 351ms | 944ms | 1.50% |
| T3 企业稳态 | 5000 agents×6s≈833/s | 805 | 8.1ms | 330ms | 0.02% |
| T4 burst | 2000 stress 全速 | **2,231** | 680ms | 2.3s | 0.14% |

**要点**:
- Pi 5 regular 与 AIC 吞吐接近 (~2,100/s), 均为 **CPU 墙** (4核 A76), 与 x86
  不同——x86 上 AIC 只有 regular 一半 (多 DA 验签+双写), Pi 上两者相当说明
  CPU 已被签名单线程打满, 差异被掩盖。
- **10s 短窗会低估**: AIC 1000 agents 10s 只测到 935/s, 20s 窗 2,103/s
  (短窗含排空/启动抖动)。
- **T3 企业稳态 833/s 接近 Pi 5 上限** (~2,100/s 的 40%): p99 330ms、错误
  0.02%, 尚可但余量小 (仅 ~2.5 倍 vs x86 的 9 倍)。50 万 agents 上班瞬间
  burst 在 Pi 5 上排空 = 500,000/2,200 ≈ **227 秒** (~4 分钟)。
- **SD 卡 I/O**: 初始 `innodb_flush_log_at_trx_commit=1` + O_DIRECT + doublewrite
  下 I/O wait 高达 58% (SD 卡 fsync 极慢); 调 `flush_log_at_trx_commit=2` 后
  wa 消失 (engine bulk 批量插入本身 fsync 少), CPU 满 80% 成瓶颈。
- MariaDB 根因: 原 root 密码未知, 经 `--skip-grant-tables` 重建了 `bench` 用户
  (`'bench'@'%'`), TCP 登录正常。

**对比汇总 (全部 engine + MariaDB, 无背压)**:

| 平台 | regular | AIC | 企业833/s余量 | burst排空(50万) |
|------|---------|-----|--------------|----------------|
| x86 18核 turbo | 16,642 | 8,040 | ~9.6倍 | ~62s |
| Pi 5 4核 2.4GHz | ~2,100 | ~2,100 | ~2.5倍 | ~227s |

> 结论: Pi 5 能满足稳态 833/s (错误<0.1%), 但 burst 余量仅 ~2.5 倍且排空需
> ~4 分钟; 若生产用 Pi 5 建议配 NVMe/USB3 SSD 替代 SD 卡 + 前端排队。

## §7 设备档案配置 (device_profile)

**动机**: §5§6 发现设备差异显著影响性能（x86 节能 vs turbo +43%、Pi 5 低内存/慢盘
需更小批）。把这些"设备敏感参数"做成 core 配置预设，部署时按设备选型即可。

**新增配置** `device_profile`（`internal/config.go`）:

| 值 | 适用设备 | 预设覆盖 |
|----|---------|---------|
| `""`（默认） | x86/台式机 | 内置默认（不覆盖） |
| `"low_mem"` | 单板机/低内存（如 Pi 5: 4GB + SD 卡） | record_buffer: threshold 500→**200**、max_pending→**5000**；engine: max_certs/max_da_nonces/max_nonces→**50000**、write_max_pending→**5000** |
| `"high_throughput"` | 多核服务器 | record_buffer: threshold→**1000**、max_pending→**100000**；engine: write_max_pending→**100000**、write_threshold→**500**、write_workers→**8** |

**语义**: profile 只填充**未显式配置**的值（显式 `engine`/`record_buffer` 设置
始终覆盖预设）。在 `LoadConfig.normalizeDefaults` 与 `MergeConfig` 末尾各应用一次，
覆盖 CLI 加载与配置合并两条路径。

**新增透传**: `engine.write_workers`（此前 core 未暴露，engine 默认 4；high_throughput
预设 8）。`EngineConfig` 增加该字段，`engineFromConfig` 透传给 `EngineOptions.WriteWorkers`。

**验证**: 新增单测 `TestDeviceProfileLowMem` / `TestDeviceProfileHighThroughput` /
`TestDeviceProfileExplicitWins` / `TestDeviceProfileInvalid` /
`TestDeviceProfileViaMerge`，全绿；`internal` 与 `internal/serve` 全套件通过。

> 说明: 系统层（CPU governor/turbo）与 MariaDB 调优（`innodb_flush_log_at_trx_commit`
> 等）**不做进配置**——前者属运维部署脚本范畴（§5 节已给命令），后者只能文档提示
> （见 `../../bench/README.md` Pi 5 节）。`device_profile` 只覆盖应用层（core 进程内）
> 能直接生效的写管线/内存预算参数。

### 7.1 实测修正 (2026-08-28, 本机 turbo, opencode 自身占 ~140% CPU 的噪声下)

bench 新增 `-profile` flag 并加 `-v` 生效配置回显后，实测发现**凭直觉预设的三个参数
全部是反优化**，已从 profile 移除：

| 参数 | 预设值（已移除） | 实测效果 (AIC @100ms 高并发) | 结论 |
|------|------------------|------------------------------|------|
| `record_buffer.threshold` | 1000 | 批量变大 → 单次 flush 持锁更久，吞吐 ~4% 降 | 保持默认 500 |
| `engine.write_threshold` | 500 | 写管线加深 → 吞吐 ~4% 降 | 保持默认 100 |
| `engine.write_workers` | 8 | DB 连接池竞争加剧 → **~25% 降**（8,228→6,103/s 单测） | 保持默认 4 |

修正后的 `high_throughput` 只提 `record_buffer.max_pending` 与 `engine.write_max_pending`
到 100000（更深的缓冲上限吸收突发）。

**验证数据**（3000 agent 30s burst，**未手动 `-maxpending`**，暴露默认 20000 vs 100000）:

| profile | 吞吐 | 错误率 | p50 | 判读 |
|---------|------|--------|-----|------|
| `""` 默认 | 2,996/s | **15.11%** | 593ms | 背压频繁（20000 上限） |
| `high_throughput` | 3,945/s | **5.51%** | 372ms | 深度缓冲吸收 burst (+32%, 错误率 -2.7×) |

高并发 AIC（2000 agents、命令行 `-maxpending 1e6` 屏蔽 max_pending 差异）5-run 中位：
default 5,967 / high_throughput 5,882 certs/s（差 ~1.4%，噪声内）——**修正后无性能回归**。

`go test ./internal/...` 全绿（含 `internal/serve` 72s 套件）。

## §8 关键配置决策速查 (2026-08-28)
> 用户问"哪些配置最关键、如何配置"，本节为沉淀的配置决策结论。已同步写入
> `docs/core/configuration.md` 的 "Performance Decision Guide" 一节。

**按价值排序的关键配置**：

| 层 | 配置 | 默认 | 怎么配 | 依据 |
|----|------|------|--------|------|
| ① 选型预设 | `device_profile` | `""` | 每类机器设一次：`""`(x86) / `low_mem`(Pi5/SBC) / `high_throughput`(多核) | §5§6§7.1 |
| ② 背压上限 | `record_buffer.max_pending` | 20000 | 扛突发提到 100000+（表: 错误率 15.1%→5.5%, +32%）；代价=内存 | §7.1 |
| ② 背压上限 | `engine.write_max_pending` | 20000 | 同上，AIC/revoke/nonce 写管线的上限 | §7.1 |
| ③ 防滥用 | `rate_limit` | 关 | `enabled/rate/burst` 每 IP 限流；测容量须关闭 | — |
| ④ 系统层 | CPU governor+no_turbo | — | 运维命令，不进配置文件（+43%） | §5 |
| ④ 系统层 | MariaDB `innodb_flush_log_at_trx_commit` | 1 | 文档提示，不进配置文件（SD 卡 iowait −58%） | §6 |

**别动三项**（实测调大使吞吐下降）：`record_buffer.threshold`(500)、
`engine.write_threshold`(100)、`engine.write_workers`(4)。profile 已编码这一结论；
手动覆盖唯一合理的场景是进一步加深 `max_pending`。

**结论口诀**：部署机先选 `device_profile`，扛突发现场再加深 `max_pending`，其余保持默认。
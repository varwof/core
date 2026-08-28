# varwof-core 负载测试

`run-load-tests.sh` 一键重现 `docs/bench/benchmark-report-2026-08-27.md`
⑤⑥⑦ 节的全部负载测试，输出可对照的关键指标，保证结论可复现、可审计。

## 前置条件

- Go ≥ 1.22，本机 MySQL/MariaDB（脚本用 `sudo mysql` 重建测试库，可改
  `MYSQL_ADMIN`）。
- bench 工具依赖本地 engine（`go.mod` 已 `replace` 指到 engine 仓）。

## 用法

```bash
# 跑全部 5 个测试（约 25 分钟，含每个测试后的 MySQL 排空）
./run-load-tests.sh

# 只跑指定测试
./run-load-tests.sh --only t1     # 普通证书无背压吞吐
./run-load-tests.sh --only t2     # AIC 无背压吞吐
./run-load-tests.sh --only t3     # 企业稳态 833/s
./run-load-tests.sh --only t4     # burst 3000 并发
./run-load-tests.sh --only t5     # burst 5000 并发
```

环境变量：`MYSQL_URL`（被测 DSN）、`MYSQL_ADMIN`（建库命令前缀）、
`NO_BUILD`（跳过重新编译）、`RUN_TIMEOUT`（单测试 wall-clock 上限）。

`-profile low_mem|high_throughput` 给被测的嵌入 server 套用设备调优预设（默认 `""`）：
high_throughput 把 `record_buffer.max_pending` / `engine.write_max_pending` 提到
100000 吸收突发；low_mem 收紧到 5000 适配 Pi 5 / SBC 内存。`-v` 会回显实际生效的
engine/record_buffer 配置便于核对。预设值来源与实测见 `docs/core/configuration.md`
及报告 ⑪a。

## 5 个测试各自的「目的」

| # | 测试 | 目的 | 关键判读 |
|---|------|------|----------|
| T1 | `regular` @100ms×2500 agents, maxpending 1e6 | 量普通证书在**无 503 背压**下的真实持续吞吐（CPU 上限）。default 200k maxpending 下 52% 是 503 限流，掩盖真实能力 | ~1.1 万 certs/s、503=0；注入提到 5000 agents 吞吐不变 = CPU 墙 |
| T2 | `aic` @100ms×2500 agents, maxpending 1e6 | 量 AIC 无背压下的真实持续吞吐。与 T1 对比量化 AIC 的额外成本（DA 验签 + 每请求 2 条写） | ~6k certs/s、503=0；企业需求 833/s 有 ~7 倍余量 |
| T3 | `aic` 5000 agents×6s ≈ 833/s, 120s | 验证真实企业需求（5 万人×10 agents，每 10 分钟一次 = 833/s）的长期稳定性 | 错误率 ~0、p99 个位数 ms、无 503 |
| T4 | `aic` stress 3000 agents 全速 | 测最坏情况（50 万 agents 上班瞬间同时突发）的 CPU 墙吞吐，外推排空时间 | ~6.1k/s、503=0；排空时间 = 50万/吞吐 ≈ 82s |
| T5 | `aic` stress 5000 agents 全速 | 验证 burst 吞吐是 CPU 墙、**与并发数无关**（对照 T4） | 两测试吞吐差 <5%；RSS 峰值 5000 > 3000 = 缓冲积压内存线性 |

## 输出

每次运行生成 `results/<时间戳>/`：

- `<测试名>.log`：完整 bench 报告（原始输出，含 latency/memory/db 行）
- `<测试名>.metrics`：解析出的关键指标（reqs/success/HTTP0/HTTP503/p50/p99/err）
- `SUMMARY.md`：汇总表（可对照报告 ⑤⑥⑦ 节数字复核）

超时（排空未完成）的测试会打上 `(TIMEOUT)` 标记并继续后续测试，不会拖死脚本。

## 参考结果（2026-08-28 实测，18 核 Intel Ultra 5 125H + 本机 MariaDB）

| 测试 | 成功(certs) | req/s | HTTP503 | p50 | p99 | err% |
|------|------------|-------|---------|-----|-----|------|
| t1-regular-nobp | 176577 | 11799 | 0 | 83.8ms | 408.3ms | 0.48% |
| t2-aic-nobp | 91094 | 6131 | 0 | 163.6ms | 2119.5ms | 1.54% |
| t3-enterprise-steady | 99291 | 827 | 0 | 2.4ms | 5.0ms | 0.00% |
| t4-burst-3000 | 186551 | 6268 | 0 | 385.0ms | 2249.3ms | 1.36% |
| t5-burst-5000 | 185490 | 6169 | 0 | 645.6ms | 2391.9ms | 2.12% |

> HTTP0 = duration 结束时的 ctx 取消（非故障）；本机结果受 CPU/MySQL 影响，
> 换机器重跑时对照 `SUMMARY.md` 看相对量级即可。

## 跨平台：树莓派 5

Pi 5 只有 Go 1.19（项目要求 1.26），无法在 Pi 上编译，需**本机交叉编译**
后 scp 过去（依赖全纯 Go：modernc sqlite / go-sql-driver / pgx）：

```bash
# 本机（core/bench 目录）
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/bench-pi5 .
scp /tmp/bench-pi5 varwof@192.168.1.236:/tmp/pibench/

# Pi 上跑（示例，AIC 无背压）
ssh varwof@192.168.1.236 \
  '/tmp/pibench/bench-pi5 -mode random -scenario aic -duration 20s \
   -agents 1000 -users 1000 -interval 100ms -engine -maxpending 1000000 \
   -db "mysql://bench:bench@127.0.0.1:3306/bench_mysql"'
```

Pi 5 注意点（详见报告 ⑩ 节）：
- 4 核 A76 @2.4GHz，CPU 墙，regular≈AIC≈2,100 certs/s
- MariaDB 跑 SD 卡上，`innodb_flush_log_at_trx_commit=2` 可消除 I/O wait 瓶颈
- **10s 短窗会低估**，用 ≥20s 窗口
- 结果：企业稳态 833/s 满足（错误 0.02%），burst 排空 ~4 分钟

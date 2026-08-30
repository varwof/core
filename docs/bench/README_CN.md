# Varwof Core — 基准与测试文档

varwof-core 引擎与写管线的负载基准和测试报告。原始数据与报告均由 `bench/` 工具产出
（工具本身见 [`bench/README.md`](../../bench/README.md)）。

## 报告

| 文档 | 说明 |
|------|------|
| [基准报告](zh/benchmark-report-2026-08-27.md) | 大规模 Agent 负载基准：测试矩阵、背压分析、无背压复测（§1）、企业 5万×10 场景（§2）、上班瞬间 burst（§3）、复现脚本（§4）、CPU 节能影响（§5）、树莓派 5（§6）、设备档案（§7）、配置速查（§8） |
| [性能工程工作日志](zh/performance-worklog-2026-08-27.md) | 前置工程记录 §1–§4：bench 工具变更、argon2 根因、引擎模式三后端对比（PG/MariaDB/SQLite）、DA nonce 批量写、User/Token 内存索引、MariaDB 写管线崩溃根因（R12）、瓶颈 prof + 锁分片（R4/R13） |
| [全面测试报告](zh/test-report-2026-08-27.md) | 构建、单元测试、集成冒烟套件（91/91 全通过） |
| [测试待办事项](zh/test-todos.md) | 覆盖率缺口、负面/安全/压力/模糊测试待办、优先级、进度跟踪 |

英文版见 [README.md](README.md)。

## 原始数据

- `results/*.json` — 测试矩阵背后的首轮调参前原始数据
  （当前测量由 `run-load-tests.sh` 产出，位于 bench 工作目录
  `results/<时间戳>/`）
- `results/20260828-005559/` — 可重现测试脚本的完整原始运行归档
  （`../../bench/run-load-tests.sh`）

## 复现

仓库根目录一条命令重跑全部负载测试：

```bash
./bench/run-load-tests.sh              # 全量（T1–T5）
./bench/run-load-tests.sh --only t1    # 单测
```

需要可用的基准数据库（默认 `mysql://bench:bench@127.0.0.1:3306/bench_mysql`），
并开启 `performance` CPU 调速器 + turbo（见基准报告 §5）。

## 许可证

AGPL-3.0
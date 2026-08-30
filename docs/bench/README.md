# Varwof Core — Bench & Test Documentation

Load benchmarks and test reports for the varwof-core engine and write pipeline.
Raw measurement data and reports produced by the `bench/` tool
(see [`bench/README.md`](../../bench/README.md) for the tool itself).

## Reports

| Document | Description |
|----------|-------------|
| [Benchmark Report](en/benchmark-report-2026-08-27.md) | Large-scale Agent load benchmark: test matrix, backpressure analysis, no-backpressure re-measurement (§1), enterprise 50k×10 scenario (§2), wake-up burst (§3), reproducible script (§4), CPU power-save impact (§5), Raspberry Pi 5 (§6), device profiles (§7) and configuration quick reference (§8) |
| [Performance Work Log](en/performance-worklog-2026-08-27.md) | Prerequisite engineering record §1–§4: bench tool changes, argon2 root cause, engine-mode backend comparison (PG/MariaDB/SQLite), DA nonce batch writes, User/Token memory indexes, MariaDB crash root cause (R12), bottleneck prof + lock sharding (R4/R13) |
| [Test Report](en/test-report-2026-08-27.md) | Full test run: builds, unit tests, integration smoke suite (91/91) |
| [Test To-Dos](en/test-todos.md) | Coverage gaps, negative/security/stress/fuzz to-do items, priorities, progress tracking |

Chinese versions: [README_CN.md](README_CN.md).

## Raw Data

- `results/*.json` — first-round, pre-tuning raw data behind the Test Matrix
  (current measurements are produced by `run-load-tests.sh` into
  `results/<timestamp>/` under the bench working directory)
- `results/20260828-005559/` — full raw run archive of the reproducible test script
  (`../../bench/run-load-tests.sh`)

## Reproducing

Re-run all load tests with one command from the repo root:

```bash
./bench/run-load-tests.sh              # full suite (T1–T5)
./bench/run-load-tests.sh --only t1    # single test
```

Requires a running benchmark DB (default `mysql://bench:bench@127.0.0.1:3306/bench_mysql`)
and the `performance` CPU governor + turbo enabled (see the benchmark report §5).

## License

AGPL-3.0
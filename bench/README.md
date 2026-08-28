# varwof-core Load Testing

`run-load-tests.sh` reproduces every load test from §1–§3 of
[`docs/bench/en/benchmark-report-2026-08-27.md`](../docs/bench/en/benchmark-report-2026-08-27.md)
in one command, emitting the key metrics for comparison so the conclusions stay
reproducible and auditable.

## Prerequisites

- Go ≥ 1.22, a local MySQL/MariaDB (the script rebuilds the test DB with
  `sudo mysql`; override via `MYSQL_ADMIN`).
- The bench tool depends on the local engine (`go.mod` has a `replace` pointing
  to the engine repo).

## Usage

```bash
# Run all 5 tests (~25 minutes, including the MySQL drain after each test)
./run-load-tests.sh

# Run a single test
./run-load-tests.sh --only t1     # regular cert no-backpressure throughput
./run-load-tests.sh --only t2     # AIC no-backpressure throughput
./run-load-tests.sh --only t3     # enterprise steady state 833/s
./run-load-tests.sh --only t4     # burst 3000 concurrency
./run-load-tests.sh --only t5     # burst 5000 concurrency
```

Environment variables: `MYSQL_URL` (DB under test), `MYSQL_ADMIN` (command
prefix used to create the DB), `NO_BUILD` (skip recompile), `RUN_TIMEOUT`
(single-test wall-clock cap).

`-profile low_mem|high_throughput` applies a device-tuning preset to the
embedded server under test (default `""`): high_throughput raises
`record_buffer.max_pending` / `engine.write_max_pending` to 100000 to absorb
bursts; low_mem tightens to 5000 for Pi 5 / SBC memory. `-v` echoes the
effective engine/record_buffer config for verification. Preset values and
measurements: `docs/core/configuration.md` and report §7.1.

## Purpose of Each Test

| # | Test | Purpose | Key interpretation |
|---|------|---------|--------------------|
| T1 | `regular` @100ms×2500 agents, maxpending 1e6 | Measure the real sustained throughput of regular certs **without 503 backpressure** (CPU ceiling). At the default 200k maxpending, 52% of requests are 503 throttle, hiding the real capability | ~11k certs/s, 503=0; throughput unchanged when injection raised to 5000 agents = CPU wall |
| T2 | `aic` @100ms×2500 agents, maxpending 1e6 | Measure real AIC sustained throughput without backpressure. Comparing with T1 quantifies AIC's extra cost (DA verification + 2 writes per request) | ~6k certs/s, 503=0; ~7× headroom over the 833/s enterprise demand |
| T3 | `aic` 5000 agents×6s ≈ 833/s, 120s | Verify long-term stability at the real enterprise demand (50k people×10 agents, once per 10 min = 833/s) | error ~0, p99 single-digit ms, no 503 |
| T4 | `aic` stress 3000 agents full-speed | Measure the worst case (500k agents waking at once) CPU-wall throughput; extrapolate the drain time | ~6.1k/s, 503=0; drain time = 500k/throughput ≈ 82s |
| T5 | `aic` stress 5000 agents full-speed | Verify burst throughput is a CPU wall, **independent of concurrency** (control vs T4) | both tests differ <5%; RSS peak 5000 > 3000 = buffered-backlog memory is linear |

## Output

Each run writes `results/<timestamp>/`:

- `<test>.log` — full bench report (raw output, incl. latency/memory/db rows)
- `<test>.metrics` — parsed key metrics (reqs/success/HTTP0/HTTP503/p50/p99/err)
- `SUMMARY.md` — summary table (cross-checkable against report §1–§3 numbers)

Tests that time out (drain not finished) get a `(TIMEOUT)` marker and the run
continues; a stuck test never blocks the whole script.

## Reference Results (measured 2026-08-28, 18-core Intel Ultra 5 125H + local MariaDB)

| Test | Success(certs) | req/s | HTTP503 | p50 | p99 | err% |
|------|----------------|-------|---------|-----|-----|------|
| t1-regular-nobp | 176577 | 11799 | 0 | 83.8ms | 408.3ms | 0.48% |
| t2-aic-nobp | 91094 | 6131 | 0 | 163.6ms | 2119.5ms | 1.54% |
| t3-enterprise-steady | 99291 | 827 | 0 | 2.4ms | 5.0ms | 0.00% |
| t4-burst-3000 | 186551 | 6268 | 0 | 385.0ms | 2249.3ms | 1.36% |
| t5-burst-5000 | 185490 | 6169 | 0 | 645.6ms | 2391.9ms | 2.12% |

> HTTP0 = ctx cancellation at the duration end (not a failure). Results depend
> on CPU/MySQL; on other machines compare relative magnitudes against the
> `SUMMARY.md` output.

## Cross-Platform: Raspberry Pi 5

The Pi 5 only ships Go 1.19 (the project needs 1.26), so it cannot compile on
the Pi — cross-compile **locally** and copy over (the dependencies are pure Go:
modernc sqlite / go-sql-driver / pgx):

```bash
# local (in core/bench)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/bench-pi5 .
scp /tmp/bench-pi5 <user>@<pi-host>:/tmp/pibench/

# on the Pi (example, AIC no-backpressure)
ssh <user>@<pi-host> \
  '/tmp/pibench/bench-pi5 -mode random -scenario aic -duration 20s \
   -agents 1000 -users 1000 -interval 100ms -engine -maxpending 1000000 \
   -db "mysql://bench:bench@127.0.0.1:3306/bench_mysql"'
```

Pi 5 notes (details in report §6):
- 4-core A76 @2.4GHz, CPU wall, regular≈AIC≈2,100 certs/s
- MariaDB on SD card: `innodb_flush_log_at_trx_commit=2` removes the I/O-wait
  bottleneck
- **10s short windows underestimate; use ≥20s windows**
- Result: steady 833/s is met (error 0.02%), burst drain ~4 minutes
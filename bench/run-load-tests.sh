#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# varwof-core load-test reproduction script
#
# Reproduces every load test from §1–§3 of the benchmark report
# (docs/bench/en/benchmark-report-2026-08-27.md) in one command and
# emits the comparable key metrics, keeping the conclusions
# reproducible and auditable.
#
# Usage:
#   ./run-load-tests.sh                 # run all 5 tests
#   ./run-load-tests.sh --only t1       # run one test (t1|t2|t3|t4|t5)
#   MYSQL_URL=mysql://bench:bench@127.0.0.1:3306/bench_mysql ./run-load-tests.sh
#
# Environment variables:
#   MYSQL_URL   MySQL DSN under test (default: local bench DB)
#   MYSQL_ADMIN command prefix for creating the DB (default "sudo mysql",
#               needs root DROP/CREATE privileges)
#   NO_BUILD    non-empty = skip recompiling the bench binary (use existing bin/bench-load)
#   RUN_TIMEOUT per-test wall-clock cap in seconds (default 0 = built-in caps)
#
# Output:
#   results/<timestamp>/<test>.log    full bench report
#   results/<timestamp>/SUMMARY.md    summary table + interpretation
# ═══════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)

# ─── Tunable config ───
MYSQL_URL="${MYSQL_URL:-mysql://bench:bench@127.0.0.1:3306/bench_mysql}"
MYSQL_ADMIN="${MYSQL_ADMIN:-sudo mysql}"
BENCH_BIN="$ROOT/bin/bench-load"
RESULTS="$ROOT/results/$(date +%Y%m%d-%H%M%S)"
# ─── Arg parsing ───
# Supports both `--only tN` and the ONLY=tN environment variable
ONLY="${ONLY:-all}"
if [ "${1:-}" = "--only" ]; then
  ONLY="${2:-all}"
fi
mkdir -p "$RESULTS"

# ─── Helpers ───

# Rebuild the MySQL DB under test: each test gets a clean DB so the starting
# state (row counts / memory / index state) is reproducible. Tests are fully
# repeatable and never pollute each other.
rebuild_db() {
  $MYSQL_ADMIN -e "DROP DATABASE IF EXISTS bench_mysql" 2>/dev/null || true
  $MYSQL_ADMIN -e "CREATE DATABASE bench_mysql"
  # Apply the 'bench'@'%' account grant (1133-class errors are ignorable, see history)
  $MYSQL_ADMIN -e "GRANT ALL ON bench_mysql.* TO 'bench'@'%'" 2>/dev/null || true
}

# Run bench in the background and sample the peak RSS. Args: <out-file> <wall-timeout(s)> <bench args...>
# Deliberately NOT wrapped in `timeout` (timeout forks a child, $! would be the
# timeout PID, not bench, so RSS sampling would hit the wrong process). Instead
# a built-in watchdog: past the wall seconds, kill bench directly, write a
# .timeout marker, and continue with the remaining tests. The peak RSS is
# returned on stdout (diagnostics go to stderr).
run_bench() {
  local out="$1" wall="$2"; shift 2
  local peak=0 pid start now rss
  "$BENCH_BIN" "$@" > "$out" 2>&1 &
  pid=$!
  start=$(date +%s)
  while kill -0 "$pid" 2>/dev/null; do
    rss=$(grep VmRSS "/proc/$pid/status" 2>/dev/null | awk '{print $2}') || rss=0
    [ "${rss:-0}" -gt "$peak" ] && peak=$rss
    now=$(date +%s)
    if [ $((now - start)) -gt "$wall" ]; then
      kill -9 "$pid" 2>/dev/null
      touch "$out.timeout"
      echo "  ⚠ bench killed after ${wall}s (test window + drain not finished)" >&2
      break
    fi
    sleep 1
  done
  wait "$pid" 2>/dev/null || true
  echo "$peak"   # returns peak RSS (kB)
}

# Extract the key metrics from a full bench report into $RESULTS/<name>.metrics
# (one per line, missing values default to 0). Report format: see the bench
# Benchmark Report output; some tests may have no HTTP 503 line (no
# backpressure), so every extracted item has a default fallback to keep
# set -e from aborting on a non-zero pipeline (incl. set -o pipefail).
parse_report() {
  local name="$1" f="$RESULTS/$name.log"
  local reqs success h0 h503 latline p50 p95 p99 max err
  reqs=$(grep -E "total requests:" "$f" | sed -E 's/.*\(([0-9]+) req\/s\).*/\1/' || true); reqs=${reqs:-0}
  success=$(grep -E "^  success:" "$f" | awk '{print $2}' || true); success=${success:-0}
  h0=$(grep -E "HTTP 0:" "$f" | awk '{print $3}' || true); h0=${h0:-0}
  h503=$(grep -E "HTTP 503:" "$f" | awk '{print $3}' || true); h503=${h503:-0}
  latline=$(grep -E "latency:" "$f" | sed -E 's/.*p50=([0-9.a-z]+) p95=([0-9.a-z]+) p99=([0-9.a-z]+) max=([0-9.a-z]+).*/\1 \2 \3 \4/' || true)
  read -r p50 p95 p99 max <<<"$latline"
  err=$(grep -E "error rate:" "$f" | awk '{print $3}' || true); err=${err:-0%}
  printf "%s\n%s\n%s\n%s\n%s %s %s %s\n%s\n" \
    "$reqs" "$success" "$h0" "$h503" "${p50:-0}" "${p95:-0}" "${p99:-0}" "${max:-0}" "$err" > "$RESULTS/$name.metrics"
}

# Print a one-line summary row (read from .metrics; format matches the
# SUMMARY.md header).
# Note: `read` only reads the first line; multi-line metrics must be read line by line with mapfile.
summary_row() {
  local name="$1" metrics="$2"
  local -a lines
  local p50 p95 p99 _max
  mapfile -t lines < "$metrics"
  read -r p50 p95 p99 _max <<<"${lines[4]:-}"
  printf "%-18s | %-9s | %-9s | %-7s | %-7s | %-10s | %-8s | %-8s\n" \
    "$name" "${lines[1]:-0}" "${lines[0]:-0}" "${lines[2]:-0}" "${lines[3]:-0}" \
    "${p50:-0}" "${p99:-0}" "${lines[5]:-0%}"
}

# ─── Preflight and build ───
echo "═══════════════════════════════════════════════════════════════"
echo "  varwof-core load-test reproduction script"
echo "  output dir: $RESULTS"
echo "═══════════════════════════════════════════════════════════════"

# 1. MySQL connectivity (prerequisite — avoid finding out mid-run that the DB is unusable)
echo -n "[check] MySQL $MYSQL_URL ... "
$MYSQL_ADMIN -e "SELECT 1" >/dev/null 2>&1 && echo "OK" || { echo "FAIL (need passwordless root mysql, or set MYSQL_ADMIN)"; exit 1; }

# 2. Build bench (unless disabled)
if [ -n "${NO_BUILD:-}" ] && [ -x "$BENCH_BIN" ]; then
  echo "[skip] using existing $BENCH_BIN"
else
  echo "[build] go build -o $BENCH_BIN ."
  (cd "$ROOT" && go build -o "$BENCH_BIN" .)
fi

# ─── Test list ───
# Each test is its own function: purpose comment / bench args / expected +
# acceptance criteria / output. All results land in $RESULTS, summarized at the end.

# ── T1: regular-cert no-backpressure real throughput ceiling ──
# Purpose: measure the real sustained throughput of regular certs with "no 503
#   backpressure" (CPU ceiling). Previously 52% of requests under the 200k
#   maxpending were 503 throttling, hiding the real capability; only after
#   raising maxpending to 1e6 (not triggered within the test window) is the
#   true CPU wall measured.
# Expected: ~11k certs/s, 503 = 0; throughput unchanged when injection raised to 5000 agents.
# Interpret: close to 10k/s with zero 503s → satisfied; significantly lower → CPU or lock bottleneck.
run_t1() {
  local name=t1-regular-nobp label="T1 regular no-backpressure throughput (CPU ceiling)"
  echo "▶ $label"
  rebuild_db
  local peak
  peak=$(run_bench "$RESULTS/$name.log" 420 -mode random -scenario regular \
    -duration 15s -agents 2500 -users 2500 -interval 100ms -engine \
    -maxpending 1000000 -db "$MYSQL_URL")
  parse_report "$name"
  printf "  peak RSS: %d kB\n" "$peak"
  echo "  -> $name: $(summary_row "$name" "$RESULTS/$name.metrics")"
}

# ── T2: AIC no-backpressure real throughput ceiling ──
# Purpose: measure the real sustained AIC (agent-proxy) throughput without
#   backpressure (CPU ceiling). Comparing with T1 quantifies AIC's extra server
#   cost vs regular (DA verification + 2 DB writes per request). The earlier
#   ~4.1k/s under 200k maxpending was a backpressure artifact.
# Expected: ~5.7-6.1k certs/s, 503 = 0; unchanged at 5000 agents (CPU wall).
# Interpret: AIC ceiling ≈ 6k/s → ~7× headroom over the 833/s enterprise demand.
run_t2() {
  local name=t2-aic-nobp label="T2 AIC no-backpressure throughput (CPU ceiling)"
  echo "▶ $label"
  rebuild_db
  local peak
  peak=$(run_bench "$RESULTS/$name.log" 420 -mode random -scenario aic \
    -duration 15s -agents 2500 -users 2500 -interval 100ms -engine \
    -maxpending 1000000 -db "$MYSQL_URL")
  parse_report "$name"
  printf "  peak RSS: %d kB\n" "$peak"
  echo "  -> $name: $(summary_row "$name" "$RESULTS/$name.metrics")"
}

# ── T3: enterprise steady state (50k people × 10 agents, once per 10 min) ──
# Purpose: verify long-term stability at the real enterprise demand.
#   50k people × 10 agents = 500k agents, one AIC every 10 min = average injection
#   833/s. Simulated exactly with 5000 agents at a 6s interval.
# Expected: error ~0, p99 single-digit ms, no 503, stable memory.
# Interpret: at 833/s, p99 < 100ms and error < 1% → ≥ 7× steady-state headroom.
run_t3() {
  local name=t3-enterprise-steady label="T3 enterprise steady state 833/s"
  echo "▶ $label"
  rebuild_db
  local peak
  peak=$(run_bench "$RESULTS/$name.log" 420 -mode random -scenario aic \
    -duration 120s -agents 5000 -users 5000 -interval 6s -engine \
    -maxpending 500000 -db "$MYSQL_URL")
  parse_report "$name"
  printf "  peak RSS: %d kB\n" "$peak"
  echo "  -> $name: $(summary_row "$name" "$RESULTS/$name.metrics")"
}

# ── T4: wake-up-moment burst (worst case 500k at once) ──
# Purpose: measure the worst case — 500k agents all requesting an AIC at the
#   same instant. stress mode = all agents at full speed, no interval, pummels
#   the server; 3000 agents measure the CPU-wall throughput, from which the
#   500k burst drain time is extrapolated = 500k ÷ measured throughput.
# Expected: ~6.1k certs/s (CPU wall), 503 = 0, RSS peak ~1.6GB.
# Interpret: drain time = 500000/throughput ≈ 82s; latency rises but no dropped
#   requests, no 503.
run_t4() {
  local name=t4-burst-3000 label="T4 burst 3000 concurrency"
  echo "▶ $label"
  rebuild_db
  local peak
  peak=$(run_bench "$RESULTS/$name.log" 600 -mode stress -scenario aic \
    -duration 30s -agents 3000 -users 5000 -engine -maxpending 500000 \
    -db "$MYSQL_URL")
  parse_report "$name"
  printf "  peak RSS: %d kB\n" "$peak"
  echo "  -> $name: $(summary_row "$name" "$RESULTS/$name.metrics")"
}

# ── T5: burst high-concurrency control ──
# Purpose: verify burst throughput is a CPU wall, independent of concurrency
#   (3000 vs 5000 agents). T4 at 3000 → 6.1k/s vs T5 at 5000 should be the
#   same ~6.1k/s, proving the drain time is constant at ≈82s regardless of
#   concurrency; higher concurrency only (a) raises queuing latency and
#   (b) raises the RSS peak.
# Interpret: the two tests within 5% → CPU wall holds; RSS 5000 > 3000 →
#   buffered-backlog memory is linear.
run_t5() {
  local name=t5-burst-5000 label="T5 burst 5000 concurrency"
  echo "▶ $label"
  rebuild_db
  local peak
  peak=$(run_bench "$RESULTS/$name.log" 600 -mode stress -scenario aic \
    -duration 30s -agents 5000 -users 5000 -engine -maxpending 500000 \
    -db "$MYSQL_URL")
  parse_report "$name"
  printf "  peak RSS: %d kB\n" "$peak"
  echo "  -> $name: $(summary_row "$name" "$RESULTS/$name.metrics")"
}

# ─── Execution ───
run_all() {
  run_t1; run_t2; run_t3; run_t4; run_t5
}

case "${ONLY}" in
  all)      run_all ;;
  t1|T1)    run_t1 ;;
  t2|T2)    run_t2 ;;
  t3|T3)    run_t3 ;;
  t4|T4)    run_t4 ;;
  t5|T5)    run_t5 ;;
  *)        echo "unknown test: $ONLY (available: all|t1..t5)"; exit 1 ;;
esac

# ─── Summary ───
cat > "$RESULTS/SUMMARY.md" <<'HDR'
# Load Test Summary

| Test | Success(certs) | req/s | HTTP0 | HTTP503 | p50 | p99 | err% |
|------|----------------|-------|-------|---------|-----|-----|------|
HDR
for f in "$RESULTS"/t*-*.metrics; do
  [ -e "$f" ] || continue
  name=$(basename "$f" .metrics)
  # run_bench writes the timeout marker as <log>.timeout; detect it by path
  if [ -e "${f%.metrics}.log.timeout" ]; then
    echo "  $name (TIMEOUT, results missing)" >> "$RESULTS/SUMMARY.md"
  else
    summary_row "$name" "$f" >> "$RESULTS/SUMMARY.md"
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  summary: $RESULTS/SUMMARY.md"
cat "$RESULTS/SUMMARY.md"
echo "═══════════════════════════════════════════════════════════════"
echo "  full reports: $RESULTS/t*.log  |  metrics: $RESULTS/t*.metrics"
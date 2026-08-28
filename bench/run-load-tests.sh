#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# varwof-core 负载测试重现脚本
#
# 一键重现 docs/bench/benchmark-report-2026-08-27.md ⑤⑥⑦ 节的全部
# 负载测试，输出可对照的关键指标，保证结论可复现、可审计。
#
# 用法:
#   ./run-load-tests.sh                 # 跑全部 5 个测试
#   ./run-load-tests.sh --only t1       # 只跑指定测试 (t1|t2|t3|t4|t5)
#   MYSQL_URL=mysql://bench:bench@127.0.0.1:3306/bench_mysql ./run-load-tests.sh
#
# 环境变量:
#   MYSQL_URL   被测 MySQL DSN（默认本机 bench 库）
#   MYSQL_ADMIN 建库命令前缀（默认 "sudo mysql"，需要 root 权限 DROP/CREATE 库）
#   NO_BUILD    非空则跳过 bench 二进制重新编译（用现有 bin/bench-load）
#   RUN_TIMEOUT 单个测试 wall-clock 上限（秒，默认 0 = 按测试内置上限）
#
# 输出:
#   results/<时间戳>/<测试名>.log   完整 bench 报告
#   results/<时间戳>/SUMMARY.md     汇总表 + 判读结论
# ═══════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)

# ─── 可调配置 ───
MYSQL_URL="${MYSQL_URL:-mysql://bench:bench@127.0.0.1:3306/bench_mysql}"
MYSQL_ADMIN="${MYSQL_ADMIN:-sudo mysql}"
BENCH_BIN="$ROOT/bin/bench-load"
RESULTS="$ROOT/results/$(date +%Y%m%d-%H%M%S)"
# ─── 参数解析 ───
# 支持 --only tN 与 ONLY=tN 环境变量两种方式
ONLY="${ONLY:-all}"
if [ "${1:-}" = "--only" ]; then
  ONLY="${2:-all}"
fi
mkdir -p "$RESULTS"

# ─── 工具函数 ───

# 重建被测 MySQL 库：每个测试独立库，保证干净起点（行数/内存/索引状态）
# 全部测试可重复跑，互不污染。
rebuild_db() {
  $MYSQL_ADMIN -e "DROP DATABASE IF EXISTS bench_mysql" 2>/dev/null || true
  $MYSQL_ADMIN -e "CREATE DATABASE bench_mysql"
  # 应用账号 grant：'bench'@'%'（1133 类报错可忽略，见历史记录）
  $MYSQL_ADMIN -e "GRANT ALL ON bench_mysql.* TO 'bench'@'%'" 2>/dev/null || true
}

# 后台运行 bench 并采样 RSS 峰值。参数: <输出文件> <wall-timeout(秒)> <bench 参数...>
# 注意不用 `timeout` 包裹（timeout 会 fork 子进程，$! 拿到的是 timeout 而非
# bench，RSS 采样会采错进程），改为内置 watchdog：超过 wall 秒直接 kill bench，
# 写入 .timeout 标记并继续后续测试。峰值 RSS 通过 stdout 返回（诊断输出走 stderr）。
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
      echo "  ⚠ bench 超过 ${wall}s 被终止 (测试窗口+排空未完成)" >&2
      break
    fi
    sleep 1
  done
  wait "$pid" 2>/dev/null || true
  echo "$peak"   # 返回峰值 RSS (kB)
}

# 从 bench 完整报告中提取关键指标，写入 $RESULTS/<name>.metrics（每行一个，
# 缺省填 0）。报告格式见 bench 的 Benchmark Report 输出；某些测试可能没有
# HTTP 503 行（无背压时），故每个提取项都做缺省兜底，避免 set -e 在无匹配
# （含 set -o pipefail 使管道非零）时中断。
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

# 打印单行摘要（从 .metrics 读取，格式与 SUMMARY.md 表头对应）
# 注意：read 只读第一行，多行指标必须用 mapfile 逐行读取。
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

# ─── 前置检查与编译 ───
echo "═══════════════════════════════════════════════════════════════"
echo "  varwof-core 负载测试重现脚本"
echo "  输出目录: $RESULTS"
echo "═══════════════════════════════════════════════════════════════"

# 1. MySQL 连通性（前提，避免跑一半才发现库不可用）
echo -n "[check] MySQL $MYSQL_URL ... "
$MYSQL_ADMIN -e "SELECT 1" >/dev/null 2>&1 && echo "OK" || { echo "FAIL (需能无密码 root 执行 mysql 或设 MYSQL_ADMIN)"; exit 1; }

# 2. 编译 bench（若未禁用）
if [ -n "${NO_BUILD:-}" ] && [ -x "$BENCH_BIN" ]; then
  echo "[skip] 使用现有 $BENCH_BIN"
else
  echo "[build] go build -o $BENCH_BIN ."
  (cd "$ROOT" && go build -o "$BENCH_BIN" .)
fi

# ─── 测试清单 ───
# 每个测试独立函数，含：目的注释 / bench 参数 / 预期与判读标准 / 输出
# 测试结果全部写入 $RESULTS，末尾统一汇总。

# ── T1: 普通证书 (regular) 无背压真实吞吐上限 ──
# 目的: 量普通证书在"无 503 背压"下的真实持续吞吐 (CPU 上限)。
#   此前 200k maxpending 下 52% 是 503 限流, 掩盖真实能力;
#   调大 maxpending 到 1e6 (测试窗口内不触发) 后量到的才是 CPU 墙。
# 预期: ~1.1 万 certs/s, 503 = 0, 与注入提高到 5000 agents 时吞吐不变。
# 判读: 若接近 1 万/s 且 503 归零 → 满足; 若明显偏低 → CPU 或锁瓶颈。
run_t1() {
  local name=t1-regular-nobp label="T1 普通证书无背压吞吐 (CPU上限)"
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

# ── T2: AIC 无背压真实吞吐上限 ──
# 目的: 量 AIC (agent-proxy) 无背压下的真实持续吞吐 (CPU 上限)。
#   与 T1 对比即可量化 AIC 相对 regular 的额外服务端成本 (DA 验签 + 每请求
#   2 条 DB 写)。此前 200k maxpending 下 ~4.1k/s 是背压假象。
# 预期: ~5.7-6.1k certs/s, 503 = 0; 提高到 5000 agents 吞吐不变 (CPU 墙)。
# 判读: AIC 上限 ≈ 6k/s → 企业需求 833/s 有 ~7 倍余量。
run_t2() {
  local name=t2-aic-nobp label="T2 AIC 无背压吞吐 (CPU上限)"
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

# ── T3: 企业稳态 (5万人 × 10 agents, 每 10 分钟一次) ──
# 目的: 验证真实企业需求强度下的长期稳定性。
#   5 万人 × 10 agents = 50 万 agents, 每 10 分钟申请一次 AIC
#   = 平均注入 833/s。用 5000 agents × 6s interval 精确模拟该强度。
# 预期: 错误率 ~0, p99 个位数 ms, 无 503, 内存稳定。
# 判读: 若 833/s 下 p99 < 100ms 且错误 < 1% → 稳态余量 ≥ 7 倍。
run_t3() {
  local name=t3-enterprise-steady label="T3 企业稳态 833/s"
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

# ── T4: 上班瞬间 burst (最坏 50 万同时突发) ──
# 目的: 测最坏情况 —— 50 万 agents 上班瞬间同时申请 AIC。
#   stress 模式 = 所有 agent 全速无间隔, 直接打满服务器; 用 3000 agents 测
#   CPU 墙吞吐, 外推 50 万突发排空时间 = 50万 ÷ 实测吞吐。
# 预期: ~6.1k certs/s (CPU 墙), 503 = 0, RSS 峰值 ~1.6GB。
# 判读: 排空时间 = 500000/吞吐 ≈ 82s; 期间延迟升高但不丢请求、不 503。
run_t4() {
  local name=t4-burst-3000 label="T4 burst 3000并发"
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

# ── T5: burst 高并发对照 ──
# 目的: 验证 burst 吞吐是 CPU 墙、与并发数无关 (3000 vs 5000 agents)。
#   T4 3000 并发 6.1k/s vs T5 5000 并发应同样 ~6.1k/s → 证明排空时间与
#   并发无关, 恒定 ≈ 82s; 并发越高仅 (a) 排队延迟升 (b) RSS 峰值升。
# 判读: 两测试吞吐差 < 5% → CPU 墙成立; RSS 5000 > 3000 → 缓冲积压内存线性。
run_t5() {
  local name=t5-burst-5000 label="T5 burst 5000并发"
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

# ─── 执行 ───
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
  *)        echo "未知测试: $ONLY (可用: all|t1..t5)"; exit 1 ;;
esac

# ─── 汇总 ───
cat > "$RESULTS/SUMMARY.md" <<'HDR'
# 负载测试汇总

| 测试 | 成功(certs) | req/s | HTTP0 | HTTP503 | p50 | p99 | err% |
|------|------------|-------|-------|---------|-----|-----|------|
HDR
for f in "$RESULTS"/t*-*.metrics; do
  [ -e "$f" ] || continue
  name=$(basename "$f" .metrics)
  # run_bench 把超时标记写为 <log>.timeout，这里按 metrics 路径反推检测
  if [ -e "${f%.metrics}.log.timeout" ]; then
    echo "  $name (TIMEOUT, 结果缺失)" >> "$RESULTS/SUMMARY.md"
  else
    summary_row "$name" "$f" >> "$RESULTS/SUMMARY.md"
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  汇总: $RESULTS/SUMMARY.md"
cat "$RESULTS/SUMMARY.md"
echo "═══════════════════════════════════════════════════════════════"
echo "  完整报告: $RESULTS/t*.log  | 指标: $RESULTS/t*.metrics"

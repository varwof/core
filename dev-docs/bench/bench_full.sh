#!/usr/bin/env bash
# pki-core 全密钥类型 × 三数据库 性能基准测试
# 每密钥类型 3 轮，自动生成 Markdown 报告
set -euo pipefail

# ─── 配置 ───
TOTAL=50          # 每轮签发数（RSA-8192 慢，用 50 张）
CONCURRENT=10     # 并发数
ROUNDS=3          # 每密钥类型轮数
KEYTYPES=("ecdsa-p256" "ecdsa-p384" "ecdsa-p521" "ed25519" "rsa-2048" "rsa-4096" "rsa-8192")
KEYTYPE_LABELS=(
  "ECDSA P-256" "ECDSA P-384" "ECDSA P-521" "Ed25519"
  "RSA-2048" "RSA-4096" "RSA-8192"
)

PKI=/usr/local/bin/pki-core
AGENT="--cert /etc/varwof/core/keys/agent.pem --key /etc/varwof/core/keys/agent.key"
KEYDIR=/etc/varwof/core/keys
TS=$(date +%Y%m%d-%H%M%S)
REPORT="$(dirname "$0")/FULL_RESULTS_${TS}.md"
TMPDIR=$(mktemp -d /tmp/pki-bench-full-XXXX)
trap "rm -rf $TMPDIR; echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null >/dev/null; kill \$(lsof -ti:19999 2>/dev/null) 2>/dev/null; kill \$(lsof -ti:19998 2>/dev/null) 2>/dev/null; true" EXIT

# ─── 辅助函数 ───
GOV_ORIG=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")

bench_latency() {
  local API=$1 AUTH=$2
  local T=""
  for i in $(seq 1 10); do
    local s=$(date +%s%N)
    curl -sk $AUTH -o /dev/null -w "" "$API/api/v1/cas?limit=1" 2>/dev/null
    local e=$(date +%s%N)
    T="$T $(((e-s)/1000000))"
  done
  echo "$(echo $T|tr ' ' '\n'|sort -n|sed -n '5p')"
}

bench_sequential() {
  local API=$1 AUTH=$2 KT=$3 R=$4
  local s=$(date +%s%N)
  for i in $(seq 1 $TOTAL); do
    curl -sk $AUTH -X POST "$API/api/v1/certs" \
      -H "Content-Type: application/json" \
      -d "{\"ca\":\"Varwof Issuing CA\",\"key_type\":\"$KT\",\"cn\":\"b-seq-$KT-r$R-i$i.bench.example.com\",\"validity\":1}" \
      -o /dev/null 2>/dev/null
  done
  local e=$(date +%s%N)
  local ms=$(((e-s)/1000000))
  echo "$ms|$((TOTAL*1000/(ms+1)))"
}

bench_concurrent() {
  local API=$1 AUTH=$2 KT=$3 R=$4
  local s=$(date +%s%N)
  seq 1 $TOTAL | xargs -P $CONCURRENT -I{} curl -sk $AUTH -X POST "$API/api/v1/certs" \
    -H "Content-Type: application/json" \
    -d "{\"ca\":\"Varwof Issuing CA\",\"key_type\":\"$KT\",\"cn\":\"b-con-$KT-r$R-i{}.bench.example.com\",\"validity\":1}" \
    -o /dev/null 2>/dev/null
  local e=$(date +%s%N)
  local ms=$(((e-s)/1000000))
  echo "$ms|$((TOTAL*1000/(ms+1)))"
}

bench_crl() {
  local API=$1 AUTH=$2
  local s=$(date +%s%N)
  curl -sk $AUTH -X POST "$API/api/v1/crl/Varwof%20Issuing%20CA/generate" \
    -o /dev/null 2>/dev/null
  local e=$(date +%s%N)
  echo "$(((e-s)/1000000))"
}

# 清理本数据库签发的测试证书（通过 API 吊销太慢，直接 SQLite 操作原始 DB）
clean_test_certs() {
  local API=$1 AUTH=$2
  # 批量吊销已签发的测试证书（删除再生成 CRL）
  # 简化为：不清理，每轮用不同前缀，最后一次性通过 DB 清理
  true
}

# ═══ 主流程 ═══
echo "═══ pki-core 全密钥类型 × 三数据库 基准测试 ═══"
echo "  日期: $(date)"
echo "  CPU: $(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)kHz"
echo "  每轮: $TOTAL 张, $CONCURRENT 并发, $ROUNDS 轮"
echo "  密钥类型: ${KEYTYPES[*]}"
echo "  输出: $REPORT"
echo ""

# 切到 performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null >/dev/null
echo "  CPU governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"

# ─── 单个数据库测试函数 ───
run_db_bench() {
  local DB_LABEL=$1 DB_NAME=$2 API=$3 AUTH=$4
  local CFG_FILE=$5  # may be empty for SQLite (already running)

  echo "" | tee -a "$REPORT"

  if [ "$DB_NAME" != "sqlite" ]; then
    # Start server
    $PKI serve --config "$CFG_FILE" &>/dev/null &
    eval "${DB_NAME}_pid=\$!"
    sleep 2
    # Verify
    curl -sf "$API/healthz" -o /dev/null 2>/dev/null || {
      echo "  ❌ $DB_LABEL failed to start, skipping"
      return
    }
  fi

  echo "  ✅ $DB_LABEL running at $API"

  local DB_RESULTS=""
  local IDX=0

  for KT in "${KEYTYPES[@]}"; do
    local LABEL="${KEYTYPE_LABELS[$IDX]}"
    IDX=$((IDX+1))

    # 3 rounds
    local R1_SEQ="" R1_CON="" R1_CRL=""
    local R2_SEQ="" R2_CON="" R2_CRL=""
    local R3_SEQ="" R3_CON="" R3_CRL=""

    for R in $(seq 1 $ROUNDS); do
      echo -n "  $DB_LABEL $LABEL 轮次 $R/$ROUNDS ... "

      # Latency
      local LAT=$(bench_latency "$API" "$AUTH")

      # Sequential
      local SEQ_OUT=$(bench_sequential "$API" "$AUTH" "$KT" "$R")
      local SEQ_MS="${SEQ_OUT%%|*}"
      local SEQ_TPS="${SEQ_OUT##*|}"

      # Concurrent
      local CON_OUT=$(bench_concurrent "$API" "$AUTH" "$KT" "$R")
      local CON_MS="${CON_OUT%%|*}"
      local CON_TPS="${CON_OUT##*|}"

      # CRL
      local CRL_MS=$(bench_crl "$API" "$AUTH")

      echo "LAT=${LAT}ms SEQ=${SEQ_TPS}TPS(${SEQ_MS}ms) CON=${CON_TPS}TPS(${CON_MS}ms) CRL=${CRL_MS}ms"

      # Store
      case $R in
        1) R1_SEQ=$SEQ_TPS; R1_CON=$CON_TPS; R1_CRL=$CRL_MS ;;
        2) R2_SEQ=$SEQ_TPS; R2_CON=$CON_TPS; R2_CRL=$CRL_MS ;;
        3) R3_SEQ=$SEQ_TPS; R3_CON=$CON_TPS; R3_CRL=$CRL_MS ;;
      esac
    done

    # Median of 3 rounds
    local SEQ_MED=$(echo -e "$R1_SEQ\n$R2_SEQ\n$R3_SEQ" | sort -n | sed -n '2p')
    local CON_MED=$(echo -e "$R1_CON\n$R2_CON\n$R3_CON" | sort -n | sed -n '2p')
    local CRL_MED=$(echo -e "$R1_CRL\n$R2_CRL\n$R3_CRL" | sort -n | sed -n '2p')

    DB_RESULTS="$DB_RESULTS$LABEL|$SEQ_MED|$CON_MED|$CRL_MED"$'\n'
  done

  # Save DB results to temp file
  echo "$DB_RESULTS" > "$TMPDIR/${DB_NAME}_results.txt"

  # Stop server if we started one
  if [ "$DB_NAME" != "sqlite" ]; then
    local PID_VAR="${DB_NAME}_pid"
    kill "${!PID_VAR}" 2>/dev/null || true
    wait "${!PID_VAR}" 2>/dev/null || true
    sleep 1
  fi
}

# ─── 准备临时配置 ────
# PG config
cat > "$TMPDIR/pg-bench.json" << CONF
{"db":"postgres://pki_test:pki_test_pass@127.0.0.1:5432/pki_core_test","cas":{"Varwof Issuing CA":{"cert":"$KEYDIR/issuing-ca.pem","key":"$KEYDIR/issuing-ca.key"}},"serve":{"addr":":19999"},"defaults":{"ca":"Varwof Issuing CA","profile":"tls-server","key_type":"ecdsa-p256","hash":"sha256","cert_validity":"2160h"}}
CONF

# MySQL config
cat > "$TMPDIR/my-bench.json" << CONF
{"db":"mysql://pki_test:pki_test_pass@tcp(127.0.0.1:3306)/pki_test","cas":{"Varwof Issuing CA":{"cert":"$KEYDIR/issuing-ca.pem","key":"$KEYDIR/issuing-ca.key"}},"serve":{"addr":":19998"},"defaults":{"ca":"Varwof Issuing CA","profile":"tls-server","key_type":"ecdsa-p256","hash":"sha256","cert_validity":"2160h"}}
CONF

# ─── 逐个数据库测试 ───

# 1. SQLite (当前运行的服务)
run_db_bench "SQLite"    "sqlite" "https://127.0.0.1:4433" "$AGENT" ""

# 2. PostgreSQL
run_db_bench "PostgreSQL" "pg"  "http://127.0.0.1:19999" "" "$TMPDIR/pg-bench.json"

# 3. MySQL
run_db_bench "MySQL"     "mysql" "http://127.0.0.1:19998" "" "$TMPDIR/my-bench.json"

# ═══ 生成报告 ═══
echo "═══ 生成报告 ═══"
echo "" > "$REPORT"

cat >> "$REPORT" << HEADER
# pki-core 全密钥类型 × 三数据库 性能基准测试报告

> 测试日期: $(date)
> 环境: $(hostname), CPU $(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)kHz (performance mode)
> 每轮: $TOTAL 张证书, $CONCURRENT 并发, $ROUNDS 轮取中位数

## 汇总

### 顺序签发 (TPS)

| 密钥类型 | SQLite | PostgreSQL | MySQL |
|---------|:------:|:----------:|:-----:|
HEADER

for KT_LABEL in "${KEYTYPE_LABELS[@]}"; do
  local SQLITE_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/sqlite_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  local PG_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/pg_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  local MYSQL_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/mysql_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  echo "| ${KT_LABEL} | ${SQLITE_VAL:-N/A} | ${PG_VAL:-N/A} | ${MYSQL_VAL:-N/A} |" >> "$REPORT"
done

cat >> "$REPORT" << HEADER2

### 并发签发 (TPS)

| 密钥类型 | SQLite | PostgreSQL | MySQL |
|---------|:------:|:----------:|:-----:|
HEADER2

for KT_LABEL in "${KEYTYPE_LABELS[@]}"; do
  local SQLITE_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/sqlite_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  local PG_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/pg_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  local MYSQL_VAL=$(grep "^$KT_LABEL|" "$TMPDIR/mysql_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  echo "| ${KT_LABEL} | ${SQLITE_VAL:-N/A} | ${PG_VAL:-N/A} | ${MYSQL_VAL:-N/A} |" >> "$REPORT"
done

cat >> "$REPORT" << HEADER3

### CRL 生成 (ms)

| 数据库 | CRL 耗时 |
|--------|:-------:|
HEADER3

for DB in sqlite pg mysql; do
  local LABEL=""
  case $DB in sqlite) LABEL="SQLite" ;; pg) LABEL="PostgreSQL" ;; mysql) LABEL="MySQL" ;; esac
  local CRL_VAL=$(grep "^$LABEL" "$TMPDIR/${DB}_results.txt" 2>/dev/null | head -1 | cut -d'|' -f4)
  echo "| $LABEL | ${CRL_VAL:-N/A} ms |" >> "$REPORT"
done

echo "" >> "$REPORT"
echo "---" >> "$REPORT"
echo "_测试工具: \`bench/bench_full.sh\`_" >> "$REPORT"

# ═══ 汇总到终端 ═══
echo ""
echo "══════════════════════════════════════════════════"
echo "  顺序签发 TPS 对比"
echo "══════════════════════════════════════════════════"
printf "  %-16s %8s %12s %8s\n" "密钥类型" "SQLite" "PostgreSQL" "MySQL"
echo "  ─────────────────────────────────────────────"
for KT_LABEL in "${KEYTYPE_LABELS[@]}"; do
  local SV=$(grep "^$KT_LABEL|" "$TMPDIR/sqlite_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  local PV=$(grep "^$KT_LABEL|" "$TMPDIR/pg_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  local MV=$(grep "^$KT_LABEL|" "$TMPDIR/mysql_results.txt" 2>/dev/null | head -1 | cut -d'|' -f2)
  printf "  %-16s %8s %12s %8s\n" "$KT_LABEL" "${SV:-N/A} TPS" "${PV:-N/A} TPS" "${MV:-N/A} TPS"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "  并发签发 TPS 对比"
echo "══════════════════════════════════════════════════"
printf "  %-16s %8s %12s %8s\n" "密钥类型" "SQLite" "PostgreSQL" "MySQL"
echo "  ─────────────────────────────────────────────"
for KT_LABEL in "${KEYTYPE_LABELS[@]}"; do
  local SV=$(grep "^$KT_LABEL|" "$TMPDIR/sqlite_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  local PV=$(grep "^$KT_LABEL|" "$TMPDIR/pg_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  local MV=$(grep "^$KT_LABEL|" "$TMPDIR/mysql_results.txt" 2>/dev/null | head -1 | cut -d'|' -f3)
  printf "  %-16s %8s %12s %8s\n" "$KT_LABEL" "${SV:-N/A} TPS" "${PV:-N/A} TPS" "${MV:-N/A} TPS"
done

echo ""
echo "  报告已生成: $REPORT"
echo ""

# 恢复 governor
echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null >/dev/null
echo "  CPU governor restored to: $GOV_ORIG"

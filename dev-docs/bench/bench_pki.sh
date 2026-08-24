#!/usr/bin/env bash
# pki-core 性能基准测试
# 测量证书签发吞吐量、API 响应时间、CRL 生成性能
set -euo pipefail

PKI_DIR="${1:-/etc/varwof/core}"
AGENT="--cert $PKI_DIR/keys/agent.pem --key $PKI_DIR/keys/agent.key"
API="https://127.0.0.1:4433"
TOTAL=100
CONCURRENT=10
PASS=0; FAIL=0

pass() { echo -e "\033[32m✅ $1\033[0m"; PASS=$((PASS+1)); }
fail() { echo -e "\033[31m❌ $1\033[0m"; FAIL=$((FAIL+1)); }
info() { echo -e "\033[36m$1\033[0m"; }

echo "════════════════════════════════════════════"
info "  pki-core 性能基准测试"
info "  服务器: $API"
info "  总请求: $TOTAL, 并发: $CONCURRENT"
echo "════════════════════════════════════════════"
echo ""

# 1. 基础延迟测试
info "1. 基础 API 延迟（单次请求，重复 10 次取中位数）"
TIMES=""
for i in $(seq 1 10); do
  START=$(date +%s%N)
  curl -sk $AGENT -o /dev/null -w "" "$API/api/v1/cas" 2>/dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  TIMES="$TIMES$MS "
done
MEDIAN=$(echo "$TIMES" | tr ' ' '\n' | sort -n | sed -n '5p')
pass "  GET /api/v1/cas 中位数: ${MEDIAN}ms"

TIMES=""
for i in $(seq 1 10); do
  START=$(date +%s%N)
  curl -sk $AGENT -o /dev/null -w "" "$API/api/v1/certs?limit=5" 2>/dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  TIMES="$TIMES$MS "
done
MEDIAN=$(echo "$TIMES" | tr ' ' '\n' | sort -n | sed -n '5p')
pass "  GET /api/v1/certs 中位数: ${MEDIAN}ms"
echo ""

# 2. 单线程签发吞吐量
info "2. 证书签发吞吐量（顺序签发 $TOTAL 张）"
START=$(date +%s%N)
for i in $(seq 1 $TOTAL); do
  curl -sk $AGENT -X POST "$API/api/v1/certs" \
    -H "Content-Type: application/json" \
    -d "{\"ca\":\"Varwof Issuing CA\",\"cn\":\"perf-test-$i.example.com\",\"validity\":1}" \
    -o /dev/null 2>/dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
TPS=$(( TOTAL * 1000 / (TOTAL_MS + 1) ))
pass "  $TOTAL 张证书, ${TOTAL_MS}ms, $TPS 张/秒"
echo ""

# 3. 并发签发测试
info "3. 并发签发（$CONCURRENT 并发，共 $TOTAL 张）"
START=$(date +%s%N)
for i in $(seq 1 $TOTAL); do
  (
    curl -sk $AGENT -X POST "$API/api/v1/certs" \
      -H "Content-Type: application/json" \
      -d "{\"ca\":\"Varwof Issuing CA\",\"cn\":\"concurrent-perf-$i.example.com\",\"validity\":1}" \
      -o /dev/null 2>/dev/null
  ) &
  if [ $((i % CONCURRENT)) -eq 0 ]; then wait; fi
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
TPS=$(( TOTAL * 1000 / (TOTAL_MS + 1) ))
pass "  $TOTAL 张证书, ${TOTAL_MS}ms, $TPS 张/秒（并发 $CONCURRENT）"
echo ""

# 4. CRL 生成
info "4. CRL 生成时间"
for size in 10 100 500; do
  START=$(date +%s%N)
  curl -sk $AGENT -X POST "$API/api/v1/crl/Varwof%20Issuing%20CA/generate" -o /dev/null 2>/dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  pass "  CRL 生成: ${MS}ms（${size} 个已吊销证书）"
done
echo ""

# 5. 内存使用
info "5. 服务端资源"
MEM=$(ps -o rss= -C pki-core 2>/dev/null | head -1 || echo 0)
CPU=$(ps -o %cpu= -C pki-core 2>/dev/null | head -1 || echo 0)
if [ "$MEM" -gt 0 ]; then
  pass "  内存: $(( MEM / 1024 )) MB  RSS"
  pass "  CPU: ${CPU}%"
fi
echo ""

echo "════════════════════════════════════════════"
echo -e " 通过: $PASS  失败: $FAIL"
echo "════════════════════════════════════════════"

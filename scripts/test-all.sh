#!/usr/bin/env bash
# test-all.sh — Run unit tests across all varwof repos
# Usage: ./scripts/test-all.sh [--short]
# Requires: go 1.26+, repos cloned (run build.sh first)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$(dirname "$CORE_DIR")}"
GOFLAGS="${GOFLAGS:--buildvcs=false}"

SHORT=false
[[ "${1:-}" == "--short" ]] && SHORT=true

REPOS=(
  "pkcs7"
  "types"
  "capability"
  "register"
  "engine"
  "gateway-core"
  "core"
  "gateway"
)

TEST_ARGS="-count=1"
$SHORT && TEST_ARGS="$TEST_ARGS -short"

echo "═══════════════════════════════════════════════════════════"
echo "  varwof test"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════"
echo ""

PASS=0; FAIL=0
for repo in "${REPOS[@]}"; do
  REPO_DIR="$BUILD_DIR/$repo"
  if [ ! -d "$REPO_DIR" ]; then
    echo "[$repo] SKIP (not cloned)"
    continue
  fi

  cd "$REPO_DIR"

  # Check if there are test files
  if ! find . -name "*_test.go" -print -quit 2>/dev/null | grep -q .; then
    echo "[$repo] SKIP (no test files)"
    continue
  fi

  result=$(go test $GOFLAGS $TEST_ARGS ./... 2>&1 | tail -3)
  exit_code=$?

  if [ $exit_code -eq 0 ]; then
    echo "[$repo] ✅ PASS"
    echo "  $(echo "$result" | head -1)"
    ((PASS=PASS+1))
  else
    echo "[$repo] ❌ FAIL"
    echo "  $(echo "$result" | tail -2)"
    ((FAIL=FAIL+1))
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Summary: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════"

[ $FAIL -eq 0 ] && echo "  ✅ ALL PASSED" || echo "  ❌ SOME FAILED"
[ $FAIL -eq 0 ]

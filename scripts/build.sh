#!/usr/bin/env bash
# build.sh — Clone all varwof repos and build binaries to bin/
# Usage: ./scripts/build.sh [--clean]
# Requires: git, go 1.26+
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$(dirname "$CORE_DIR")}"
GOFLAGS="${GOFLAGS:--buildvcs=false}"

CLEAN=false
[[ "${1:-}" == "--clean" ]] && CLEAN=true

# All repos in dependency order
REPOS=(
  "pkcs7"
  "types"
  "capability"
  "register"
  "engine"
  "gateway-core"
  "client"
  "core"
  "gateway"
)

echo "═══════════════════════════════════════════════════════════"
echo "  varwof build"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Source: $BUILD_DIR"
echo "  Output: $CORE_DIR/bin/"
echo ""

# ── Step 1: Clone ──
echo "── 1. Clone repositories ──"
for repo in "${REPOS[@]}"; do
  TARGET="$BUILD_DIR/$repo"
  if [ -d "$TARGET/.git" ]; then
    echo "  [$repo] already cloned"
  else
    echo -n "  [$repo] cloning... "
    git clone --depth 1 "https://github.com/varwof/$repo.git" "$TARGET" 2>/dev/null && echo "OK" || echo "FAIL"
  fi
done
echo ""

# ── Step 2: Build ──
echo "── 2. Build binaries ──"
mkdir -p "$CORE_DIR/bin"

PASS=0; FAIL=0
build_lib() {
  local repo="$1"
  cd "$BUILD_DIR/$repo"
  go build $GOFLAGS ./... 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "  [$repo] library ✓"
    ((PASS=PASS+1))
  else
    echo "  [$repo] library ✗"
    ((FAIL=FAIL+1))
  fi
}

build_bin() {
  local repo="$1" cmd="$2" output="$3"
  cd "$BUILD_DIR/$repo"
  go build $GOFLAGS -o "$CORE_DIR/bin/$output" "./cmd/$cmd/" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "  [$repo] $output ✓"
    ((PASS=PASS+1))
  else
    echo "  [$repo] $output ✗"
    ((FAIL=FAIL+1))
  fi
}

# Libraries (build check only)
for lib in pkcs7 types engine gateway-core client; do
  build_lib "$lib"
done

# Binaries
build_bin "types"     "aic"        "aic"
build_bin "register"  "gen-authz"  "gen-authz"
build_bin "core"      "pki"        "pki"
build_bin "gateway"   "http"       "gateway-http"
build_bin "gateway"   "tcp"        "gateway-tcp"
build_bin "gateway"   "udp"        "gateway-udp"

echo ""
echo "── Build Summary ──"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
ls -lh "$CORE_DIR/bin/" 2>/dev/null | grep -v "^total"
echo ""

[ $FAIL -eq 0 ] && echo "  ✅ ALL BUILT" || echo "  ❌ SOME FAILED"
[ $FAIL -eq 0 ]

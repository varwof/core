#!/usr/bin/env bash
# quick-start.sh — One-command: build + test + smoke
# Usage: ./scripts/quick-start.sh [--skip-smoke]
# Requires: git, go 1.26+, openssl, python3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$(dirname "$CORE_DIR")}"

SKIP_SMOKE=false
[[ "${1:-}" == "--skip-smoke" ]] && SKIP_SMOKE=true

echo "═══════════════════════════════════════════════════════════"
echo "  varwof quick-start"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Build ──
echo "═══ Step 1/3: Build ═══"
bash "$SCRIPT_DIR/build.sh"
echo ""

# ── Step 2: Test ──
echo "═══ Step 2/3: Test ═══"
bash "$SCRIPT_DIR/test-all.sh"
echo ""

# ── Step 3: Smoke ──
if [ "$SKIP_SMOKE" = false ]; then
  echo "═══ Step 3/3: Smoke ═══"
  bash "$SCRIPT_DIR/smoke.sh"
  echo ""
else
  echo "═══ Step 3/3: Smoke (SKIPPED) ═══"
  echo ""
fi

echo "═══════════════════════════════════════════════════════════"
echo "  Done!"
echo "  Binaries: $CORE_DIR/bin/"
echo "═══════════════════════════════════════════════════════════"

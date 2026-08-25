#!/usr/bin/env bash
#
# aic-db-mysql-v2.sh — AIC database test suite (database-v1 scheme)
#
# Coverage (per docs/database-scheme-design.md §8 closed-loop):
#   1. Rule files (std/database-v1: query:SELECT)
#      - tables / columns / filter_columns / row_filter / limit contract validation
#      - conditions (mini-language) and flow (Mini Workflow) structure validation
#   2. PKCS#7 signing + verification (reuses register signing tools)
#   3. Execution budget sandbox + static pre-check (no nested loops / out-of-bound reject)
#   4. MySQL SQL generation (structured predicates → SQL, injection-safe)
#   5. Multi-user permission matrix (zhangsan/lisi/privilege-escalation/wrong-tenant)
#   6. Gateway phase-two plugin adaptation (RulePlugin)
#   7. TS browser-side mirror (same semantics)
#
# Usage:
#   scripts/aic-db-mysql-v2.sh
#
# Configurable (env vars):
#   REGISTER_DIR   register module directory (default <workspace>/register)
#   WORKDIR        output directory (default /tmp/aic-db-mysql-v2)
#   MYSQL_DSN      optional: real MySQL DSN (e.g. "user:pass@tcp(127.0.0.1:3306)/test")
#                  connectivity check only; SQL execution requires mysql-api demo customers table
#
# Exit code: 0 = all pass; non-zero = failures
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(cd "$ROOT/../varwof" 2>/dev/null || cd "$ROOT/.." 2>/dev/null || echo "$ROOT")}"
REGISTER_DIR="${REGISTER_DIR:-$WORKSPACE_ROOT/register}"
WORKDIR="${WORKDIR:-/tmp/aic-db-mysql-v2}"
GO="${GO:-go}"
NODE="${NODE:-node}"

mkdir -p "$WORKDIR"
PASS=0
FAIL=0
FAILED_LIST=()

log()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '\033[1;31m  [FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED_LIST+=("$*"); }
note() { printf '\033[1;36m%s\033[0m\n' "$*"; }

# ---------- Environment check ----------
command -v "$GO" >/dev/null 2>&1 || { echo "go not found"; exit 2; }
command -v "$NODE" >/dev/null 2>&1 || { echo "node not found"; exit 2; }
[ -d "$REGISTER_DIR/demo/rule-exec" ] || { echo "register demo not found: $REGISTER_DIR/demo/rule-exec"; exit 2; }

# ============================================================
log "== 1. Rule validation + execution budget + SQL generation + permission matrix (Go test suite) =="
OUT="$("$GO" test "$REGISTER_DIR/ruleexec/" 2>&1)"
if [ "$?" -eq 0 ]; then
  ok "Go test suite passed (rules/budget/conditions/flow/SQL/signing/plugins)"
else
  fail "Go test suite: $OUT"
fi

# ============================================================
log "== 2. End-to-end closed loop (rule → PKCS#7 sign → verify → execute) =="
E2E_OUT="$(cd "$REGISTER_DIR" && "$GO" run ./demo/rule-exec 2>&1)"
if echo "$E2E_OUT" | grep -q "end-to-end closed-loop verification passed"; then
  ok "End-to-end closed-loop verification passed"
else
  fail "End-to-end closed loop: $E2E_OUT"
fi

# ============================================================
log "== 3. MySQL SQL generation (database-v1 contract → SQL) =="
SQL="$("$GO" run "$REGISTER_DIR/demo/rule-exec" -sql 2>&1 | tail -1)"
EXPECTED="SELECT \`id\`, \`name\` FROM \`customers\` WHERE (\`tenant_id\` = 'org-a') LIMIT 100"
if [ "$SQL" = "$EXPECTED" ]; then
  ok "SQL generation matches contract: $SQL"
else
  fail "SQL generation: got=$SQL want=$EXPECTED"
fi

# ============================================================
log "== 4. TS browser-side mirror (same semantics) =="
TS_OUT="$(cd "$REGISTER_DIR/demo/rule-exec" && "$NODE" --test ts/mini.test.ts 2>&1)"
if echo "$TS_OUT" | grep -q "^# fail 0"; then
  ok "TS mirror tests all passed"
else
  fail "TS mirror: $TS_OUT"
fi

# ============================================================
log "== 5. Real MySQL (optional) =="
# MYSQL_DSN is Go driver DSN (go-sql-driver/mysql),
# MYSQL_CLI_ARGS is mysql CLI args (e.g. "--socket=/tmp/aic-mysql.sock -u root"), optional.
if [ -n "${MYSQL_DSN:-}" ]; then
  if [ -n "${MYSQL_CLI_ARGS:-}" ] && command -v mysql >/dev/null 2>&1; then
    if mysql $MYSQL_CLI_ARGS -N -e "SELECT 1" >/dev/null 2>&1; then
      ok "MySQL CLI connectivity check passed"
    else
      fail "MySQL CLI connectivity check failed (MYSQL_CLI_ARGS=$MYSQL_CLI_ARGS)"
    fi
  else
    note "MYSQL_CLI_ARGS not set or mysql CLI not installed, skipping CLI check (Go driver test still runs)"
  fi
  LIVE_OUT="$(cd "$REGISTER_DIR" && MYSQL_DSN="$MYSQL_DSN" "$GO" test ./ruleexec/ -run TestMySQLLive -v 2>&1)"
  if echo "$LIVE_OUT" | grep -q -- "--- PASS: TestMySQLLive"; then
    ok "Real DB end-to-end query assertion passed (TestMySQLLive)"
  else
    fail "Real DB test: $LIVE_OUT"
  fi
else
  note "Skipped: MYSQL_DSN not set (default: SQL generation level verification only)"
  ok "SQL generation level verification (no database required)"
fi

# ============================================================
log "== 6. HTTP gateway full chain (rule → phase-two plugin → SQL → database) =="
CHAIN_OUT="$(cd "$REGISTER_DIR" && "$GO" test ./ruleexec/ -run TestHTTPGatewayChain -v 2>&1)"
if echo "$CHAIN_OUT" | grep -q -- "--- PASS: TestHTTPGatewayChain"; then
  ok "Gateway chain test passed (identity/conditions/SQL generation, no database required)"
else
  fail "Gateway chain test: $CHAIN_OUT"
fi
if [ -n "${MYSQL_DSN:-}" ]; then
  GW_LIVE_OUT="$(cd "$REGISTER_DIR" && MYSQL_DSN="$MYSQL_DSN" "$GO" test ./ruleexec/ -run TestHTTPGatewayE2ELive -v 2>&1)"
  if echo "$GW_LIVE_OUT" | grep -q -- "--- PASS: TestHTTPGatewayE2ELive"; then
    ok "Real DB full chain e2e passed (zhangsan/lisi columns + tenant isolation)"
  else
    fail "Real DB full chain e2e: $GW_LIVE_OUT"
  fi
else
  note "Skipped real DB full chain e2e (MYSQL_DSN not set)"
fi

# ============================================================
log "== 7. Real gateway full e2e (varwof client issues AIC + rule_schemes + mysql-api) =="
# Prerequisite: pki-core init-full PKI + pki-client issued AIC (see §8 docs)
E2E_AIC_CERT="${E2E_AIC_CERT:-/tmp/aic-e2e-pki/certs/zhangsan-agent.pem}"
E2E_AIC_KEY="${E2E_AIC_KEY:-/tmp/aic-e2e-pki/certs/zhangsan-agent.key}"
if [ -n "${MYSQL_DSN:-}" ] && [ -f "$E2E_AIC_CERT" ] && [ -f "$E2E_AIC_KEY" ]; then
  REAL_OUT="$(cd "$WORKSPACE_ROOT" && MYSQL_DSN="$MYSQL_DSN" E2E_AIC_CERT="$E2E_AIC_CERT" E2E_AIC_KEY="$E2E_AIC_KEY" "$GO" test ./gateway/http/ -run TestRealGatewayE2E -v 2>&1)"
  if echo "$REAL_OUT" | grep -q -- "--- PASS: TestRealGatewayE2E"; then
    ok "Real gateway full e2e passed (AIC→gateway→mysql-api)"
  else
    fail "Real gateway full e2e: $REAL_OUT"
  fi
else
  note "Skipped real gateway full e2e (requires MYSQL_DSN + pki-core init-full + pki-client AIC certs)"
fi

# ============================================================
log "== 8. Real gateway permission matrix (3 users × 4 methods, aic-matrix-demo style) =="
MATRIX_DIR="${E2E_MATRIX_DIR:-/tmp/aic-e2e-pki/certs}"
if [ -n "${MYSQL_DSN:-}" ] && [ -f "$MATRIX_DIR/zhangsan-agent.pem" ]; then
  MX_OUT="$(cd "$WORKSPACE_ROOT" && MYSQL_DSN="$MYSQL_DSN" E2E_MATRIX_DIR="$MATRIX_DIR" "$GO" test ./gateway/http/ -run TestRealGatewayMatrixE2E -v 2>&1)"
  if echo "$MX_OUT" | grep -q -- "--- PASS: TestRealGatewayMatrixE2E"; then
    ok "Real gateway permission matrix passed (zhangsan/lisi/wangwu × GET/POST/PUT/DELETE)"
  else
    fail "Real gateway permission matrix: $MX_OUT"
  fi
else
  note "Skipped real gateway permission matrix (requires MYSQL_DSN + setup-e2e-pki.sh AIC certs)"
fi

# ============================================================
log "== 9. Downgrade test (principal revocation + re-issue, same key, permission shrink → old AIC permissions invalidated) =="
  DG_OUT="$(cd "$WORKSPACE_ROOT" && "$GO" test ./gateway-core/ -run TestPrincipalDowngradeRevokesAgentPermissions -v 2>&1)"
if echo "$DG_OUT" | grep -q -- "--- PASS: TestPrincipalDowngradeRevokesAgentPermissions"; then
  ok "Downgrade test passed (C2 missing one permission → old AIC INSERT disappears from EffectiveCaps)"
else
  fail "Downgrade test: $DG_OUT"
fi

# ============================================================
log ""
if [ "$FAIL" -eq 0 ]; then
  log "== All passed: PASS=$PASS FAIL=$FAIL =="
  exit 0
else
  log "== Failures detected: PASS=$PASS FAIL=$FAIL =="
  for f in "${FAILED_LIST[@]}"; do
    printf '  - %s\n' "$f"
  done
  exit 1
fi

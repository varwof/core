#!/usr/bin/env bash
#
# aic-full-walkthrough.sh — Full feature walkthrough (repeatable verification script)
#
# Covers two environments with layered functional verification:
#   1. Smoke instance (default /tmp/pki-superadmin-smoke) — pki-core self-test
#      - Certificate full lifecycle: issue / list / renew / revoke / batch / re-sign
#      - AIC full chain: aic issue / cert show / revoke-by-principal
#      - TSA: RFC 3161 timestamp issuance and verification
#      - Management API: config / audit / trust / tsa-cert
#   2. Production instance (default localhost:4433 + gateway localhost:9443) — AIC→gateway→backend
#      - AIC permission matrix: 4 users × 4 operations = 16 assertions
#
# Usage:
#   scripts/aic-full-walkthrough.sh [--smoke-dir DIR] [--pki-client PATH]
#
# Configurable (env vars):
#   SMOKE_DIR       smoke instance directory (default /tmp/pki-superadmin-smoke)
#   SMOKE_ADDR      smoke mTLS address (default https://sa.smoke.varwof.test:9447)
#   PKI_CLIENT      built pki-client binary (default /tmp/pki-client-bin)
#   WORKDIR         output directory (default /tmp/aic-walkthrough)
#   Production matrix params follow scripts/aic-agent-matrix.sh env vars
#
# Exit code: 0 = all pass; non-zero = failures
#
set -uo pipefail

SMOKE_DIR="${SMOKE_DIR:-/tmp/pki-superadmin-smoke}"
SMOKE_ADDR="${SMOKE_ADDR:-https://sa.smoke.varwof.test:9447}"
PKI_CLIENT="${PKI_CLIENT:-/tmp/pki-client-bin}"
WORKDIR="${WORKDIR:-/tmp/aic-walkthrough}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$WORKDIR"
PASS=0
FAIL=0
FAILED_LIST=()

log()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '\033[1;31m  [FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED_LIST+=("$*"); }
note() { printf '\033[1;36m%s\033[0m\n' "$*"; }

# ---------- Environment check ----------
[ -x "$PKI_CLIENT" ] || { echo "pki-client not found: $PKI_CLIENT"; exit 2; }
[ -f "$SMOKE_DIR/pki.json" ] || { echo "smoke dir not found: $SMOKE_DIR"; exit 2; }

CERT="$SMOKE_DIR/sa.pem"
KEY="$SMOKE_DIR/sa.key"
ROOTCA="$SMOKE_DIR/tls/certs/ca.pem"
[ -f "$CERT" ] && [ -f "$KEY" ] && [ -f "$ROOTCA" ] || { echo "smoke certs missing"; exit 2; }

SMOKE_CA="${SMOKE_CA:-SATest People CA}"

# pki-client config file
cat > "$WORKDIR/pki-client.json" << EOF
{
  "server": "$SMOKE_ADDR",
  "ca_cert": "$ROOTCA",
  "client_cert": "$CERT",
  "client_key": "$KEY"
}
EOF
chmod 600 "$WORKDIR/pki-client.json"

curlargs=(--cert "$CERT" --key "$KEY" --cacert "$ROOTCA")

# ============================================================
log "== 1. pki-core selfcheck (DB/TSA/CRL/healthz/issue/revoke/CRL generation) =="
OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" selfcheck --ca "$SMOKE_CA" 2>&1)"
if echo "$OUT" | grep -q "ALL PASS"; then ok "selfcheck all passed"; else fail "selfcheck: $OUT"; fi

# ============================================================
log "== 2. Certificate full lifecycle =="

note "--- 2a. issue certificate ---"
ISSUE_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" issue \
  --cn "walk-$(date +%H%M%S)" --ca "$SMOKE_CA" --profile tls-client --validity 30 \
  --out "$WORKDIR" 2>&1)"
if echo "$ISSUE_OUT" | grep -q "Serial:"; then ok "issue certificate"; else fail "issue: $ISSUE_OUT"; fi
SER="$(echo "$ISSUE_OUT" | grep 'Serial:' | awk '{print $2}' | tr -d ' ')"

note "--- 2b. list certificates ---"
LIST_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" list --ca "$SMOKE_CA" --status V 2>&1)"
if echo "$LIST_OUT" | grep -qE "^[0-9A-F]{40}"; then ok "list with full serial"; else fail "list: no full serial"; fi

note "--- 2c. renew certificate ---"
RENEW_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" renew --ca "$SMOKE_CA" --serial "$SER" --out "$WORKDIR" 2>&1)"
if echo "$RENEW_OUT" | grep -q "new serial"; then ok "renew certificate"; else fail "renew: $RENEW_OUT"; fi

note "--- 2d. batch issue ---"
cat > "$WORKDIR/batch.json" << EOF
[
  {"cn":"batch-walk-a","ca":"$SMOKE_CA","profile":"tls-client","validity":30},
  {"cn":"batch-walk-b","ca":"$SMOKE_CA","profile":"tls-client","validity":30}
]
EOF
BATCH_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" batch --requests "$WORKDIR/batch.json" 2>&1)"
if echo "$BATCH_OUT" | grep -q '"status": "ok"'; then ok "batch issue"; else fail "batch: $BATCH_OUT"; fi

note "--- 2e. re-sign (full serial) ---"
RESIGN_SER="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" list --ca "$SMOKE_CA" --cn "batch-walk-a" 2>/dev/null | awk 'NR==2{print $1}')"
if [ -n "$RESIGN_SER" ]; then
  RESIGN_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" re-sign --ca "$SMOKE_CA" --serial "$RESIGN_SER" --validity 45 --out "$WORKDIR" 2>&1)"
  if echo "$RESIGN_OUT" | grep -q "BEGIN CERTIFICATE"; then ok "re-sign certificate"; else fail "re-sign: $RESIGN_OUT"; fi
else
  fail "re-sign: could not get batch certificate serial"
fi

note "--- 2f. revoke + CRL generation ---"
REVOKE_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" revoke --ca "$SMOKE_CA" --serial "$RESIGN_SER" --reason superseded --crl 2>&1)"
if echo "$REVOKE_OUT" | grep -q "Revoked:"; then ok "revoke + CRL"; else fail "revoke: $REVOKE_OUT"; fi

# ============================================================
log "== 3. AIC full chain =="

note "--- 3a. issue user certificate (AIC base) ---"
USER_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" issue \
  --cn "walk-user" --ca "$SMOKE_CA" --profile tls-client --ou "db:reader" --validity 60 \
  --out "$WORKDIR" 2>&1)"
if echo "$USER_OUT" | grep -q "Serial:"; then ok "user certificate issued"; else fail "user certificate: $USER_OUT"; fi
USER_CERT="$(ls -t "$WORKDIR"/*.pem 2>/dev/null | grep -vE -- "-key|agent|user" | head -1)"
[ -n "$USER_CERT" ] || USER_CERT="$(echo "$USER_OUT" | grep 'Cert:' | awk '{print $2}' | tr -d ' ')"
USER_KEY="${USER_CERT%.pem}-key.pem"

note "--- 3b. aic issue ---"
AIC_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" aic issue \
  --user-cert "$USER_CERT" --user-key "$USER_KEY" --agent "walk-agent" \
  --caps "std/database-v1:query:SELECT std/database-v1:GET:*" --ca "$SMOKE_CA" --ou "db:reader" \
  --out "$WORKDIR" 2>&1)"
if echo "$AIC_OUT" | grep -q "Serial:"; then ok "AIC issued"; else fail "AIC issue: $AIC_OUT"; fi

note "--- 3c. cert show (decode AIC extension) ---"
SHOW_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" cert show --cert "$WORKDIR/walk-agent.pem" 2>&1)"
if echo "$SHOW_OUT" | grep -q "AIC Extension" && echo "$SHOW_OUT" | grep -q "agent_id=walk-agent"; then
  ok "AIC extension decoded (agent_id/caps)"
else
  fail "cert show: $SHOW_OUT"
fi

note "--- 3d. revoke-by-principal ---"
PU="$(echo "$SHOW_OUT" | grep 'PrincipalUid:' | awk '{print $2}')"
REV_PR_OUT="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" revoke-by-principal --principal-uid "$PU" 2>&1)"
if echo "$REV_PR_OUT" | grep -qE "Revoked [0-9]+ cert"; then ok "revoke-by-principal AIC revoked"; else fail "revoke-by-principal: $REV_PR_OUT"; fi

note "--- 3e. verify AIC revoked ---"
AIC_SERIAL="$(openssl x509 -in "$WORKDIR/walk-agent.pem" -noout -serial 2>/dev/null | sed 's/serial=//')"
AIC_STATUS="$("$PKI_CLIENT" "$WORKDIR/pki-client.json" list --ca "$SMOKE_CA" --status R --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
target='$AIC_SERIAL'.lower()
for c in d:
    if c.get('serial_number','').lower()==target:
        print(c.get('status','')); break
")"
[ "$AIC_STATUS" = "R" ] && ok "AIC certificate status=R (revoked)" || fail "AIC status expected R, got=$AIC_STATUS"

# ============================================================
log "== 4. TSA (RFC 3161 timestamp) =="
printf 'aic-walkthrough tsa test %s\n' "$(date +%s)" > "$WORKDIR/msg.txt"
if openssl ts -query -data "$WORKDIR/msg.txt" -sha256 -cert -out "$WORKDIR/tsq" 2>/dev/null; then
  curl -sk "$SMOKE_ADDR/tsa" -X POST --data-binary @"$WORKDIR/tsq" \
    "${curlargs[@]}" -o "$WORKDIR/tsr" -w '%{http_code}' > "$WORKDIR/tsa-code"
  if [ "$(cat "$WORKDIR/tsa-code")" = "200" ]; then
    if openssl ts -reply -in "$WORKDIR/tsr" -text 2>/dev/null | grep -q "Status: Granted"; then
      ok "TSA timestamp Granted"
    else
      fail "TSA response not Granted"
    fi
  else
    fail "TSA HTTP=$(cat "$WORKDIR/tsa-code")"
  fi
else
  fail "openssl ts -query not available"
fi

# ============================================================
log "== 5. Management API =="

note "--- 5a. admin config ---"
code="$(curl -sk "$SMOKE_ADDR/api/v1/admin/config" "${curlargs[@]}" -o /dev/null -w '%{http_code}')"
[ "$code" = "200" ] && ok "admin config read" || fail "admin config: HTTP $code"

note "--- 5b. audit log ---"
code="$(curl -sk "$SMOKE_ADDR/api/v1/audit" "${curlargs[@]}" -o /dev/null -w '%{http_code}')"
[ "$code" = "200" ] && ok "audit log" || fail "audit: HTTP $code"

note "--- 5c. trust anchors ---"
code="$(curl -sk "$SMOKE_ADDR/api/v1/trust" "${curlargs[@]}" -o /dev/null -w '%{http_code}')"
[ "$code" = "200" ] && ok "trust list" || fail "trust: HTTP $code"

note "--- 5d. tsa cert management ---"
code="$(curl -sk "$SMOKE_ADDR/api/v1/tsa/cert" "${curlargs[@]}" -o /dev/null -w '%{http_code}')"
[ "$code" = "200" ] && ok "tsa cert query" || fail "tsa cert: HTTP $code"

note "--- 5e. RBAC deny (anonymous access to management API should be rejected) ---"
code="$(curl -sk "$SMOKE_ADDR/api/v1/admin/config" -o /dev/null -w '%{http_code}' 2>/dev/null)"
# Under mTLS, anonymous requests fail handshake returning 000 (connection refused), equivalent to denied
[ "$code" = "401" ] || [ "$code" = "403" ] || [ "$code" = "000" ] \
  && ok "anonymous access denied (code=$code）" || fail "anonymous access should be denied, got=$code"

# ============================================================
log "== 6. Production AIC→gateway→backend permission matrix =="
if [ -x "$ROOT/scripts/aic-agent-matrix.sh" ]; then
  if "$ROOT/scripts/aic-agent-matrix.sh" > "$WORKDIR/matrix.log" 2>&1; then
    ok "AIC permission matrix (16 assertions passed)"
  else
    fail "AIC permission matrix has failures (see $WORKDIR/matrix.log)"
  fi
else
  note "skipped (aic-agent-matrix.sh not present)"
fi

# ============================================================
echo
log "=== Summary ==="
printf '  PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\n\033[1;31mFailed items:\033[0m\n'
  for f in "${FAILED_LIST[@]}"; do printf '  - %s\n' "$f"; done
  exit 1
fi
echo "  All passed"
exit 0

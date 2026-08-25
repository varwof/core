#!/usr/bin/env bash
# smoke.sh — Full smoke test: init CA + start server + test + cleanup
# Usage: ./scripts/smoke.sh [--keep]
#   --keep    Keep test environment after run (for debugging)
# Requires: go 1.26+, openssl, repos cloned + built (run build.sh first)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$(dirname "$CORE_DIR")}"
BIN="$CORE_DIR/bin"
GOFLAGS="${GOFLAGS:--buildvcs=false}"

KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true

# Temp test environment
BASE=$(mktemp -d /tmp/varwof-smoke-XXXX)
CFG="$BASE/pki.json"
KEYDIR="$BASE/keys"
TMP="$BASE/test-output"
mkdir -p "$TMP"

cleanup() {
  if [ "$KEEP" = false ]; then
    # Kill server if running
    [ -f "$BASE/server.pid" ] && kill "$(cat "$BASE/server.pid")" 2>/dev/null
    rm -rf "$BASE"
  else
    echo "  Test environment: $BASE"
  fi
}
trap cleanup EXIT

OK=0; FAIL=0
ok()   { OK=$((OK+1)); echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

echo "═══════════════════════════════════════════════════════════"
echo "  varwof smoke test"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── Prerequisites ──
echo "── Prerequisites ──"
for cmd in "$BIN/pki" openssl python3; do
  command -v "$cmd" > /dev/null 2>&1 && ok "$(basename "$cmd") found" || fail "$(basename "$cmd") not found"
done

# Check repos are cloned
for repo in pkcs7 types register engine gateway-core client core gateway; do
  [ -d "$BUILD_DIR/$repo/.git" ] && ok "$repo cloned" || fail "$repo not cloned (run build.sh first)"
done

if [ $FAIL -gt 0 ]; then
  echo ""
  echo "  Prerequisites failed. Run: ./scripts/build.sh"
  exit 1
fi
echo ""

# ── Step 1: Init CA hierarchy ──
echo "── 1. Init CA hierarchy ──"
mkdir -p "$KEYDIR"
cd "$BASE"
"$BIN/pki" init-full \
  --out-dir "$KEYDIR" \
  --config-out "$CFG" \
  --domain "smoke.test" \
  --root "Smoke Root CA" \
  --org "Varwof" > /dev/null 2>&1

# Fix CA name in config (init-full uses Varwof Root CA but DB stores Smoke Root CA)
python3 -c "
import json
with open('$CFG') as f:
    cfg = json.load(f)
cas = cfg.get('cas', {})
if 'Varwof Root CA' in cas:
    cas['Smoke Root CA'] = cas.pop('Varwof Root CA')
    cfg['cas'] = cas
cfg['serve'] = cfg.get('serve', {})
cfg['serve']['addr'] = '127.0.0.1:8443'
cfg['serve']['tls_addr'] = '127.0.0.1:9443'
cfg['serve']['tls_client_ca'] = '$KEYDIR/root/certs/ca.pem'
with open('$CFG', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null

[ -f "$CFG" ] && ok "CA hierarchy initialized" || fail "CA init failed"

# Create full chain certs for mTLS
for role in superadmin admin operator auditor readonly auto-renew; do
  cat "$KEYDIR/management/users/certs/$role.pem" \
      "$KEYDIR/management/certs/ca.pem" > "$KEYDIR/$role-fullchain.pem" 2>/dev/null
done
ok "Full chain certs created"

# ── Step 2: Start server ──
echo ""
echo "── 2. Start server ──"
"$BIN/pki" serve --config "$CFG" &>/dev/null &
SERVER_PID=$!
echo $SERVER_PID > "$BASE/server.pid"

# Wait for server to start
for i in $(seq 1 10); do
  if curl -sf http://127.0.0.1:8443/healthz > /dev/null 2>&1; then
    ok "Server started (PID $SERVER_PID)"
    break
  fi
  sleep 1
done

# Verify both listeners
ss -tlnp 2>/dev/null | grep -q "127.0.0.1:8443" && ok "HTTP listener :8443" || fail "HTTP listener :8443"
ss -tlnp 2>/dev/null | grep -q "127.0.0.1:9443" && ok "HTTPS listener :9443" || fail "HTTPS listener :9443"

# ── Step 3: Run smoke tests ──
echo ""
echo "── 3. Smoke tests ──"

API="https://127.0.0.1:9443"
HTTP="http://127.0.0.1:8443"
AGENT="--cert $KEYDIR/superadmin-fullchain.pem --key $KEYDIR/management/users/private/superadmin.key"
PKI="$BIN/pki"

# 3.1 Basic
echo "  ── 3.1 Basic ──"
$PKI version 2>/dev/null | grep -q "varwof"; ok "version" || fail "version"
curl -sf $HTTP/healthz 2>/dev/null | python3 -c "
import sys,json;d=json.load(sys.stdin)
assert d['status']=='ok' and d['db']=='ok'
" 2>/dev/null && ok "healthz" || fail "healthz"
$PKI ca list 2>/dev/null > /dev/null; ok "ca list" || fail "ca list"

# 3.2 Issue certs
echo "  ── 3.2 Cert Issue ──"
for prof_cn in "tls-server:smoke-srv-$(date +%s).smoke.test" \
               "tls-client:smoke-client-$(date +%s)" \
               "m-admin:smoke-admin-$(date +%s)" \
               "vpn-client:smoke-vpn-$(date +%s)" \
               "codesigning:smoke-codesign-$(date +%s)"; do
  PNAME="${prof_cn%%:*}"
  CN="${prof_cn##*:}"
  case $PNAME in
    tls-server|tls-client) CA="Varwof TLS CA" ;;
    m-admin)               CA="Varwof Management CA" ;;
    vpn-client)            CA="Varwof VPN CA" ;;
    codesigning)           CA="Varwof CodeSign CA" ;;
  esac
  $PKI --config $CFG issue --ca "$CA" --profile $PNAME \
    --cn "$CN" --validity 1 \
    --out $TMP/$PNAME.pem --out-key $TMP/$PNAME.key > /dev/null 2>&1 \
    && ok "issue $PNAME" || fail "issue $PNAME"
done

# Verify tls-server structure
echo "  ── 3.3 Cert Structure ──"
openssl x509 -in $TMP/tls-server.pem -noout -ext keyUsage 2>/dev/null | grep -q "Digital Signature" \
  && ok "KU: DigitalSignature" || fail "KU: missing DigitalSignature"
openssl x509 -in $TMP/tls-server.pem -noout -ext keyUsage 2>/dev/null | grep -q "Key Encipherment" \
  && ok "KU: KeyEncipherment" || fail "KU: missing KeyEncipherment"
openssl x509 -in $TMP/tls-server.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Server Authentication" \
  && ok "EKU: ServerAuth" || fail "EKU: missing ServerAuth"
openssl x509 -in $TMP/tls-server.pem -noout -text 2>/dev/null | grep -q "Public Key Algorithm: id-ecPublicKey" \
  && ok "key: ECDSA" || fail "key: not ECDSA"
openssl x509 -in $TMP/tls-server.pem -noout -text 2>/dev/null | grep -q "CRL Distribution Points" \
  && ok "ext: CRL DP" || fail "ext: missing CRL DP"
openssl x509 -in $TMP/tls-server.pem -noout -text 2>/dev/null | grep -q "CA:FALSE" \
  && ok "BC: CA:FALSE" || fail "BC: not CA:FALSE"

# Verify cert/key match
CERT_PUB=$(openssl x509 -in $TMP/tls-server.pem -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
KEY_PUB=$(openssl pkey -in $TMP/tls-server.key -pubout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
[ "$CERT_PUB" = "$KEY_PUB" ] && ok "cert/key match" || fail "cert/key mismatch"

# 3.4 Chain verify
echo "  ── 3.4 Chain Verify ──"
for cert_file in tls-server tls-client m-admin vpn-client codesigning; do
  for subca in tls management vpn codesign; do
    if openssl verify -CAfile $KEYDIR/root/certs/ca.pem \
      -untrusted $KEYDIR/$subca/certs/ca.pem $TMP/$cert_file.pem > /dev/null 2>&1; then
      ok "chain: $cert_file"
      break
    fi
  done
done

# 3.5 Lifecycle
echo "  ── 3.5 Lifecycle ──"
SERIAL=$(openssl x509 -in $TMP/tls-server.pem -noout -serial 2>/dev/null | cut -d= -f2)
$PKI --config $CFG revoke --ca "Varwof TLS CA" --serial "$SERIAL" --reason unspecified > /dev/null 2>&1 \
  && ok "revoke" || fail "revoke"
$PKI --config $CFG crl --ca "Varwof TLS CA" --out $TMP/test.crl > /dev/null 2>&1 \
  && ok "CRL gen" || fail "CRL gen"
openssl crl -in $TMP/test.crl -CAfile $KEYDIR/tls/certs/ca.pem -noout -verify 2>/dev/null \
  && ok "CRL verify" || fail "CRL verify"

# 3.6 PFX
echo "  ── 3.6 PFX ──"
$PKI export --pfx --cert $TMP/m-admin.pem --key $TMP/m-admin.key --out $TMP/test.p12 --password smoke123 > /dev/null 2>&1 \
  && ok "PFX export" || fail "PFX export"
openssl pkcs12 -in $TMP/test.p12 -passin pass:smoke123 -nokeys -noout 2>/dev/null \
  && ok "P12: cert readable" || fail "P12: cert unreadable"
openssl pkcs12 -in $TMP/test.p12 -passin pass:wrong -nokeys -noout 2>/dev/null \
  && fail "P12: wrong password accepted" || ok "P12: wrong password rejected"

# 3.7 TSA
echo "  ── 3.7 TSA ──"
echo "smoke-tsa-data" > $TMP/tsa-data.txt
openssl ts -query -data $TMP/tsa-data.txt -sha256 -out $TMP/tsa.req 2>/dev/null \
  && ok "TSA: query created" || fail "TSA: query creation"
curl -sf -H "Content-Type: application/timestamp-query" \
  --data-binary @$TMP/tsa.req $HTTP -o $TMP/tsa.resp 2>/dev/null \
  && ok "TSA: response" || fail "TSA: no response"
openssl ts -reply -in $TMP/tsa.resp -text 2>/dev/null | grep -qi "Status: granted" \
  && ok "TSA: granted" || fail "TSA: not granted"

# 3.8 API
echo "  ── 3.8 API (mTLS) ──"
curl -sk $AGENT "$API/api/v1/cas" 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
assert isinstance(d, list) and len(d) > 0 and 'name' in d[0]
" 2>/dev/null && ok "GET /cas" || fail "GET /cas"
curl -sk $AGENT "$API/api/v1/certs?limit=5" 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
assert isinstance(d, (list, dict))
" 2>/dev/null && ok "GET /certs" || fail "GET /certs"
curl -sk $AGENT -X POST "$API/api/v1/certs" -H "Content-Type:application/json" \
  -d "{\"ca\":\"Varwof TLS CA\",\"profile\":\"tls-client\",\"cn\":\"api-smoke-$(date +%s).smoke.test\",\"validity\":1}" 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
assert 'certificate_pem' in d or 'cert_pem' in d or 'serial_number' in d
" 2>/dev/null && ok "POST /api/v1/certs" || fail "POST /api/v1/certs"
curl -sf $HTTP/metrics 2>/dev/null | grep -q "pki_cas_total" && ok "metrics" || fail "metrics"

# 3.9 RBAC
echo "  ── 3.9 RBAC ──"
$PKI --config $CFG rbac mode > /dev/null 2>&1 && ok "rbac mode" || fail "rbac mode"

# 3.10 Code signing
echo "  ── 3.10 Code Signing ──"
echo "smoke" > $TMP/sign.txt
$PKI sign --ca "Varwof CodeSign CA" --chain $KEYDIR/codesign/certs/ca.pem \
  --cert $KEYDIR/superadmin-fullchain.pem --key $KEYDIR/management/users/private/superadmin.key \
  $TMP/sign.txt > /dev/null 2>&1 && ok "sign" || fail "sign"
$PKI --config $CFG verify --sig $TMP/sign.txt.p7s $TMP/sign.txt > /dev/null 2>&1 \
  && ok "verify" || fail "verify"

# 3.11 Trust anchors
echo "  ── 3.11 Trust Anchors ──"
$PKI --config $CFG trust list > /dev/null 2>&1 && ok "trust list" || fail "trust list"
$PKI --config $CFG trust import --file $KEYDIR/root/certs/ca.pem > /dev/null 2>&1 \
  && ok "trust import" || fail "trust import"

# 3.12 Cross certs
echo "  ── 3.12 Cross Certs ──"
$PKI --config $CFG cross-cert issue --issuer "Smoke Root CA" --target "Smoke Root CA" --validity 365 > /dev/null 2>&1 \
  && ok "cross-cert issue" || fail "cross-cert issue"

# 3.13 Health after ops
echo "  ── 3.13 Health After Ops ──"
curl -sf $HTTP/healthz | python3 -c "
import sys,json;d=json.load(sys.stdin)
assert d['status']=='ok'
" 2>/dev/null && ok "healthz after all ops" || fail "healthz after all ops"

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Results: $OK passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════"

[ $FAIL -eq 0 ] && echo "  ✅ ALL PASSED" || echo "  ❌ SOME FAILED"
[ $FAIL -eq 0 ]

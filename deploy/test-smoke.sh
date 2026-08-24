#!/usr/bin/env bash
# pki 部署冒烟测试
set -euo pipefail

PASS=0; FAIL=0
TMPDIR=$(mktemp -d /tmp/pki-smoke-XXXXX)
TS=$(date +%s)

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
run()  { local d=$1; shift; if "$@" &>/tmp/pki-smoke-err; then ok "$d"; else local r=$?; echo "  ✗ $d (rc=$r)"; cat /tmp/pki-smoke-err | sed 's/^/    /'; FAIL=$((FAIL+1)); fi }

CLEANUP_PID=""
cleanup() { rm -rf "$TMPDIR" /tmp/pki-smoke-err; [ -n "$CLEANUP_PID" ] && sudo kill "$CLEANUP_PID" 2>/dev/null || true; }
trap cleanup EXIT

# basic
echo "=== pki deployment smoke test ==="
varwof version
echo ""
run "version"   varwof version
run "help"      varwof help
run "ca list"   varwof ca list

# CA info
run "ca info root"     varwof ca info --name root
run "ca info issuing"  varwof ca info --name issuing
run "ca info codesign" varwof ca info --name codesign
run "ca info tsa"      varwof ca info --name tsa

# issue test certs (need sudo to read CA private keys)
CERT_DIR="$TMPDIR/certs"
mkdir -p "$CERT_DIR"

run "issue tls-server"      sudo varwof issue --ca issuing --profile tls-server --cn "smoke-a-$TS.varwof.com" --validity 1 --out "$CERT_DIR/a.pem" --out-key "$CERT_DIR/a.key"
run "issue codesign"        sudo varwof issue --ca codesign --profile codesigning --cn "SmokeCode-$TS" --validity 1 --out "$CERT_DIR/code.pem" --out-key "$CERT_DIR/code.key"
run "issue tls-client"      sudo varwof issue --ca issuing --profile tls-client --cn "smoke-client-$TS.varwof.com" --validity 1 --out "$CERT_DIR/client.pem" --out-key "$CERT_DIR/client.key"
sudo chown varwof: "$CERT_DIR"/*.pem "$CERT_DIR"/*.key
run "check client cert"     test -f "$CERT_DIR/client.pem"

# PKCS#7 sign & verify
CODESIGN_CA_CERT=/etc/varwof/core/codesign/certs/ca.pem
echo "hello pki" > "$TMPDIR/file.txt"
run "sign detached"         varwof sign --ca codesign --chain "$CODESIGN_CA_CERT" --cert "$CERT_DIR/code.pem" --key "$CERT_DIR/code.key" "$TMPDIR/file.txt"
run "check sig file"        test -f "$TMPDIR/file.txt.p7s"
run "verify detached"       varwof verify --sig "$TMPDIR/file.txt.p7s" "$TMPDIR/file.txt"

# embedded sign (writes back to same file)
cp "$TMPDIR/file.txt" "$TMPDIR/file2.txt"
run "sign embedded"         varwof sign --embed --ca codesign --chain "$CODESIGN_CA_CERT" --cert "$CERT_DIR/code.pem" --key "$CERT_DIR/code.key" "$TMPDIR/file2.txt"
run "verify embedded"       varwof verify --embed "$TMPDIR/file2.txt"

# export PFX
run "export pfx"            varwof export --pfx --cert "$CERT_DIR/a.pem" --key "$CERT_DIR/a.key" --out "$TMPDIR/a.p12" --password smoke123
run "check pfx file"        test -f "$TMPDIR/a.p12"

# key encrypt / decrypt
run "key encrypt"           varwof key encrypt --in "$CERT_DIR/a.key" --out "$TMPDIR/a-enc.key" --password encpass
run "key decrypt"           varwof key decrypt --in "$TMPDIR/a-enc.key" --out "$TMPDIR/a-dec.key" --password encpass
run "decrypted key matches" diff "$CERT_DIR/a.key" "$TMPDIR/a-dec.key"

# CRL
run "crl issuing"           sudo varwof crl --ca issuing --out "$TMPDIR/issuing.crl"
run "check crl file"        test -f "$TMPDIR/issuing.crl"

# revoke + crl (before openssl verify so CRL has revocations)
SERIAL_A=$(openssl x509 -in "$CERT_DIR/a.pem" -noout -serial 2>/dev/null | cut -d= -f2)
run "revoke cert"           varwof revoke --ca issuing --serial "$SERIAL_A" --reason keyCompromise
run "crl after revoke"      sudo varwof crl --ca issuing --out "$TMPDIR/issuing2.crl"

# renew
mkdir -p "$TMPDIR/renewed"
SERIAL_C=$(openssl x509 -in "$CERT_DIR/client.pem" -noout -serial 2>/dev/null | cut -d= -f2)
run "renew cert"            sudo varwof renew --ca issuing --serial "$SERIAL_C" --validity 2 --out-dir "$TMPDIR/renewed" --out-name "renewed"
sudo chown -R varwof: "$TMPDIR/renewed"
run "check renewed cert"    test -f "$TMPDIR/renewed/renewed.pem"
run "check renewed key"     test -f "$TMPDIR/renewed/renewed.key"

# --- OpenSSL verification ---
ROOT_CA=/etc/varwof/core/root/certs/ca.pem
ISSUING_CA=/etc/varwof/core/issuing/certs/ca.pem
CODESIGN_CA=/etc/varwof/core/codesign/certs/ca.pem

cat "$ROOT_CA" "$ISSUING_CA" > "$TMPDIR/chain-issuing.pem"
cat "$ROOT_CA" "$CODESIGN_CA" > "$TMPDIR/chain-codesign.pem"

run "openssl verify a.pem"          openssl verify -CAfile "$TMPDIR/chain-issuing.pem" "$CERT_DIR/a.pem"
run "openssl verify code.pem"       openssl verify -CAfile "$TMPDIR/chain-codesign.pem" "$CERT_DIR/code.pem"
run "openssl verify client.pem"     openssl verify -CAfile "$TMPDIR/chain-issuing.pem" "$CERT_DIR/client.pem"
run "openssl verify renewed.pem"    openssl verify -CAfile "$TMPDIR/chain-issuing.pem" "$TMPDIR/renewed/renewed.pem"

run "openssl x509 subject"          openssl x509 -in "$CERT_DIR/a.pem" -noout -subject
run "openssl x509 dates"            openssl x509 -in "$CERT_DIR/a.pem" -noout -dates
run "openssl x509 san"              openssl x509 -in "$CERT_DIR/a.pem" -noout -ext subjectAltName

# verify CRL with openssl
run "openssl crl verify"            openssl crl -in "$TMPDIR/issuing.crl" -CAfile "$ISSUING_CA" -noout
run "openssl crl revoked count"     test "$(openssl crl -in "$TMPDIR/issuing2.crl" -text -noout 2>/dev/null | grep -c 'Serial Number')" -ge 1

# --- OCSP / TSA (start varwof serve, test, stop) ---
sudo varwof serve --config /etc/varwof/core/pki.json &>/tmp/pki-smoke-server.log &
PKI_PID=$!; CLEANUP_PID=$PKI_PID
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 4430 2>/dev/null; then break; fi
  sleep 1
done

if kill -0 $PKI_PID 2>/dev/null; then
  # OCSP query over HTTP
  run "ocsp request"                sh -c "openssl ocsp -issuer \"$ISSUING_CA\" -cert \"$CERT_DIR/a.pem\" -url http://127.0.0.1:4430/ocsp -timeout 5 2>/dev/null | grep -q 'revoked'"

  # TSA (RFC 3161) over HTTP
  echo "tsa test data $TS" > "$TMPDIR/tsa-data.txt"
  run "tsa query"                   openssl ts -query -data "$TMPDIR/tsa-data.txt" -no_nonce -out "$TMPDIR/tsa-req.tsq"
  run "tsa response"                curl -sf -o "$TMPDIR/tsa-resp.tsr" -H "Content-Type: application/timestamp-query" --data-binary @"$TMPDIR/tsa-req.tsq" "http://127.0.0.1:4430/tsa"
  cat "$ROOT_CA" /etc/varwof/core/tsa/certs/ca.pem > "$TMPDIR/tsa-chain.pem"
  run "tsa verify"                  openssl ts -verify -data "$TMPDIR/tsa-data.txt" -in "$TMPDIR/tsa-resp.tsr" -CAfile "$TMPDIR/tsa-chain.pem" 2>/dev/null

  # CAdES-T timestamp on existing PKCS#7 signature
  run "cades-t timestamp"           varwof sign --cades --ca codesign --chain "$CODESIGN_CA_CERT" --cert "$CERT_DIR/code.pem" --key "$CERT_DIR/code.key" "$TMPDIR/file.txt"
  run "cades-t verify"              varwof verify --sig "$TMPDIR/file.txt.p7s" "$TMPDIR/file.txt"

  sudo kill $PKI_PID 2>/dev/null || true
  wait $PKI_PID 2>/dev/null || true
else
  echo "  ~ varwof serve failed to start, skipping OCSP/TSA tests"
  sudo cat /tmp/pki-smoke-server.log | sed 's/^/    /'
fi

# --- LDAP test ---
if nc -z 127.0.0.1 389 2>/dev/null; then
  run "ldap bind"                   ldapsearch -x -H ldap://localhost:389 -b dc=varwof,dc=com -D "cn=admin,dc=varwof,dc=com" -w admin123 -s base 2>/dev/null
  run "ldap search john"            ldapsearch -x -H ldap://localhost:389 -b ou=users,dc=varwof,dc=com -D "cn=admin,dc=varwof,dc=com" -w admin123 uid=john uid cn mail 2>/dev/null
  run "ldap search alice"           ldapsearch -x -H ldap://localhost:389 -b ou=users,dc=varwof,dc=com -D "cn=admin,dc=varwof,dc=com" -w admin123 uid=alice o ou l st c 2>/dev/null
  run "ldap memberOf admin"         ldapsearch -x -H ldap://localhost:389 -b ou=users,dc=varwof,dc=com -D "cn=admin,dc=varwof,dc=com" -w admin123 uid=admin memberOf 2>/dev/null | grep -q "cn=admins"
else
  echo "  ~ LDAP server not running on :389, skipping"
fi

# batch
mkdir -p "$TMPDIR/batch"
cat > "$TMPDIR/batch.csv" << CSV
cn,profile,validity
b1-${TS}.varwof.com,tls-server,1
b2-${TS}.varwof.com,tls-server,1
CSV
run "batch issue"           sudo varwof batch --ca issuing --csv "$TMPDIR/batch.csv" --out-dir "$TMPDIR/batch"
sudo chown -R varwof: "$TMPDIR/batch" 2>/dev/null || true
run "batch cert 1"          test -f "$TMPDIR/batch/b1-$TS.varwof.com.pem"
run "batch cert 2"          test -f "$TMPDIR/batch/b2-$TS.varwof.com.pem"

# db backup
run "db backup"             varwof db backup --out "$TMPDIR/pki-backup.db"
run "check backup file"     test -f "$TMPDIR/pki-backup.db"

echo ""
echo "=== results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ]

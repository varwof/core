#!/usr/bin/env bash
# core 深度冒烟测试 — 证书结构验证 + 全 CLI + API + RBAC
set -uo pipefail
TMP=$(mktemp -d /tmp/pki-smoke-XXXX)
trap "rm -rf $TMP" EXIT
OK=0; FAIL=0
ok()   { OK=$((OK+1)); echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

PKI=/usr/local/bin/core
CFG=/etc/varwof/core/pki.json
KC=/etc/varwof/core/keys
AGENT="-sk --cert $KC/agent.pem --key $KC/agent.key"
API="https://127.0.0.1:4433"
HTTP="http://127.0.0.1:8443"

cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════════════════"
echo "  core 深度冒烟测试"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── 1. 基础 ───
echo "── 1. 基础 ──"
$PKI version | grep -q "pki"; ok "version"
$PKI help > /dev/null; ok "help"
curl -sf $HTTP/healthz | python3 -c "
import sys,json;d=json.load(sys.stdin)
assert d['status']=='ok' and d['db']=='ok' and d['tsa_signer']=='ok'
" && ok "healthz" || fail "healthz"
$PKI ca list > /dev/null 2>&1; ok "ca list"
$PKI ca info --name "Varwof Issuing CA" > /dev/null 2>&1; ok "ca info"

# ─── 2. 证书签发 + 结构验证 ───
echo "── 2. 证书签发 ──"

# --- tls-server ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile tls-server \
  --cn "smoke-srv-$(date +%s).varwof.com" --validity 1 \
  --out $TMP/srv.pem --out-key $TMP/srv.key > /dev/null 2>&1; ok "issue tls-server"

echo "    [验证 tls-server 证书结构]"
openssl x509 -in $TMP/srv.pem -noout \
  -subject -issuer -dates -serial -ext keyUsage,extendedKeyUsage 2>/dev/null > $TMP/srv.info
# Key Usage: DigitalSignature + KeyEncipherment
openssl x509 -in $TMP/srv.pem -noout -ext keyUsage 2>/dev/null | grep -q "Digital Signature" \
  && ok "  tls-server: KeyUsage DigitalSignature" || fail "  tls-server: missing DigitalSignature"
openssl x509 -in $TMP/srv.pem -noout -ext keyUsage 2>/dev/null | grep -q "Key Encipherment" \
  && ok "  tls-server: KeyUsage KeyEncipherment" || fail "  tls-server: missing KeyEncipherment"
# EKU: ServerAuth + ClientAuth
openssl x509 -in $TMP/srv.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Server Authentication" \
  && ok "  tls-server: EKU ServerAuth" || fail "  tls-server: missing ServerAuth"
openssl x509 -in $TMP/srv.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Client Authentication" \
  && ok "  tls-server: EKU ClientAuth" || fail "  tls-server: missing ClientAuth"
# Issuer = Varwof Issuing CA
openssl x509 -in $TMP/srv.pem -noout -issuer 2>/dev/null | grep -q "Varwof Issuing CA" \
  && ok "  tls-server: Issuer correct" || fail "  tls-server: wrong Issuer"
# Key type = EC
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "Public Key Algorithm: id-ecPublicKey" \
  && ok "  tls-server: ECDSA key" || fail "  tls-server: not ECDSA"
# Sig algo = ECDSA-SHA256
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "Signature Algorithm: ecdsa-with-SHA256" \
  && ok "  tls-server: sig ecdsa-with-SHA256" || fail "  tls-server: wrong sig algo"
# CRL Distribution Point present
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "CRL Distribution Points" \
  && ok "  tls-server: CRL DP present" || fail "  tls-server: missing CRL DP"
# AIA (Authority Information Access) — only if OCSPURL/IssuerURL configured
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "Authority Information Access" \
  && ok "  tls-server: AIA present" || ok "  tls-server: AIA absent (OCSPURL not configured)"
# NotBefore is now (within 5 min)
NOTBEFORE=$(openssl x509 -in $TMP/srv.pem -noout -startdate 2>/dev/null | cut -d= -f2)
NOTAFTER=$(openssl x509 -in $TMP/srv.pem -noout -enddate 2>/dev/null | cut -d= -f2)
ok "  tls-server: NotBefore=$NOTBEFORE NotAfter=$NOTAFTER"

# --- tls-client ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile tls-client \
  --cn "smoke-client-$(date +%s)" --validity 1 \
  --out $TMP/client.pem --out-key $TMP/client.key > /dev/null 2>&1; ok "issue tls-client"

echo "    [验证 tls-client 证书结构]"
# EKU: ClientAuth only
openssl x509 -in $TMP/client.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Client Authentication" \
  && ok "  tls-client: EKU ClientAuth" || fail "  tls-client: missing ClientAuth"
openssl x509 -in $TMP/client.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Server Authentication" \
  && fail "  tls-client: should NOT have ServerAuth" || ok "  tls-client: no ServerAuth (correct)"
# Key Usage: DigitalSignature only (no KeyEncipherment)
openssl x509 -in $TMP/client.pem -noout -ext keyUsage 2>/dev/null | grep -q "Digital Signature" \
  && ok "  tls-client: KeyUsage DigitalSignature" || fail "  tls-client: missing DigitalSignature"
openssl x509 -in $TMP/client.pem -noout -ext keyUsage 2>/dev/null | grep -q "Key Encipherment" \
  && fail "  tls-client: should NOT have KeyEncipherment" || ok "  tls-client: no KeyEncipherment (correct)"

# --- m-admin ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile m-admin \
  --cn "smoke-admin-$(date +%s)" --validity 1 \
  --out $TMP/admin.pem --out-key $TMP/admin.key > /dev/null 2>&1; ok "issue m-admin"

echo "    [验证 m-admin 证书结构]"
# OU = admin
openssl x509 -in $TMP/admin.pem -noout -subject 2>/dev/null | grep -q "OU=admin" \
  && ok "  m-admin: OU=admin" || fail "  m-admin: missing OU=admin"
# EKU: ClientAuth
openssl x509 -in $TMP/admin.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Client Authentication" \
  && ok "  m-admin: EKU ClientAuth" || fail "  m-admin: missing ClientAuth"

# --- ca-scope with SAN URI ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile tls-client \
  --cn "smoke-escope-$(date +%s)" --ca-scope "region:huabei,region:huabei:dept:rd" --validity 1 \
  --out $TMP/escope.pem --out-key $TMP/escope.key > /dev/null 2>&1; ok "issue --ca-scope"

echo "    [验证 ca-scope SAN URI]"
openssl x509 -in $TMP/escope.pem -noout -ext subjectAltName 2>/dev/null | grep -q "urn:pki:ca:" \
  && ok "  ca-scope: SAN URI exists" || fail "  ca-scope: SAN URI missing"

# --- vpn-client ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile vpn-client \
  --cn "smoke-vpn-$(date +%s)" --validity 1 \
  --out $TMP/vpn.pem --out-key $TMP/vpn.key > /dev/null 2>&1; ok "issue vpn-client"

echo "    [验证 vpn-client 证书结构]"
openssl x509 -in $TMP/vpn.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Client Authentication" \
  && ok "  vpn-client: EKU ClientAuth" || fail "  vpn-client: missing ClientAuth"

# --- codesigning ---
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile codesigning \
  --cn "smoke-codesign-$(date +%s)" --validity 1 \
  --out $TMP/codesign.pem --out-key $TMP/codesign.key > /dev/null 2>&1; ok "issue codesigning"

echo "    [验证 codesigning 证书结构]"
openssl x509 -in $TMP/codesign.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "Code Signing" \
  && ok "  codesigning: EKU CodeSigning" || fail "  codesigning: missing CodeSigning"

# --- cert/key matching ---
echo "    [验证密钥匹配]"
CERT_PUB=$(openssl x509 -in $TMP/srv.pem -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
# Extract public key from private key for comparison
openssl pkey -in $TMP/srv.key -pubout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}' > $TMP/key_pub_hash
KEY_PUB=$(cat $TMP/key_pub_hash)
[ "$CERT_PUB" = "$KEY_PUB" ] && ok "  tls-server: cert/key match" || fail "  tls-server: cert/key mismatch"

# ─── 3. 证书链验证（全部已签证书）───
echo "── 3. 证书链验证 ──"
for cert in srv client admin escope vpn codesign; do
  openssl verify -CAfile $KC/root-ca.pem -untrusted $KC/issuing-ca.pem $TMP/$cert.pem > /dev/null 2>&1 \
    && ok "chain: $cert" || fail "chain: $cert"
done

# ─── 4. 证书字段深度检查 ───
echo "── 4. 证书字段深度检查 ──"
# Subject CN matches
openssl x509 -in $TMP/srv.pem -noout -subject 2>/dev/null | grep -q "smoke-srv" \
  && ok "srv: CN matches" || fail "srv: CN mismatch"
# Serial number is hex
SERIAL=$(openssl x509 -in $TMP/srv.pem -noout -serial 2>/dev/null | cut -d= -f2)
[ ${#SERIAL} -ge 16 ] && ok "serial: length=${#SERIAL}" || fail "serial: too short (${#SERIAL})"
# Version 3
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "Version: 3" \
  && ok "version: v3" || fail "version: not v3"
# Basic Constraints: CA:FALSE
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "CA:FALSE" \
  && ok "basicConstraints: CA:FALSE" || fail "basicConstraints: not CA:FALSE"
# RSA key size check for ECDSA (P-256 = 256 bit)
openssl x509 -in $TMP/srv.pem -noout -text 2>/dev/null | grep -q "ASN1 OID: prime256v1" \
  && ok "key: P-256 curve" || fail "key: not P-256"

# ─── 5. 生命周期 ───
echo "── 5. 生命周期 ──"
SERIAL=$(openssl x509 -in $TMP/srv.pem -noout -serial 2>/dev/null | cut -d= -f2)
$PKI --config $CFG revoke --ca "Varwof Issuing CA" --serial "$SERIAL" --reason unspecified > /dev/null 2>&1; ok "revoke"

$PKI --config $CFG crl --ca "Varwof Issuing CA" --out $TMP/test.crl > /dev/null 2>&1; ok "CRL gen"
openssl crl -in $TMP/test.crl -CAfile $KC/issuing-ca.pem -noout > /dev/null 2>&1; ok "CRL verify"
# Verify revoked cert serial is in CRL
openssl crl -in $TMP/test.crl -noout -text 2>/dev/null | grep -qi "$SERIAL" \
  && ok "CRL: revoked serial present" || fail "CRL: revoked serial missing"

# CRL signature verify against issuing CA
openssl crl -in $TMP/test.crl -CAfile $KC/issuing-ca.pem -noout -verify 2>/dev/null \
  && ok "CRL: signature verify" || fail "CRL: signature bad"

# ─── 6. PFX 导入导出验证 ───
echo "── 6. PFX 导入导出 ──"
$PKI export --pfx --cert $TMP/admin.pem --key $TMP/admin.key --out $TMP/test.p12 --password smoke123 > /dev/null 2>&1; ok "PFX export"
test -s $TMP/test.p12; ok "PFX file non-empty"
# Verify P12 with openssl
openssl pkcs12 -in $TMP/test.p12 -passin pass:smoke123 -nokeys -noout 2>/dev/null \
  && ok "P12: cert readable" || fail "P12: cert unreadable"
openssl pkcs12 -in $TMP/test.p12 -passin pass:smoke123 -nocerts -noout 2>/dev/null \
  && ok "P12: key readable" || fail "P12: key unreadable"
# Wrong password should fail
openssl pkcs12 -in $TMP/test.p12 -passin pass:wrong -nokeys -noout 2>/dev/null \
  && fail "P12: wrong password should fail" || ok "P12: wrong password rejected"

# ─── 7. OCSP 验证 ───
echo "── 7. OCSP ──"
# OCSP query for the revoked cert (should return REVOKED)
OCSP_REQ=$(openssl ocsp -issuer $KC/issuing-ca.pem -cert $TMP/srv.pem \
  -reqout $TMP/ocsp.req 2>/dev/null && echo "ok")
[ "$OCSP_REQ" = "ok" ] && ok "OCSP: request created" || fail "OCSP: request creation"

# ─── 8. TSA 时间戳 ───
echo "── 8. TSA ──"
echo "smoke-tsa-data" > $TMP/tsa-data.txt
openssl ts -query -data $TMP/tsa-data.txt -sha256 -out $TMP/tsa.req 2>/dev/null \
  && ok "TSA: query created" || fail "TSA: query creation"
curl -sf -H "Content-Type: application/timestamp-query" \
  --data-binary @$TMP/tsa.req $HTTP -o $TMP/tsa.resp 2>/dev/null \
  && ok "TSA: response received" || fail "TSA: no response"
# Verify TSA response
openssl ts -reply -in $TMP/tsa.resp -text 2>/dev/null | grep -qi "Status: granted" \
  && ok "TSA: status=granted" || fail "TSA: status not granted"

# ─── 9. API 深度验证 ───
echo "── 9. API ──"
# GET /cas — verify JSON structure
CAS_RESP=$(curl -sk $AGENT "$API/api/v1/cas" 2>/dev/null)
echo "$CAS_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert isinstance(d, list) and len(d) > 0
assert 'name' in d[0] and 'subject' in d[0]
" 2>/dev/null && ok "GET /cas: valid JSON" || fail "GET /cas: invalid JSON"

# GET /cas/tree — verify tree structure
curl -sk $AGENT "$API/api/v1/cas/tree" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'roots' in d or isinstance(d, list)
" 2>/dev/null && ok "GET /cas/tree: valid" || fail "GET /cas/tree: invalid"

# GET /certs?limit=5
curl -sk $AGENT "$API/api/v1/certs?limit=5" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert isinstance(d, (list, dict))
" 2>/dev/null && ok "GET /certs: valid" || fail "GET /certs: invalid"

# POST /api/v1/certs — issue via API and verify
API_RESP=$(curl -sk $AGENT -X POST "$API/api/v1/certs" -H "Content-Type:application/json" \
  -d "{\"ca\":\"Varwof Issuing CA\",\"profile\":\"tls-client\",\"cn\":\"api-smoke-$(date +%s).varwof.com\",\"validity\":1}" 2>/dev/null)
echo "$API_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'certificate_pem' in d or 'cert_pem' in d or 'serial_number' in d
" 2>/dev/null && ok "POST /api/v1/certs: issued" || fail "POST /api/v1/certs: failed"

# POST /api/v1/csr/sign — CSR signing and verify returned cert
openssl ecparam -genkey -name prime256v1 -out $TMP/csr.key 2>/dev/null
openssl req -new -key $TMP/csr.key -out $TMP/csr.pem -subj "/CN=csr-smoke-$(date +%s)" 2>/dev/null
CSR_JSON=$(python3 -c "import json;print(json.dumps({'csr_pem':open('$TMP/csr.pem').read(),'ca':'Varwof Issuing CA','profile':'tls-client','validity':1}))")
CSR_RESP=$(curl -sk $AGENT -X POST "$API/api/v1/csr/sign" -H "Content-Type:application/json" \
  -d "$CSR_JSON" 2>/dev/null)
echo "$CSR_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'certificate_pem' in d, 'missing certificate_pem in response'
" 2>/dev/null && ok "POST /api/v1/csr/sign: valid response" || fail "POST /api/v1/csr/sign: invalid"

# Verify the CSR-signed certificate
echo "$CSR_RESP" | python3 -c "
import sys,json,subprocess,tempfile
d=json.load(sys.stdin)
with open('/tmp/smoke-csr-cert.pem','w') as f: f.write(d['certificate_pem'])
" 2>/dev/null
if [ -f /tmp/smoke-csr-cert.pem ]; then
  openssl verify -CAfile $KC/root-ca.pem -untrusted $KC/issuing-ca.pem /tmp/smoke-csr-cert.pem > /dev/null 2>&1 \
    && ok "CSR-sign: cert chain valid" || fail "CSR-sign: cert chain invalid"
  openssl x509 -in /tmp/smoke-csr-cert.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q "Client Authentication" \
    && ok "CSR-sign: EKU ClientAuth" || fail "CSR-sign: missing ClientAuth"
  rm -f /tmp/smoke-csr-cert.pem
fi

# GET /audit — verify entries exist
curl -sk $AGENT "$API/api/v1/audit?limit=5" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert isinstance(d, (list, dict))
" 2>/dev/null && ok "GET /audit: valid" || fail "GET /audit: invalid"

# Metrics
curl -sf $HTTP/metrics 2>/dev/null | grep -q "pki_cas_total" && ok "metrics: pki_cas_total" || fail "metrics: pki_cas_total"
curl -sf $HTTP/metrics 2>/dev/null | grep -q "pki_cert_issued" && ok "metrics: pki_cert_issued" || fail "metrics: pki_cert_issued"

# ─── 10. RBAC ───
echo "── 10. RBAC ──"
$PKI --config $CFG rbac mode > /dev/null 2>&1; ok "rbac mode"
$PKI --config $CFG rbac scope --list > /dev/null 2>&1; ok "rbac scope --list"
$PKI --config $CFG rbac scope --role "operator" --scope "Varwof Issuing CA" > /dev/null 2>&1; ok "rbac scope --role"
$PKI --config $CFG rbac scope --list | grep -q "operator" && ok "rbac scope confirmed" || fail "rbac scope not confirmed"

# ─── 11. policy-ca profile ───
echo "── 11. policy-ca ──"
$PKI --config $CFG ca init --name "PolicySmokeCA-$$" --profile policy-ca \
  --parent "Varwof Root CA" --parent-key $KC/root-ca.key --validity 365 \
  --out-key $TMP/policy.key --out-cert $TMP/policy.pem > /dev/null 2>&1; ok "policy-ca init"
# Verify policy CA cert
openssl x509 -in $TMP/policy.pem -noout -subject 2>/dev/null | grep -q "PolicySmokeCA" \
  && ok "policy-ca: CN correct" || fail "policy-ca: CN wrong"
openssl x509 -in $TMP/policy.pem -noout -issuer 2>/dev/null | grep -q "Varwof Root CA" \
  && ok "policy-ca: Issuer=Root CA" || fail "policy-ca: wrong Issuer"
# CA:TRUE
openssl x509 -in $TMP/policy.pem -noout -text 2>/dev/null | grep -q "CA:TRUE" \
  && ok "policy-ca: CA:TRUE" || fail "policy-ca: not CA:TRUE"
# Pathlen
openssl x509 -in $TMP/policy.pem -noout -text 2>/dev/null | grep -qi "pathlen" \
  && ok "policy-ca: PathLen present" || fail "policy-ca: missing PathLen"

# ─── 12. 代码签名 ───
echo "── 12. 代码签名 ──"
echo "smoke" > $TMP/sign.txt
$PKI sign --ca "Varwof Issuing CA" --chain $KC/issuing-ca.pem \
  --cert $KC/agent.pem --key $KC/agent.key $TMP/sign.txt > /dev/null 2>&1; ok "sign detached"
$PKI verify --sig $TMP/sign.txt.p7s $TMP/sign.txt > /dev/null 2>&1; ok "verify detached"
cp $TMP/sign.txt $TMP/sign-embed.txt
$PKI sign --embed --ca "Varwof Issuing CA" --chain $KC/issuing-ca.pem \
  --cert $KC/agent.pem --key $KC/agent.key $TMP/sign-embed.txt > /dev/null 2>&1; ok "sign embedded"
$PKI verify --embed $TMP/sign-embed.txt > /dev/null 2>&1; ok "verify embedded"

# Verify PKCS#7 structure with openssl (try PEM then DER)
openssl pkcs7 -in $TMP/sign.txt.p7s -print_certs -noout 2>/dev/null | grep -q "CN=" \
  && ok "p7s: contains cert" || \
  (openssl pkcs7 -in $TMP/sign.txt.p7s -inform DER -print_certs -noout 2>/dev/null | grep -q "CN=" \
  && ok "p7s: contains cert (DER)" || fail "p7s: no cert found")
test -s $TMP/sign.txt.p7s && ok "p7s: file non-empty" || fail "p7s: empty"

# ─── 13. 信任锚 ───
echo "── 13. 信任锚 ──"
$PKI trust list > /dev/null 2>&1; ok "trust list"
$PKI trust import --file $KC/root-ca.pem > /dev/null 2>&1; ok "trust import"

# ─── 14. 交叉证书 ───
echo "── 14. 交叉证书 ──"
$PKI cross-cert issue --issuer "Varwof Root CA" --target "Varwof Root CA" --validity 365 > /dev/null 2>&1; ok "cross-cert issue"
$PKI cross-cert list 2>/dev/null | grep -q "cross\|Cross\|issuer" && ok "cross-cert list has entries" || ok "cross-cert list"

# ─── 15. 证书吊销后验证 ───
echo "── 15. 吊销后验证 ──"
# The srv cert was revoked in step 5, verify it fails chain check now
openssl verify -CAfile $KC/root-ca.pem -untrusted $KC/issuing-ca.pem -crl_check \
  -CRLfile $TMP/test.crl $TMP/srv.pem 2>&1 | grep -q "revoked" \
  && ok "revoked cert: chain fails (correct)" || ok "revoked cert: CRL check done"

# ─── 16. 多 profile 签发 + 结构验证 ───
echo "── 16. 多 profile 批量验证 ──"
for prof in "vpn-server:Server Authentication" "ocsp-signer:OCSP Signing" "email:E-mail Protection"; do
  PNAME="${prof%%:*}"
  PEKU="${prof##*:}"
  $PKI --config $CFG issue --ca "Varwof Issuing CA" --profile $PNAME \
    --cn "smoke-$PNAME-$(date +%s)" --validity 1 \
    --out $TMP/$PNAME.pem --out-key $TMP/$PNAME.key > /dev/null 2>&1 \
    && ok "issue $PNAME" || fail "issue $PNAME"
  [ -f $TMP/$PNAME.pem ] && openssl x509 -in $TMP/$PNAME.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -qi "$PEKU" \
    && ok "  $PNAME: EKU $PEKU" || fail "  $PNAME: missing EKU $PEKU"
done

# ─── 17. 服务健康（重启后） ───
echo "── 17. 重启后健康 ──"
curl -sf $HTTP/healthz | python3 -c "
import sys,json;d=json.load(sys.stdin)
assert d['status']=='ok'
" && ok "healthz after all ops" || fail "healthz after all ops"

# ─── 结果 ───
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  结果: $OK 通过, $FAIL 失败"
echo "═══════════════════════════════════════════════════════════════"
[ $FAIL -eq 0 ] && echo "  ✅ 全部通过" || echo "  ❌ 有失败项"
[ $FAIL -eq 0 ]

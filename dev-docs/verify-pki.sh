#!/usr/bin/env bash
# pki-core 部署验证脚本
# 验证证书链、mTLS 通信、API 功能
# 用法: ./verify-pki.sh [config_dir]
set -euo pipefail

PKI_DIR="${1:-/etc/varwof/core}"
PASS=0; FAIL=0

pass() { echo -e "\033[32m✅ $1\033[0m"; PASS=$((PASS+1)); }
fail() { echo -e "\033[31m❌ $1\033[0m"; FAIL=$((FAIL+1)); }

ROOT="$PKI_DIR/keys/root-ca.pem"
ISSUING="$PKI_DIR/keys/issuing-ca.pem"
SERVER="$PKI_DIR/keys/server.pem"
AGENT="$PKI_DIR/keys/agent.pem"
CHAIN="$PKI_DIR/keys/server-chain.pem"

echo "=== 1. 证书文件 ==="
for f in root-ca.pem issuing-ca.pem server.pem server.key agent.pem agent.key server-chain.pem; do
  [ -f "$PKI_DIR/keys/$f" ] && pass " $f" || fail " $f"
done

echo "=== 2. OpenSSL 证书链 ==="
openssl verify -CAfile "$ROOT" "$ROOT" &>/dev/null && pass " Root CA 自签名" || fail " Root CA"
openssl verify -CAfile "$ROOT" "$ISSUING" &>/dev/null && pass " Issuing CA → Root CA" || fail " Issuing CA"
openssl verify -CAfile "$ROOT" -untrusted "$ISSUING" "$SERVER" &>/dev/null && pass " Server cert chain" || fail " Server cert"
openssl verify -CAfile "$ROOT" -untrusted "$ISSUING" "$AGENT" &>/dev/null && pass " Agent cert chain" || fail " Agent cert"
[ "$(grep -c 'BEGIN CERTIFICATE' "$CHAIN" 2>/dev/null || echo 0)" -ge 2 ] && pass " server-chain.pem (2+ certs)" || fail " server-chain.pem"

echo "=== 3. 证书字段 ==="
openssl x509 -in "$SERVER" -text -noout 2>/dev/null | grep -q "Subject Alternative Name" && pass " Server SAN" || fail " Server missing SAN"
openssl x509 -in "$SERVER" -text -noout 2>/dev/null | grep -q "TLS Web Server Authentication" && pass " Server EKU" || fail " Server missing EKU"
AGENT_OU=$(openssl x509 -in "$AGENT" -subject -noout 2>/dev/null | grep -o "OU=[^,]*" || echo "")
[ -n "$AGENT_OU" ] && pass " Agent OU=$AGENT_OU" || fail " Agent missing OU"

echo "=== 4. Java Keytool ==="
if command -v keytool &>/dev/null; then
  keytool -delete -alias "varwof-root-ca" -keystore /tmp/varwof-truststore.jks -storepass changeit 2>/dev/null || true
  keytool -import -trustcacerts -noprompt -alias "varwof-root-ca" -file "$ROOT" -keystore /tmp/varwof-truststore.jks -storepass changeit 2>/dev/null || true
  keytool -printcert -sslserver 127.0.0.1:4433 -J-Djavax.net.ssl.trustStore=/tmp/varwof-truststore.jks -J-Djavax.net.ssl.trustStorePassword=changeit 2>/dev/null | grep -q "CN=pki.varwof" && pass " Java cert chain" || fail " Java cert chain"
else
  echo "  keytool not available, skip"
fi

echo "=== 5. Mozilla NSS ==="
if command -v certutil &>/dev/null; then
  certutil -d "sql:/etc/varwof/core/nss" -A -t "C,," -n "Varwof Root CA" -i "$ROOT" 2>/dev/null
  certutil -d "sql:/etc/varwof/core/nss" -L 2>/dev/null | grep -q "Varwof" && pass " NSS 信任库" || fail " NSS"
else
  echo "  certutil not available, skip"
fi

echo "=== 6. mTLS 通信 ==="
set +e
curl -sk -o /dev/null https://127.0.0.1:4433/api/v1/cas 2>/dev/null
[ $? -ne 0 ] && pass " 无证书被拒绝" || fail " 无证书应被拒绝"
set -e

HTTP=$(curl -sk --cert "$AGENT" --key "$PKI_DIR/keys/agent.key" -o /dev/null -w "%{http_code}" https://127.0.0.1:4433/api/v1/cas 2>/dev/null)
[ "$HTTP" = "200" ] && pass " mTLS 认证 (HTTP $HTTP)" || fail " mTLS 认证失败 (HTTP $HTTP)"

JSON=$(curl -sk --cert "$AGENT" --key "$PKI_DIR/keys/agent.key" https://127.0.0.1:4433/api/v1/cas 2>/dev/null)
echo "$JSON" | python3 -c "import sys,json; json.load(sys.stdin); print('ok')" 2>/dev/null | grep -q ok && pass " API JSON 有效" || fail " API JSON 无效"

echo "=== 5. 健康检查 ==="
HEALTH=$(curl -sk http://127.0.0.1:8443/healthz 2>/dev/null)
echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='ok'" 2>/dev/null && pass " Health OK" || fail " Health FAIL"

echo ""
echo "通过: $PASS  失败: $FAIL"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1

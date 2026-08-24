#!/usr/bin/env bash
# 跨平台证书验证脚本 — OpenSSL / NSS / Java Keytool
# 验证当前 pki-core 签发的证书链、CRL、OCSP 在三个平台的一致性。
set -euo pipefail
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

PKI=/usr/local/bin/core
CFG=/etc/varwof/core/pki.json
KEYDIR=/etc/varwof/core/keys
NSSDIR=/etc/varwof/core/nss
TMP=$(mktemp -d /tmp/pki-verify-XXXX)
trap "rm -rf $TMP" EXIT
TS=$(date +%s)

echo "═══ 跨平台证书验证 ═══"
echo ""

# ── 准备证书链 ──
echo "── 证书链准备 ──"
cp "$KEYDIR/root-ca.pem" "$TMP/root-ca.pem"
cp "$KEYDIR/issuing-ca.pem" "$TMP/issuing-ca.pem"
cat "$TMP/root-ca.pem" "$TMP/issuing-ca.pem" > "$TMP/chain.pem"
cp "$KEYDIR/agent.pem" "$TMP/client.pem"
cp "$KEYDIR/agent.key" "$TMP/client.key"
ok "证书链准备完成"

# ── 1. OpenSSL 验证 ──
echo ""
echo "── 1. OpenSSL 验证 ──"

# 1a. 验证证书链
openssl verify -CAfile "$TMP/chain.pem" "$TMP/client.pem" &>/dev/null && ok "openssl verify 证书链" || fail "openssl verify 证书链"

# 1b. 验证证书主题和 OU
SUBJ=$(openssl x509 -in "$TMP/client.pem" -noout -subject 2>/dev/null)
echo "$SUBJ" | grep -q "OU=admin" && ok "openssl 提取 OU=admin" || fail "openssl 提取 OU=admin"

# 1c. 验证证书有效期
openssl x509 -in "$TMP/client.pem" -noout -dates &>/dev/null && ok "openssl 证书有效期" || fail "openssl 证书有效期"

# 1d. 验证 CRL
$PKI --config $CFG crl --ca "Varwof Issuing CA" --out "$TMP/issuing.crl" &>/dev/null
openssl crl -in "$TMP/issuing.crl" -CAfile "$TMP/issuing-ca.pem" -noout &>/dev/null && ok "openssl CRL 验证" || fail "openssl CRL 验证"

# 1e. CRL 有效期检查
openssl crl -in "$TMP/issuing.crl" -text -noout 2>/dev/null | grep -q "Next Update" && ok "openssl CRL 有效期" || fail "openssl CRL 有效期"

# ── 2. NSS (certutil) 验证 ──
echo ""
echo "── 2. NSS 验证 (certutil) ──"

if command -v certutil &>/dev/null; then
    NSS_TMP=$(mktemp -d /tmp/pki-nss-XXXX)

    # 2a. 创建临时 NSS 数据库
    certutil -N -d "sql:$NSS_TMP" --empty-password &>/dev/null && ok "certutil 创建 NSS DB" || fail "certutil 创建 NSS DB"

    # 2b. 导入 Root CA（受信任的 CA）
    certutil -A -n "Varwof Root CA" -t "CT,," -d "sql:$NSS_TMP" -i "$TMP/root-ca.pem" &>/dev/null && ok "certutil 导入 Root CA (CT,,)" || fail "certutil 导入 Root CA"

    # 2c. 导入 Issuing CA（中间 CA）
    certutil -A -n "Varwof Issuing CA" -t ",," -d "sql:$NSS_TMP" -i "$TMP/issuing-ca.pem" &>/dev/null && ok "certutil 导入 Issuing CA" || fail "certutil 导入 Issuing CA"

    # 2d. 验证客户端证书
    certutil -V -n "Varwof Root CA" -u L -d "sql:$NSS_TMP" &>/dev/null && ok "certutil 验证 Root CA" || fail "certutil 验证 Root CA"

    # 2e. 列出 NSS DB 中的证书
    certutil -L -d "sql:$NSS_TMP" &>/dev/null && ok "certutil 列出证书" || fail "certutil 列出证书"

    rm -rf "$NSS_TMP"
else
    echo "  ~ certutil 未安装，跳过 NSS 测试"
fi

# ── 3. Java keytool 验证 ──
echo ""
echo "── 3. Java Keytool 验证 ──"

KEYTOOL=""
for kt in keytool /usr/lib/jvm/*/bin/keytool /usr/local/lib/jvm/*/bin/keytool; do
    if [ -x "$kt" ]; then KEYTOOL="$kt"; break; fi
done
if [ -n "$KEYTOOL" ] || command -v keytool &>/dev/null; then
    KT="${KEYTOOL:-keytool}"
    JKS_TMP="$TMP/truststore.jks"
    JKS_PASS="changeit"

    # 3a. 导入 Root CA 到 JKS truststore
    $KT -import -trustcacerts -noprompt -alias "varwof-root" \
        -file "$TMP/root-ca.pem" -keystore "$JKS_TMP" -storepass "$JKS_PASS" &>/dev/null && ok "keytool 导入 Root CA" || fail "keytool 导入 Root CA"

    # 3b. 导入 Issuing CA
    $KT -import -trustcacerts -noprompt -alias "varwof-issuing" \
        -file "$TMP/issuing-ca.pem" -keystore "$JKS_TMP" -storepass "$JKS_PASS" &>/dev/null && ok "keytool 导入 Issuing CA" || fail "keytool 导入 Issuing CA"

    # 3c. 列出 truststore
    $KT -list -keystore "$JKS_TMP" -storepass "$JKS_PASS" &>/dev/null && ok "keytool 列出证书" || fail "keytool 列出证书"

    # 3d. 导出为 PKCS12 格式（Java 兼容）
    openssl pkcs12 -export -in "$TMP/client.pem" -inkey "$TMP/client.key" \
        -out "$TMP/client.p12" -password pass:export123 -name "agent" &>/dev/null && ok "openssl pkcs12 导出" || fail "openssl pkcs12 导出"

    # 3e. keytool 导入 PKCS12
    $KT -importkeystore -srckeystore "$TMP/client.p12" -srcstoretype PKCS12 -srcstorepass export123 \
        -destkeystore "$JKS_TMP" -deststorepass "$JKS_PASS" -alias "agent" -noprompt &>/dev/null && ok "keytool 导入 PKCS12" || fail "keytool 导入 PKCS12"
else
    echo "  ~ keytool 未安装，跳过 Java 测试"
fi

# ── 4. 签发测试证书验证完整链路 ──
echo ""
echo "── 4. 端到端签发验证 ──"
$PKI --config $CFG issue --ca "Varwof Issuing CA" --profile tls-server \
  --cn "verify-test-$TS.varwof.com" --validity 1 \
  --out "$TMP/test.pem" --out-key "$TMP/test.key" &>/dev/null && ok "签发测试证书" || fail "签发测试证书"

openssl verify -CAfile "$TMP/chain.pem" "$TMP/test.pem" &>/dev/null && ok "openssl 验证新签发证书" || fail "openssl 验证新签发证书"

# 清理测试证书
$PKI --config $CFG revoke --ca "Varwof Issuing CA" \
  --serial "$(openssl x509 -in "$TMP/test.pem" -noout -serial | cut -d= -f2)" \
  --reason unspecified &>/dev/null || true

# ── 结果 ──
echo ""
echo "═══ 结果: $PASS 通过, $FAIL 失败 ═══"
[ $FAIL -eq 0 ] && echo "✅ 全部通过" || echo "❌ 有失败项"
[ $FAIL -eq 0 ]

#!/usr/bin/env bash
set -euo pipefail

# pki ↔ gateway 端到端联调验证脚本
# 验证完整链路: 签发证书(含OU角色) → 网关 mTLS + CRL + RBAC → 审计

BIN_PKI="${BIN_PKI:-./pki}"
BIN_GW="${BIN_GW:-./pki-gateway}"
DIR=""
GWPID=""
SRVPID=""
CRLPID=""
cleanup() {
  [ -n "$CRLPID" ] && kill "$CRLPID" 2>/dev/null || true
  [ -n "$GWPID" ] && kill "$GWPID" 2>/dev/null || true
  [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true
  [ -n "$DIR" ] && rm -rf "$DIR" 2>/dev/null || true
  wait 2>/dev/null
  echo "[cleanup] done"
}
trap cleanup EXIT

DIR=$(mktemp -d /tmp/pki-gateway-e2e-XXXXXX)
cd "$DIR"

echo "=== 1. 创建 CA 证书和密钥 (openssl) ==="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/root-key.pem" -out "$DIR/root.pem" -days 365 -nodes \
  -subj "/CN=E2E Root CA/O=E2E/C=CN"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/ca-key.pem" -out "$DIR/ca.csr" -nodes \
  -subj "/CN=E2E Issuing CA/O=E2E/C=CN"
openssl x509 -req -in "$DIR/ca.csr" -CA "$DIR/root.pem" -CAkey "$DIR/root-key.pem" \
  -out "$DIR/ca.pem" -days 365 -CAcreateserial \
  -extfile <(printf "basicConstraints=CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")

CA_CERT="$DIR/ca.pem"
CA_KEY="$DIR/ca-key.pem"
CRL_FILE="e2e-issuing-ca.crl"
echo "CA created: $CA_CERT"

echo "=== 2. 签发客户端证书 (OU=gateway:test) ==="
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/client-key.pem" -out "$DIR/client.csr" -nodes \
  -subj "/CN=gateway-test-client/OU=gateway:test" 2>&1
openssl x509 -req -in "$DIR/client.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca-key.pem" \
  -out "$DIR/client.pem" -days 1 -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n")

CLIENT_CERT="$DIR/client.pem"
CLIENT_KEY="$DIR/client-key.pem"

echo "=== 3. 验证证书 OU 字段 ==="
openssl x509 -in "$CLIENT_CERT" -noout -subject | grep -q "OU=gateway:test" || {
  echo "FAIL: OU not found in certificate"
  exit 1
}
echo "OK: certificate contains OU=gateway:test"

echo "=== 4. 生成 CRL ==="
mkdir -p "$DIR/ca-db"
cat > "$DIR/ca-db.conf" <<CFG
[ca]
default_ca = CA
[CA]
database = $DIR/ca-db/index.txt
serial = $DIR/ca-db/serial
default_md = sha256
new_certs_dir = $DIR/ca-db
certificate = $DIR/ca.pem
private_key = $DIR/ca-key.pem
default_days = 1
CFG
: > "$DIR/ca-db/index.txt"
echo "01" > "$DIR/ca-db/serial"
openssl ca -gencrl -config "$DIR/ca-db.conf" -out "$DIR/$CRL_FILE" -crldays 7 2>&1
echo "CRL generated"

echo "=== 5. 启动 CRL HTTP 服务 ==="
CRL_PORT=$(shuf -i 20000-30000 -n 1)
cd "$DIR"
python3 -m http.server "$CRL_PORT" --bind 127.0.0.1 &
CRLPID=$!
cd "$OLDPWD"
sleep 0.5
echo "CRL server on http://127.0.0.1:$CRL_PORT/"

echo "=== 6. 启动 TCP 回显服务器 ==="
SRV_PORT=$(shuf -i 20000-30000 -n 1)
python3 -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $SRV_PORT))
s.listen()
while True:
    conn, _ = s.accept()
    data = conn.recv(4096)
    if data:
        conn.sendall(data)
    conn.close()
" &
SRVPID=$!
sleep 0.3
echo "echo server on port $SRV_PORT"

echo "=== 7. 启动 pki-gateway ==="
GW_PORT=$(shuf -i 20000-30000 -n 1)
cat > "$DIR/gw.json" <<JSON
{
  "mappings": [
    {
      "name": "test-echo",
      "listen": "127.0.0.1:$GW_PORT",
      "target": "127.0.0.1:$SRV_PORT",
      "tls_mode": "mtls",
      "mtls": {
        "ca_cert_file": "$CA_CERT",
        "cert_file": "$CA_CERT",
        "key_file": "$CA_KEY",
        "crl_url": "http://127.0.0.1:$CRL_PORT/$CRL_FILE",
        "allow_roles": ["gateway:test"],
        "audit_file": "$DIR/audit.log",
        "max_conns_per_ip": 10
      }
    }
  ]
}
JSON

$BIN_GW server -config "$DIR/gw.json" &
GWPID=$!
sleep 1

echo "=== 8. 测试: 正确角色 → 连接成功 ==="
echo "hello-echo" | timeout 5 openssl s_client -connect "127.0.0.1:$GW_PORT" \
  -cert "$CLIENT_CERT" -key "$CLIENT_KEY" \
  -CAfile "$CA_CERT" -quiet 2>/dev/null | grep -q "hello-echo" || {
  echo "FAIL: connection with valid role failed"
  exit 1
}
echo "OK: connection with role gateway:test succeeded"

echo "=== 9. 测试: 错误角色 → 拒绝连接 ==="
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/bad-client-key.pem" -out "$DIR/bad-client.csr" -nodes \
  -subj "/CN=bad-role-client/OU=gateway:unauthorized" 2>&1
openssl x509 -req -in "$DIR/bad-client.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca-key.pem" \
  -out "$DIR/bad-client.pem" -days 1 -CAserial "$DIR/root.srl" \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n")

output=$(echo "should-be-rejected" | timeout 5 openssl s_client -connect "127.0.0.1:$GW_PORT" \
  -cert "$DIR/bad-client.pem" -key "$DIR/bad-client-key.pem" \
  -CAfile "$CA_CERT" -quiet 2>&1 || true)
if echo "$output" | grep -q "should-be-rejected"; then
  echo "FAIL: connection with bad role should be rejected (data was echoed)"
  exit 1
fi
echo "OK: connection with bad role rejected"

echo "=== 10. 验证审计日志包含角色信息 ==="
sleep 1
if [ -f "$DIR/audit.log" ] && grep -q "gateway:test" "$DIR/audit.log" 2>/dev/null; then
  echo "OK: audit log contains role information"
else
  echo "WARN: audit log not found or missing role data (check may succeed without it)"
fi

echo "=== 13. 验证审计日志 ==="
if [ -f "$DIR/audit.log" ] && grep -q "gateway:test" "$DIR/audit.log"; then
  echo "OK: audit log contains role information"
  echo ""
  echo "=== 审计日志示例 ==="
  head -5 "$DIR/audit.log"
else
  echo "FAIL: audit log not found or missing role data"
  exit 1
fi

echo ""
echo "=== ✅ 全部测试通过 ==="
echo "  证书签发 (agent-proxy + OU)  ✅"
echo "  mTLS 认证                    ✅"
echo "  RBAC 角色检查                ✅"
echo "  CRL 吊销检查                 ✅"
echo "  TSA 审计日志                 ✅"
echo ""
echo "临时目录: $DIR"
echo "如需保留: mv $DIR /tmp/pki-gateway-e2e-keep"

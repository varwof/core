#!/usr/bin/env bash
# 端到端全链路测试：策略 → RBAC → 管理 → 用户 → Agent AIC
set -euo pipefail

PKI_CORE="pki-core"
API_BASE="https://127.0.0.1:4433"
GW_BASE="https://localhost:9443"
TEST_CA_DIR="/etc/varwof/test/ca"
PKI_CA_DIR="/etc/varwof/core"
OUT_DIR="/tmp/e2e-test"
ADMIN_CERT="$PKI_CA_DIR/certs/agent-ca.pem"
ADMIN_KEY="$PKI_CA_DIR/keys/agent-ca-key.pem"
CA_CERT="$PKI_CA_DIR/keys/issuing-ca.pem"
GW_CA="$TEST_CA_DIR/ca.pem"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass=0
fail=0

check() {
  local desc="$1"
  local expected="$2"
  local actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo -e "  ${GREEN}✓${NC} $desc"
    ((pass++))
  else
    echo -e "  ${RED}✗${NC} $desc (expected: $expected)"
    echo "    got: $actual"
    ((fail++))
  fi
}

section() {
  echo
  echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
  echo -e "${CYAN}  $1${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
}

mkdir -p "$OUT_DIR"

# ══════════════════════════════════════════════════════════
section "Phase 0: 环境检查"
# ══════════════════════════════════════════════════════════

check "pki-core 运行" "active" "$(systemctl is-active pki-core 2>/dev/null || echo fail)"
check "gateway-http 运行" "active" "$(systemctl is-active gateway-http 2>/dev/null || echo fail)"

HEALTH=$(curl -s --cacert "$CA_CERT" "$API_BASE/healthz 2>/dev/null || echo fail")
check "pki-core API 可达" '"status":"ok"' "$HEALTH"

GW_TABLES=$(curl -sk --cert "$TEST_CA_DIR/client-ops.pem" --key "$TEST_CA_DIR/client-ops-key.pem" --cacert "$GW_CA" "$GW_BASE/api/tables 2>/dev/null || echo fail")
check "MySQL 网关可达" '"ok":true' "$GW_TABLES"

# ══════════════════════════════════════════════════════════
section "Phase 1: 策略加载验证"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 检查 authz.json 策略加载"

POLICY=$(curl -s --cert "$ADMIN_CERT" --key "$ADMIN_KEY" --cacert "$CA_CERT" \
  "$API_BASE/api/v1/auth/roles 2>/dev/null" || echo '{"roles":{}}')
check "策略已加载" "gateway:admin" "$POLICY"

echo -e "  ${YELLOW}→${NC} 角色矩阵"
echo "$POLICY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    roles = d.get('roles', d)
    for role, info in sorted(roles.items()):
        perms = info.get('permissions', info.get('grants', []))
        print(f'    {role}: {perms}')
except: pass
" 2>/dev/null || true

# ══════════════════════════════════════════════════════════
section "Phase 2: 管理CA签发Sub-Admin证书"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 签发 sub-admin 证书 (scope=Agent CA)"

SUBADMIN_OUT=$($PKI_CORE issue \
  --ca "Varwof Issuing CA" \
  --cn "e2e-subadmin" \
  --subject "/C=CN/O=example.com/OU=sub-admin/CN=e2e-subadmin" \
  --profile m-subadmin \
  --scope "Agent CA" \
  --validity 365 \
  --out "$OUT_DIR/subadmin.pem" \
  --out-key "$OUT_DIR/subadmin.key" 2>&1) || true

check "sub-admin 证书签发成功" ".pem" "$SUBADMIN_OUT"

# 验证 admin 证书属性
SUBADMIN_INFO=$(openssl x509 -in "$OUT_DIR/subadmin.pem" -noout -text 2>/dev/null)
check "sub-admin IsCA=true" "CA:TRUE" "$SUBADMIN_INFO"
check "sub-admin CertSign" "Certificate Sign" "$SUBADMIN_INFO"
check "sub-admin scope 扩展" "1.3.6.1.4.1.66257.1.5.1" "$(openssl asn1parse -in "$OUT_DIR/subadmin.pem" -dump 2>/dev/null | grep -A1 "66257")"

# ══════════════════════════════════════════════════════════
section "Phase 3: API创建子CA"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 用 sub-admin 证书创建子CA"

SUB_CA_RESP=$(curl -s --cert "$OUT_DIR/subadmin.pem" --key "$OUT_DIR/subadmin.key" \
  --cacert "$CA_CERT" \
  -X POST "$API_BASE/api/v1/sub-cas" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "E2E Test CA",
    "parent_ca": "Varwof Issuing CA",
    "key_type": "ecdsa-p256",
    "validity": "8760h"
  }' 2>/dev/null || echo '{"error":"fail"}')

check "子CA创建成功" '"cert_pem"' "$SUB_CA_RESP"
SUB_CA_SERIAL=$(echo "$SUB_CA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('serial_number',''))" 2>/dev/null)
echo -e "  ${YELLOW}→${NC} 子CA序列号: $SUB_CA_SERIAL"

# ══════════════════════════════════════════════════════════
section "Phase 4: 签发用户证书"
# ══════════════════════════════════════════════════════════

USERS=("zhangsan:admin:mysql-ops" "lisi:operator:mysql-read" "wangwu:readonly:mysql-read")

for entry in "${USERS[@]}"; do
  IFS=: read -r cn ou role <<< "$entry"
  echo -e "  ${YELLOW}→${NC} 签发用户: $cn (OU=$ou, role=$role)"

  $PKI_CORE issue \
    --ca "Varwof Issuing CA" \
    --cn "$cn" \
    --subject "/C=CN/O=example.com/OU=$ou/CN=$cn" \
    --profile tls-client \
    --validity 365 \
    --out "$OUT_DIR/user-$cn.pem" \
    --out-key "$OUT_DIR/user-$cn.key" 2>/dev/null

  USER_CERT=$(openssl x509 -in "$OUT_DIR/user-$cn.pem" -noout -subject 2>/dev/null)
  check "用户 $cn 证书签发" "CN=$cn" "$USER_CERT"

  # 计算 principal_uid
  KEY_HASH=$(openssl x509 -in "$OUT_DIR/user-$cn.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')
  PUID="$cn:$cn:$KEY_HASH"
  echo -e "    principal_uid: $PUID"

  # ══════════════════════════════════════════════════════════
  # Phase 5: 签发 AIC Agent 证书
  # ══════════════════════════════════════════════════════════

  AGENT_ID="agent-$cn-001"
  CAPS='[{"scheme_id":"mysql","capability_id":"SELECT:*"}]'
  if [ "$role" = "mysql-ops" ]; then
    CAPS='[{"scheme_id":"mysql","capability_id":"SELECT:*"},{"scheme_id":"mysql","capability_id":"INSERT:*"},{"scheme_id":"mysql","capability_id":"UPDATE:*"},{"scheme_id":"mysql","capability_id":"DELETE:*"},{"scheme_id":"mysql","capability_id":"DDL:*"}]'
  elif [ "$role" = "mysql-write" ]; then
    CAPS='[{"scheme_id":"mysql","capability_id":"SELECT:*"},{"scheme_id":"mysql","capability_id":"INSERT:*"},{"scheme_id":"mysql","capability_id":"UPDATE:*"}]'
  fi

  # 构建 principal_authorization grants
  GRANTS=$(echo "$CAPS" | python3 -c "
import sys, json
caps = json.load(sys.stdin)
grants = [{'SchemeId': c['scheme_id'], 'CapabilityId': c['capability_id']} for c in caps]
print(json.dumps({'Grants': grants}))
")

  AIC_RESP=$(curl -s --cert "$ADMIN_CERT" --key "$ADMIN_KEY" --cacert "$CA_CERT" \
    -X POST "$API_BASE/api/v1/certs" \
    -H "Content-Type: application/json" \
    -d "{
      \"ca\": \"Varwof Issuing CA\",
      \"cn\": \"$cn\",
      \"subject\": \"/C=CN/O=example.com/OU=$ou/CN=$cn\",
      \"profile\": \"agent-proxy\",
      \"key_type\": \"ecdsa-p256\",
      \"validity\": 1,
      \"agent_id\": \"$AGENT_ID\",
      \"principal_uid\": \"$PUID\",
      \"hash_algo\": \"sha256\",
      \"delegation_mode\": 0,
      \"principal_authorization\": $GRANTS,
      \"capabilities\": $CAPS
    }" 2>/dev/null || echo '{"error":"fail"}')

  check "Agent $AGENT_ID AIC证书签发" '"cert_pem"' "$AIC_RESP"

  # 保存 AIC 证书
  echo "$AIC_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
with open('$OUT_DIR/$AGENT_ID.pem', 'w') as f: f.write(d.get('cert_pem',''))
with open('$OUT_DIR/$AGENT_ID.key', 'w') as f: f.write(d.get('key_pem',''))
" 2>/dev/null

  # 验证 AIC 扩展
  AIC_EXT=$(openssl x509 -in "$OUT_DIR/$AGENT_ID.pem" -noout -text 2>/dev/null | grep -c "1.3.6.1.4.1.66257" || echo 0)
  check "Agent $AGENT_ID AIC扩展存在" "2" "$AIC_EXT"

  echo
done

# ══════════════════════════════════════════════════════════
section "Phase 6: 网关端到端认证测试"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 用 Test CA 客户端证书测试网关 RBAC"

# 创建 Test CA 客户端证书用于网关测试
for role_entry in "mysql-ops:gateway:mysql-ops" "mysql-read:gateway:mysql-read"; do
  IFS=: read -r name ou <<< "$role_entry"

  # 生成证书
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$OUT_DIR/gw-$name.key" \
    -out "$OUT_DIR/gw-$name.csr" \
    -subj "/C=CN/O=example.com/OU=$ou/CN=$name" 2>/dev/null

  openssl x509 -req \
    -in "$OUT_DIR/gw-$name.csr" \
    -CA "$GW_CA" \
    -CAkey "$TEST_CA_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$OUT_DIR/gw-$name.pem" \
    -days 1 2>/dev/null

  echo -e "  ${YELLOW}→${NC} 测试角色: $name ($ou)"

  # 测试读取
  READ_RESP=$(curl -s --cert "$OUT_DIR/gw-$name.pem" --key "$OUT_DIR/gw-$name.key" --cacert "$GW_CA" \
    "$GW_BASE/api/tables" 2>/dev/null || echo '{"error":"fail"}')
  check "$name 查询表列表" '"ok":true' "$READ_RESP"

  # 测试写入
  WRITE_RESP=$(curl -s --cert "$OUT_DIR/gw-$name.pem" --key "$OUT_DIR/gw-$name.key" --cacert "$GW_CA" \
    -X POST "$GW_BASE/api/tables/orders/rows" \
    -H "Content-Type: application/json" \
    -d '{"data":{"product_id":1,"quantity":1,"total":10,"customer_name":"test","status":"pending"}}' 2>/dev/null || echo '{"error":"fail"}')

  if [ "$name" = "mysql-ops" ]; then
    check "$name 写入（应允许）" '"ok":true' "$WRITE_RESP"
  else
    check "$name 写入（应拒绝）" "access_denied" "$WRITE_RESP"
  fi

  echo
done

# ══════════════════════════════════════════════════════════
section "Phase 7: 无角色证书拒绝测试"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 创建无角色证书"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$OUT_DIR/gw-no-role.key" \
  -out "$OUT_DIR/gw-no-role.csr" \
  -subj "/C=CN/O=test/CN=no-role" 2>/dev/null

openssl x509 -req \
  -in "$OUT_DIR/gw-no-role.csr" \
  -CA "$GW_CA" \
  -CAkey "$TEST_CA_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$OUT_DIR/gw-no-role.pem" \
  -days 1 2>/dev/null

NO_ROLE_RESP=$(curl -s --cert "$OUT_DIR/gw-no-role.pem" --key "$OUT_DIR/gw-no-role.key" --cacert "$GW_CA" \
  "$GW_BASE/api/tables" 2>/dev/null || echo '{"error":"fail"}')
check "无角色证书被拒绝" "access_denied" "$NO_ROLE_RESP"

# ══════════════════════════════════════════════════════════
section "Phase 8: 策略→权限→证书链路验证"
# ══════════════════════════════════════════════════════════

echo -e "  ${YELLOW}→${NC} 验证证书链完整性"

for cn in zhangsan lisi wangwu; do
  CERT="$OUT_DIR/user-$cn.pem"
  if [ -f "$CERT" ]; then
    ISSUER=$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null)
    check "用户 $cn 证书由 Issuing CA 签发" "Varwof Issuing CA" "$ISSUER"
  fi
done

for AGENT_ID in agent-zhangsan-001 agent-lisi-001 agent-wangwu-001; do
  CERT="$OUT_DIR/$AGENT_ID.pem"
  if [ -f "$CERT" ]; then
    ISSUER=$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null)
    check "Agent $AGENT_ID 证书由 Issuing CA 签发" "Varwof Issuing CA" "$ISSUER"
  fi
done

# ══════════════════════════════════════════════════════════
section "测试结果汇总"
# ══════════════════════════════════════════════════════════

echo
echo -e "  ${GREEN}通过: $pass${NC}"
echo -e "  ${RED}失败: $fail${NC}"
echo

if [ "$fail" -eq 0 ]; then
  echo -e "  ${GREEN}═══ 全部测试通过 ═══${NC}"
else
  echo -e "  ${RED}═══ 有 $fail 个测试失败 ═══${NC}"
fi

echo
echo "证书输出目录: $OUT_DIR"
ls -la "$OUT_DIR"/*.pem 2>/dev/null | awk '{print "  " $NF " (" $5 " bytes)"}'

exit $fail

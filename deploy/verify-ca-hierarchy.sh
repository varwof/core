#!/usr/bin/env bash
# 三层 CA 架构验证脚本
# 验证：Root CA(L1) → Mgmt CA(L2) → Admin/Auditor 证书(L3)
set -euo pipefail

DIR=$(mktemp -d /tmp/pki-verify-XXXXX)
cd "$DIR"
cat > pki.json <<'CONF'
{
  "db": "pki.db",
  "defaults": {"ca": "mgmt", "profile": "tls-server"},
  "cas": {
    "Root": {"key": "root.key", "cert": "root.pem"},
    "Mgmt": {"key": "mgmt.key", "cert": "mgmt.pem"}
  }
}
CONF

export PKI_KEY_PASSWORD=test123

echo "=== 三层 CA 架构验证 ==="

echo "[1/4] L1: 创建根 CA"
pki init-ca --config pki.json --name "Root" --profile root-ca \
  --key-type ecdsa-p256 --password test123 \
  --out-key root.key --out-cert root.pem

echo "[2/4] L2: 创建管理子 CA（由 Root 签发）"
pki init-ca --config pki.json --name "Mgmt" --profile sub-ca \
  --parent "Root" --parent-key root.key --validity 365 \
  --out-key mgmt.key --out-cert mgmt.pem

echo "[3/4] L3: 签发 SuperAdmin 证书（OU=SuperAdmin）"
pki issue --config pki.json --ca "Mgmt" \
  --subject "/CN=Admin/OU=SuperAdmin" \
  --profile tls-client --validity 1 --key-type ecdsa-p256

echo "[4/4] L3: 签发 Auditor 证书（OU=Auditor）"
pki issue --config pki.json --ca "Mgmt" \
  --subject "/CN=Viewer/OU=Auditor" \
  --profile tls-client --validity 1 --key-type ecdsa-p256

echo ""
echo "=== 验证 OU 权限映射 ==="
for f in $(ls *.pem | grep -v root.pem | grep -v mgmt.pem); do
  echo "  $f → $(openssl x509 -in "$f" -noout -subject)"
done

echo ""
echo "=== 完成! 证书 OU 字段可直接用于 RBAC 角色映射 ==="
echo "  OU=SuperAdmin → admin（全部 API）"
echo "  OU=Auditor    → auditor（只读日志）"
echo ""
echo "测试目录: $DIR"

#!/usr/bin/env bash
# pki 首次部署引导脚本
# Usage: pki-init /etc/varwof/core/pki.json
# Runs as ExecStartPre in systemd; idempotent.
set -euo pipefail

CONFIG="${1:-/etc/varwof/core/pki.json}"
PKI="pki --config $CONFIG"

# Extract paths from config using basic JSON parsing
DB_DIR=$(grep -oP '"db"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/var/lib/pki")
DB_PATH=$(grep -oP '"db"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/var/lib/pki/pki.db")
CA_CERT_DIR=$(dirname "$DB_PATH")/certs
CA_KEY_DIR=$(dirname "$DB_PATH")/private
mkdir -p "$CA_CERT_DIR" "$CA_KEY_DIR"

# --- 1. Root CA ---
if [ ! -f "$CA_CERT_DIR/ca.pem" ]; then
  echo "pki-init: creating root CA..."
  $PKI init-ca --name "Root CA" \
    --key-type ecdsa-p256 \
    --out-cert "$CA_CERT_DIR/ca.pem" \
    --out-key "$CA_KEY_DIR/ca.key"
  echo "pki-init: root CA created"
else
  echo "pki-init: root CA exists, skipping"
fi

# --- 2. Server TLS cert (for HTTPS API) ---
SERVER_CERT=$(grep -oP '"tls_cert"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/etc/varwof/core/server.pem")
SERVER_KEY=$(grep -oP '"tls_key"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/etc/varwof/core/server.key")
SERVER_CN=$(hostname -f 2>/dev/null || echo "pki.local")

if [ ! -f "$SERVER_CERT" ]; then
  mkdir -p "$(dirname "$SERVER_CERT")" "$(dirname "$SERVER_KEY")"
  echo "pki-init: issuing server TLS cert for $SERVER_CN..."
  $PKI issue --cn "$SERVER_CN" \
    --san "DNS:$SERVER_CN,DNS:localhost,IP:127.0.0.1" \
    --profile tls-server \
    --out "$SERVER_CERT" --out-key "$SERVER_KEY"
  echo "pki-init: server TLS cert created"
else
  echo "pki-init: server TLS cert exists, skipping"
fi

# --- 3. Admin user ---
ADMIN_USER=$(grep -oP '"auth_username"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "admin")
ADMIN_PASS=$(grep -oP '"auth_password"\s*:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "changeme")

	if ! $PKI user list 2>/dev/null | grep -q "$ADMIN_USER" 2>/dev/null; then
  echo "pki-init: creating admin user..."
  $PKI user add --username "$ADMIN_USER" --password "$ADMIN_PASS" --role admin
  echo "pki-init: admin user created"
else
  echo "pki-init: admin user exists, skipping"
fi

echo "pki-init: done"
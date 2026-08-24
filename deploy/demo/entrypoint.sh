#!/bin/sh
# pki demo entrypoint — auto-init CA + nginx cert on first run
set -e

PKI="/usr/local/bin/varwof"
DB="/var/lib/pki/pki.db"
CA_CERT="/var/lib/pki/ca.pem"
CA_KEY="/var/lib/private/ca.key"
NGINX_CERT="/certs/server.pem"
NGINX_KEY="/certs/server.key"
NGINX_CN="${PKI_NGINX_CN:-demo.pki.local}"
NGINX_SAN="${PKI_NGINX_SAN:-DNS:demo.pki.local,DNS:localhost,IP:127.0.0.1}"
CA_NAME="${PKI_CA_NAME:-Demo Root CA}"
CA_KEY_TYPE="${PKI_CA_KEY_TYPE:-ecdsa-p256}"
PASSWORD="${PKI_KEY_PASSWORD:-demo123}"

# If a subcommand is passed, skip init and exec directly
if [ $# -gt 0 ]; then
  exec "$@"
fi

# Write config
cat > /etc/varwof/core/pki.json <<EOF
{
  "db": "$DB",
  "cas": {
    "root": {
      "cert": "$CA_CERT",
      "key": "$CA_KEY"
    }
  },
  "defaults": {
    "ca": "root",
    "profile": "tls-server",
    "default_org": "PKI Demo"
  },
  "serve": {
    "listen": ":4430",
    "api_addr": ":8443",
    "auth_username": "admin",
    "auth_password": "Admin123"
  }
}
EOF

# Init CA if not exists
if [ ! -f "$DB" ]; then
  echo "entrypoint: initializing root CA..."
  mkdir -p /var/lib/private
  $PKI --config /etc/varwof/core/pki.json ca init \
    --name "$CA_NAME" \
    --key-type "$CA_KEY_TYPE" \
    --password "$PASSWORD" \
    --out-cert "$CA_CERT" \
    --out-key "$CA_KEY"
  echo "entrypoint: root CA created"
fi

# Issue nginx cert if not exists
if [ ! -f "$NGINX_CERT" ]; then
  echo "entrypoint: issuing nginx TLS cert for $NGINX_CN..."
  mkdir -p /certs
  $PKI --config /etc/varwof/core/pki.json issue \
    --cn "$NGINX_CN" \
    --san "$NGINX_SAN" \
    --profile tls-server \
    --out "$NGINX_CERT" \
    --out-key "$NGINX_KEY"
  echo "entrypoint: nginx TLS cert issued"
fi

# Create admin user if not exists
COUNT=$($PKI --config /etc/varwof/core/pki.json user list 2>/dev/null | wc -l)
if [ "$COUNT" -le 1 ]; then
  echo "entrypoint: creating admin user..."
  $PKI --config /etc/varwof/core/pki.json user add \
    --username admin --password Admin123 --role admin
fi

echo "entrypoint: starting varwof serve api..."
exec $PKI --config /etc/varwof/core/pki.json serve api

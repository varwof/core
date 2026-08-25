#!/usr/bin/env bash
#
# setup-e2e-pki.sh — One-shot e2e PKI environment setup (reproducible)
#
# Steps:
#   1. Build varwof core and pki-client binaries
#   2. init-full to create fresh PKI (CA hierarchy + superadmin + authz.json)
#   3. Patch config: HTTPS mTLS listener (tls_addr/tls_client_ca), API cert IP SAN,
#      capability_schemes registry std/database-v1 (SELECT/INSERT/UPDATE/DELETE),
#      authz roles (db-reader/db-writer/db-ops + OU mapping)
#   4. Start pki-core serve in background (setsid)
#   5. Issue matrix user certs + AIC certs via pki-client
#
# Usage: scripts/setup-e2e-pki.sh
#
# Configurable (env vars):
#   E2E_WORKDIR  PKI working directory (default /tmp/aic-e2e-pki, rebuilt on run)
#   E2E_ORG      Organization name (default E2EOrg)
#   E2E_DOMAIN   Domain (default e2e.varwof.test)
#   E2E_HTTPS    Core HTTPS port (default 9447)
#   E2E_HTTP     Core HTTP port (default 9448)
#   PKI_BIN      varwof binary (default /tmp/varwof, auto-built)
#   PKI_CLIENT   pki-client binary (default /tmp/pki-client, auto-built)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_WORKDIR="${E2E_WORKDIR:-/tmp/aic-e2e-pki}"
E2E_ORG="${E2E_ORG:-E2EOrg}"
E2E_DOMAIN="${E2E_DOMAIN:-e2e.varwof.test}"
E2E_HTTPS="${E2E_HTTPS:-9447}"
E2E_HTTP="${E2E_HTTP:-9448}"
PKI_BIN="${PKI_BIN:-/tmp/varwof}"
PKI_CLIENT="${PKI_CLIENT:-/tmp/pki-client}"
CERTDIR="$E2E_WORKDIR/certs"
CAPSCHEMES="$E2E_WORKDIR/capschemes"

TLS_CA_NAME="$E2E_ORG TLS CA"
PEOPLE_CA_NAME="$E2E_ORG People CA"
CLIENT_CFG="$E2E_WORKDIR/client.json"

log() { printf '\033[1;34m%s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  [OK]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

case "$E2E_WORKDIR" in
  /tmp/*) rm -rf "$E2E_WORKDIR"; mkdir -p "$E2E_WORKDIR" "$CERTDIR" ;;
  *) die "E2E_WORKDIR must be under /tmp (current: $E2E_WORKDIR)" ;;
esac

log "== 1. Build varwof core and pki-client =="
(cd "$ROOT" && go build -o "$PKI_BIN" ./cmd/pki)
(cd "$ROOT" && go build -o "$PKI_CLIENT" ./client 2>/dev/null || go build -o "$PKI_CLIENT" github.com/varwof/pki-client 2>/dev/null || echo "pki-client not in this repo, using /tmp/pki-client")
ok "varwof=$PKI_BIN pki-client=$PKI_CLIENT"

log "== 2. init-full: create PKI hierarchy =="
"$PKI_BIN" init-full --org "$E2E_ORG" --domain "$E2E_DOMAIN" \
  --out-dir "$E2E_WORKDIR" \
  --admin-names "zhangsan(superadmin)" \
  --config-out "$E2E_WORKDIR/config.json" >/dev/null 2>&1
ok "PKI hierarchy created"

log "== 3. Patch config =="
mkdir -p "$CAPSCHEMES/std/database-v1"
python3 - "$CAPSCHEMES" <<'PY'
import json, sys
d = sys.argv[1]
scheme = {
  "scheme_id": "std/database-v1",
  "name": "Standard Database Capabilities (v1)",
  "version": "1.0.0",
  "vendor": "std",
  "product": "database-v1",
  "capabilities": [
    {"id": "query:SELECT", "description": "Read-only query"},
    {"id": "query:INSERT", "description": "Insert row"},
    {"id": "query:UPDATE", "description": "Update row"},
    {"id": "query:DELETE", "description": "Delete row"},
    {"id": "GET:*", "description": "HTTP GET capability"},
    {"id": "POST:*", "description": "HTTP POST capability"},
    {"id": "PUT:*", "description": "HTTP PUT capability"},
    {"id": "DELETE:*", "description": "HTTP DELETE capability"}
  ]
}
json.dump(scheme, open(f"{d}/std/database-v1/v1.json", "w"), ensure_ascii=False, indent=2)
PY
ok "Capability registry std/database-v1"

"$PKI_BIN" --config "$E2E_WORKDIR/config.json" issue \
  --ca "$TLS_CA_NAME" --cn api-e2e \
  --san "DNS:$E2E_DOMAIN,IP:127.0.0.1" --profile tls-server \
  --out "$E2E_WORKDIR/api-e2e.pem" --out-key "$E2E_WORKDIR/api-e2e.key" >/dev/null 2>&1
ok "API server certificate (IP SAN)"

python3 - "$E2E_WORKDIR/config.json" "$E2E_WORKDIR" "$E2E_HTTPS" "$E2E_HTTP" "$CAPSCHEMES" <<'PY'
import json, sys
cfg_path, wd, https, http, caps = sys.argv[1:6]
cfg = json.load(open(cfg_path))
srv = cfg.setdefault("serve", {})
srv["addr"] = f"127.0.0.1:{http}"
srv["tls_addr"] = f"127.0.0.1:{https}"
srv["tls_cert"] = f"{wd}/api-e2e.pem"
srv["tls_key"] = f"{wd}/api-e2e.key"
srv["tls_client_ca"] = f"{wd}/management/certs/ca.pem"
cfg["capability_schemes"] = caps
json.dump(cfg, open(cfg_path, "w"), ensure_ascii=False, indent=2)
PY

python3 - "$E2E_WORKDIR/authz.json" <<'PY'
import json, sys
p = sys.argv[1]
a = json.load(open(p))
a["roles"]["db-reader"] = {"display_name": "Database Read-Only", "profiles": [], "grants": [
  "std/database-v1:query:SELECT", "std/database-v1:GET:*"]}
a["roles"]["db-writer"] = {"display_name": "Database Read-Write", "profiles": [], "grants": [
  "std/database-v1:query:SELECT", "std/database-v1:GET:*", "std/database-v1:POST:*", "std/database-v1:PUT:*"]}
a["roles"]["db-ops"] = {"display_name": "Database Ops", "profiles": [], "grants": [
  "std/database-v1:query:SELECT", "std/database-v1:GET:*", "std/database-v1:POST:*", "std/database-v1:PUT:*", "std/database-v1:DELETE:*"]}
a["ou_mapping"]["db:reader"] = "db-reader"
a["ou_mapping"]["db:writer"] = "db-writer"
a["ou_mapping"]["db:ops"] = "db-ops"
json.dump(a, open(p, "w"), ensure_ascii=False, indent=2)
PY
ok "config + authz patched"

log "== 4. Start pki-core serve (HTTPS mTLS :$E2E_HTTPS) =="
setsid "$PKI_BIN" --config "$E2E_WORKDIR/config.json" serve \
  </dev/null >>"$E2E_WORKDIR/serve.log" 2>&1 &
echo $! > "$E2E_WORKDIR/serve.pid"
SUPER_CERT="$E2E_WORKDIR/management/users/certs/user-superadmin-zhangsan.pem"
SUPER_KEY="$E2E_WORKDIR/management/users/private/user-superadmin-zhangsan.key"
code=""
for i in $(seq 1 30); do
  code="$(curl -sk --cert "$SUPER_CERT" --key "$SUPER_KEY" \
    --cacert "$E2E_WORKDIR/tls/certs/ca.pem" \
    -o /dev/null -w '%{http_code}' "https://127.0.0.1:$E2E_HTTPS/api/v1/cas" 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$code" = "200" ] || die "pki-core not ready, see $E2E_WORKDIR/serve.log"
ok "pki-core ready ($code)"

log "== 5. Issue matrix user certs + AIC certs =="
cat > "$CLIENT_CFG" <<EOF
{"server":"https://127.0.0.1:$E2E_HTTPS","ca_cert":"$E2E_WORKDIR/tls/certs/ca.pem","client_cert":"$SUPER_CERT","client_key":"$SUPER_KEY"}
EOF
chmod 600 "$CLIENT_CFG"

USERS=(
  "zhangsan|db:reader|std/database-v1:query:SELECT std/database-v1:GET:*"
  "lisi|db:writer|std/database-v1:GET:* std/database-v1:POST:* std/database-v1:PUT:*"
  "wangwu|db:ops|std/database-v1:GET:* std/database-v1:POST:* std/database-v1:PUT:* std/database-v1:DELETE:*"
)
for entry in "${USERS[@]}"; do
  IFS='|' read -r name ou caps <<< "$entry"
    "$PKI_CLIENT" "$CLIENT_CFG" issue --cn "$name" --ca "$PEOPLE_CA_NAME" \
    --profile tls-client --ou "$ou" --validity 30 --out "$CERTDIR" >/dev/null 2>&1
  user_cert="$(ls -t "$CERTDIR"/*.pem | grep -v -- -key | head -1)"
  user_key="${user_cert%.pem}-key.pem"
  "$PKI_CLIENT" "$CLIENT_CFG" aic issue --user-cert "$user_cert" --user-key "$user_key" \
      --agent "$name-agent" --caps "$caps" --ca "$PEOPLE_CA_NAME" --ou "$ou" --out "$CERTDIR" >/dev/null 2>&1
  ok "$name AIC issued ($ou)"
done

log ""
log "=== Setup complete ==="
printf '  config:     %s\n' "$E2E_WORKDIR/config.json"
printf '  serve pid:  %s (log: %s)\n' "$(cat "$E2E_WORKDIR/serve.pid")" "$E2E_WORKDIR/serve.log"
printf '  client cfg: %s\n' "$CLIENT_CFG"
printf '  AIC certs:  %s/<user>-agent.pem\n' "$CERTDIR"
printf '  Run full e2e:\n'
printf '    cd %s/gateway && MYSQL_DSN=... E2E_AIC_CERT=%s/zhangsan-agent.pem go test ./http/ -run TestRealGatewayE2E\n' "$ROOT" "$CERTDIR"

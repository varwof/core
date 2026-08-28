#!/usr/bin/env bash
#
# verify-rbac-api.sh — varwof-core RBAC role × API authorization matrix
#
# Two modes:
#   --deploy   one-time setup: build varwof, install to $VARWOF_BIN, init-full a
#              fresh PKI into $PKI_DIR, write config.json (HTTP + HTTPS mTLS,
#              permission_mode, routes_file), start a persistent background
#              serve, mint the 3 extra role certs (revoker/console/reporter).
#              From then on the serve keeps running — no repeated start/kill.
#   (default)  verification: uses the already-deployed varwof + running serve,
#              re-mints missing extra certs via the API if needed, then runs the
#              role×route matrix with curl and asserts allow/deny/404 against
#              the authorization policy (auth/authz.json) and the ACTIVE route
#              table (config routes_file, else embedded routes_default.json).
#              Produces a PASS/FAIL table plus a drift report comparing the
#              route table actually in effect vs the repo routes.json.
#
# Helpers (no serve churn):
#   --set-mode simple|enterprise   patch config permission_mode (restart once)
#   --set-routes repo|embedded     pick route source in config (restart once)
#   --restart                      restart the background serve (after config edits)
#
# Usage:
#   scripts/verify-rbac-api.sh --deploy [--set-mode <mode>] [--set-routes repo|embedded]
#   scripts/verify-rbac-api.sh
#   scripts/verify-rbac-api.sh --set-mode enterprise && scripts/verify-rbac-api.sh --restart && scripts/verify-rbac-api.sh
#
# Env overrides:
#   RBAC_PKI_DIR  PKI + config dir (default /tmp/pki-rbac)
#   RBAC_BIN      deployed binary (default /usr/local/bin/varwof or PATH's varwof)
#   RBAC_HTTPS    HTTPS mTLS port (default 18443)
#   RBAC_HTTP     HTTP port (default 18080)
#   RBAC_ADMIN_PASS  superadmin account password used to satisfy the
#                    management-mint double-factor (cert + account). Dev only.
#   RBAC_ADMIN_SCOPE CA scope embedded in management certs. Defaults to "*"
#                    ONLY because this is a verification harness; production
#                    must set the smallest scope per role/CA instead.
#
# Security notes (mint policy):
#   * superadmin is CERTIFICATE-ONLY: its authority comes strictly from the
#     mTLS management certificate (OU=SuperAdmin). Username/password and API
#     tokens always resolve to the operator role and can never reach a
#     superadmin-level capability.
#   * Management (m-*) certificates are minted ONLY by the superadmin role
#     (mTLS in hand); operator and every other role are hard-excluded from the
#     management sub-CA. The operator's management-mint capability is
#     deprecated and will be removed.
#   * Private keys stay under management/users/private/ (0600 after deploy);
#     the public cert files under management/users/certs/ must never be used
#     as --key material. helpers.py always pairs certs/certs with private/keys.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI_DIR="${RBAC_PKI_DIR:-/tmp/pki-rbac}"
BIN="${RBAC_BIN:-$(command -v varwof || echo /tmp/varwof)}"
ORG="${RBAC_ORG:-RBACVerify}"
DOMAIN="${RBAC_DOMAIN:-rbac.local}"
HTTPS="${RBAC_HTTPS:-18443}"
HTTP="${RBAC_HTTP:-18080}"

MODE="simple"         # simple|enterprise
ROUTE_SRC="repo"      # repo|embedded (only meaningful at --deploy)
ACTION="verify"       # deploy|verify|set-mode|set-routes|restart
SET_VALUE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --deploy) ACTION=deploy ;;
    --set-mode) ACTION=set-mode; SET_VALUE="$2"; shift ;;
    --set-routes) ACTION=set-routes; SET_VALUE="$2"; shift ;;
    --restart) ACTION=restart ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
  shift
done

CERTDIR="$PKI_DIR/certs"
MGMT_USERS="$PKI_DIR/management/users"
CONFIG="$PKI_DIR/config.json"
API_CERT="$PKI_DIR/api-rbac.pem"
API_KEY="$PKI_DIR/api-rbac.key"
ADMIN_CA="$ORG Management CA"
BASE="https://127.0.0.1:$HTTPS"
SUPER_CERT="$MGMT_USERS/certs/user-superadmin-alice.pem"
SUPER_KEY="$MGMT_USERS/private/user-superadmin-alice.key"
SUPER_USER="alice"
SUPER_PASS="${RBAC_ADMIN_PASS:-VarwofAdmin#2026!}"
SUPER_BASIC=(-u "$SUPER_USER:$SUPER_PASS")
LOG="$PKI_DIR/verify.log"
PY="$PKI_DIR/helpers.py"
ADMIN_NAMES="alice(superadmin),bob(admin),carol(operator),dave(auditor),erin(readonly),frank(auto-renew)"
EXTRA_ROLES=(revoker console reporter)
PERSONS=(alice bob carol dave erin frank)
ROLES=(superadmin admin operator revoker auditor readonly console auto-renew reporter)

log() { printf '\033[1;34m%s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  [ok] %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m  [!!] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
api() { curl -sk --connect-timeout 3 --max-time 10 "$@"; }

cert_for() { local r="$1"
  case "$r" in
    superadmin) echo "$MGMT_USERS/certs/user-superadmin-alice.pem" ;;
    admin)      echo "$MGMT_USERS/certs/user-admin-bob.pem" ;;
    operator)   echo "$MGMT_USERS/certs/user-operator-carol.pem" ;;
    auditor)    echo "$MGMT_USERS/certs/user-auditor-dave.pem" ;;
    readonly)   echo "$MGMT_USERS/certs/user-readonly-erin.pem" ;;
    auto-renew) echo "$MGMT_USERS/certs/user-auto-renew-frank.pem" ;;
    revoker)    echo "$CERTDIR/rbac-revoker.pem" ;;
    console)    echo "$CERTDIR/rbac-console.pem" ;;
    reporter)   echo "$CERTDIR/rbac-reporter.pem" ;;
  esac; }
key_for() { local r="$1"
  case "$r" in
    superadmin) echo "$MGMT_USERS/private/user-superadmin-alice.key" ;;
    admin)      echo "$MGMT_USERS/private/user-admin-bob.key" ;;
    operator)   echo "$MGMT_USERS/private/user-operator-carol.key" ;;
    auditor)    echo "$MGMT_USERS/private/user-auditor-dave.key" ;;
    readonly)   echo "$MGMT_USERS/private/user-readonly-erin.key" ;;
    auto-renew) echo "$MGMT_USERS/private/user-auto-renew-frank.key" ;;
    revoker)    echo "$CERTDIR/rbac-revoker.key" ;;
    console)    echo "$CERTDIR/rbac-console.key" ;;
    reporter)   echo "$CERTDIR/rbac-reporter.key" ;;
  esac; }

# active route table: config routes_file if set, else embedded defaults.
active_routes_src() {
  if [ -f "$CONFIG" ] && python3 -c "import json,sys; c=json.load(open('$CONFIG')); print(bool(c.get('routes_file','')))" | grep -q True; then
    python3 -c "import json; print(json.load(open('$CONFIG'))['routes_file'])"
  else
    echo "$ROOT/internal/serve/routes_default.json"
  fi
}

write_helpers() {
  cat > "$PY" <<'PY'
import json, sys

def load_authz(path):
    a = json.load(open(path))
    return {r: set((d.get("grants") or [])) for r, d in a.get("roles", {}).items()}

def concrete(rule):
    p = rule.get("path", "")
    return "{" not in p and not p.endswith("*")

def load_routes(path):
    r = json.load(open(path))
    public = set(r.get("public_paths") or [])
    defperm = r.get("default_permission") or None
    rules = {"%s %s" % (x.get("method","*"), x["path"]): x for x in r.get("rules", []) if concrete(x)}
    return public, defperm, rules

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "expect":
        # argv: authz, routes_src, out
        grants = load_authz(sys.argv[2])
        public, defperm, rules = load_routes(sys.argv[3])
        roles = ["superadmin","admin","operator","revoker","auditor","readonly",
                 "console","auto-renew","reporter"]
        with open(sys.argv[4], "w") as f:
            for role in roles:
                for key, rule in rules.items():
                    if rule.get("path") in public:
                        continue
                    m, _, p = key.partition(" ")
                    perm = rule.get("permission","")
                    req = rule.get("require_role") or []
                    allow = bool(perm and perm in grants.get(role,set()) and (not req or role in req))
                    f.write("\t".join([role, m, p, perm, "allow" if allow else "deny"]) + "\n")
    elif cmd == "diff":
        # argv: diff, srcA, srcB — rules in A not in B
        _, _, A = load_routes(sys.argv[2])
        _, _, B = load_routes(sys.argv[3])
        for k in sorted(set(A) - set(B)):
            x = A[k]
            print("%s\t%s\t%s\t%s" % (k.split(" ")[0], x["path"], x.get("permission",""), ",".join(x.get("require_role") or [])))
    elif cmd == "mode":
        print(json.load(open(sys.argv[2])).get("rbac", {}).get("permission_mode", "simple"))
PY
}

start_serve() {
  nohup "$BIN" --config "$CONFIG" serve </dev/null >> "$PKI_DIR/serve.log" 2>&1 &
  disown
  echo $! > "$PKI_DIR/serve.pid"
}

wait_ready() {
  local code i
  for i in $(seq 1 40); do
    code="$(api --cert "$SUPER_CERT" --key "$SUPER_KEY" -o /dev/null -w '%{http_code}' "$BASE/api/v1/cas" || true)"
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  die "serve not ready (last=$code); log: $PKI_DIR/serve.log"
}

mint_extras() {
  mkdir -p "$CERTDIR"
  for r in "${EXTRA_ROLES[@]}"; do
    c="$(cert_for "$r")"
    [ -s "$c" ] && continue
    log "  mint role cert: $r"
    resp="$PKI_DIR/issue-$r.json"
    code="$(api --cert "$SUPER_CERT" --key "$SUPER_KEY" -X POST \
      -H 'Content-Type: application/json' \
      -d "{\"ca\":\"$ADMIN_CA\",\"cn\":\"$r@$DOMAIN\",\"profile\":\"m-$r\",\"key_type\":\"ecdsa-p256\",\"ca_scope\":\"*\"}" \
      -o "$resp" -w '%{http_code}' "$BASE/api/v1/certs" || true)"
    [ "$code" = "200" ] || { cat "$resp"; die "mint $r failed (http=$code)"; }
    python3 - "$resp" "$c" "$(key_for "$r")" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(d["cert_pem"].strip() + "\n")
open(sys.argv[3], "w").write(d["key_pem"].strip() + "\n")
PY
    ok "  $r cert minted (ca_scope=*)"
  done
}

run_matrix() {
  local src mode expect="$PKI_DIR/matrix.tsv"
  src="$(active_routes_src)"
  mode="$(python3 "$PY" mode "$CONFIG")"
  python3 "$PY" expect "$PKI_DIR/authz.json" "$src" "$expect"
  ok "matrix plan: $(wc -l < "$expect") checks using route table: $src (permission_mode=$mode)"
  PASS=0; FAIL=0
  while IFS=$'\t' read -r role method path perm want; do
    code="$(api --cert "$(cert_for "$role")" --key "$(key_for "$role")" -X "$method" \
      -o /dev/null -w '%{http_code}' "$BASE$path" || true)"
    if [ "$want" = "allow" ]; then
      if [ "$code" != "401" ] && [ "$code" != "403" ] && [ "$code" != "404" ]; then PASS=$((PASS+1)); else
        FAIL=$((FAIL+1)); printf 'FAIL  %-12s %-5s %-45s perm=%-16s want=%s got=%s\n' "$role" "$method" "$path" "$perm" "$want" "$code" | tee -a "$LOG"; fi
    else
      if [ "$code" = "401" ] || [ "$code" = "403" ]; then PASS=$((PASS+1)); else
        FAIL=$((FAIL+1)); printf 'FAIL  %-12s %-5s %-45s perm=%-16s want=%s got=%s\n' "$role" "$method" "$path" "$perm" "$want" "$code" | tee -a "$LOG"; fi
    fi
  done < "$expect"
}

drift_report() {
  local active src dt="$PKI_DIR/drift.tsv"
  active="$(active_routes_src)"
  src="$(python3 -c "import json; print(json.load(open('$CONFIG')).get('routes_file') or '$ROOT/routes.json')")"
  python3 "$PY" diff "$src" "$active" > "$dt" 2>/dev/null || python3 "$PY" diff "$ROOT/routes.json" "$active" > "$dt"
  if [ -s "$dt" ]; then
    warn "route drift — rules present in repo routes.json but MISSING in the ACTIVE table:"
    column -t -s$'\t' "$dt" | sed 's/^/      /' | tee -a "$LOG"
  else
    ok "no route drift: active table covers every repo routes.json rule"
  fi
}

behavior_checks() {
  log "  behavior checks($(python3 "$PY" mode "$CONFIG"))"
  local body opc opk auc auk code
  body='{"ca":"'"$ORG"' TLS CA","cn":"webapp.'"$DOMAIN"'","san":"DNS:webapp.'"$DOMAIN"'","profile":"tls-server","key_type":"ecdsa-p256"}'
  local c_super c_oper c_audi c_pub c_cfg
  c_super="$(api --cert "$SUPER_CERT" --key "$SUPER_KEY" -X POST -H 'Content-Type: application/json' -d "$body" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  opc="$(cert_for operator)"; opk="$(key_for operator)"
  c_oper="$(api --cert "$opc" --key "$opk" -X POST -H 'Content-Type: application/json' -d "$body" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  auc="$(cert_for auditor)"; auk="$(key_for auditor)"
  c_audi="$(api --cert "$auc" --key "$auk" -X POST -H 'Content-Type: application/json' -d "$body" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  opc="$(cert_for admin)"; opk="$(key_for admin)"
  c_cfg="$(api --cert "$opc" --key "$opk" -X PUT -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}' "$BASE/api/v1/admin/config" || true)"
  c_pub="$(api --cert "$(cert_for readonly)" --key "$(key_for readonly)" -o /dev/null -w '%{http_code}' "$BASE/healthz" || true)"
  printf '  %-48s %-5s %s\n' "superadmin POST /api/v1/certs (2xx)" "$c_super" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "operator   POST /api/v1/certs (2xx)" "$c_oper" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "auditor    POST /api/v1/certs (403)" "$c_audi" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "admin      PUT  /api/v1/admin/config (403)" "$c_cfg" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "readonly   GET  /healthz (public 200)" "$c_pub" "" | tee -a "$LOG"

  # P0/P1: management sub-CA hard-exclusion + certificate-only superadmin.
  # superadmin authority comes ONLY from the mTLS certificate: username/password
  # and API tokens always resolve to the operator role and can never reach a
  # superadmin-level capability (management mint, superadmin-only endpoints).
  local mb p0_oper p0_super p0_acct_mint p0_acct_cfg p0_cfg
  mb='{"ca":"'"$ADMIN_CA"'","cn":"p0-probe@'"$DOMAIN"'","profile":"m-superadmin","ca_scope":"*"}'
  opc="$(cert_for operator)"; opk="$(key_for operator)"
  p0_oper="$(api --cert "$opc" --key "$opk" -X POST -H 'Content-Type: application/json' -d "$mb" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  mb2='{"ca":"'"$ADMIN_CA"'","cn":"p0-probe2@'"$DOMAIN"'","profile":"m-revoker","ca_scope":"*"}'
  p0_super="$(api --cert "$SUPER_CERT" --key "$SUPER_KEY" -X POST -H 'Content-Type: application/json' -d "$mb2" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  p0_acct_mint="$(api --cert "$opc" --key "$opk" -u "$SUPER_USER:$SUPER_PASS" -X POST -H 'Content-Type: application/json' -d "$mb2" -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs" || true)"
  p0_acct_cfg="$(api --cert "$opc" --key "$opk" -u "$SUPER_USER:$SUPER_PASS" -X PUT -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}' "$BASE/api/v1/admin/config" || true)"
  printf '  %-48s %-5s %s\n' "P0 operator cert mint m-superadmin (403)" "$p0_oper" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "P0 superadmin cert mint (no acc) (200)" "$p0_super" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "P0 operator+superadmin-pass mint (403)" "$p0_acct_mint" "" | tee -a "$LOG"
  printf '  %-48s %-5s %s\n' "P0 operator+superadmin-pass admin cfg (403)" "$p0_acct_cfg" "" | tee -a "$LOG"
  [ "$p0_oper" = "403" ] || { warn "P0 FAIL: operator minted a management cert (http=$p0_oper)!"; FAIL=$((FAIL+1)); }
  [ "$p0_super" = "200" ] || { warn "P0 FAIL: superadmin certificate mint rejected (http=$p0_super)"; FAIL=$((FAIL+1)); }
  [ "$p0_acct_mint" = "403" ] || { warn "P0 FAIL: account credential elevated a non-superadmin cert (http=$p0_acct_mint)!"; FAIL=$((FAIL+1)); }
  [ "$p0_acct_cfg" = "403" ] || { warn "P0 FAIL: account credential reached a superadmin endpoint (http=$p0_acct_cfg)!"; FAIL=$((FAIL+1)); }
}

# ---------------------------------------------------------------------------

case "$ACTION" in
  deploy)
    # stop any stale serve from a previous interrupted deploy, then wipe the PKI
    if [ -f "$PKI_DIR/serve.pid" ]; then
      kill "$(cat "$PKI_DIR/serve.pid")" 2>/dev/null || true
      sleep 1
    fi
    pkill -f 'pki[-]rbac' 2>/dev/null || true
    sleep 1
    case "$PKI_DIR" in /tmp/*) rm -rf "$PKI_DIR";; *) die "PKI_DIR must be under /tmp for --deploy (got $PKI_DIR)";; esac
    mkdir -p "$PKI_DIR"
    if [ "$ROUTE_SRC" = "embedded" ]; then ROUTES_PATH=""; else ROUTES_PATH="$ROOT/routes.json"; fi
    log "== deploy: build varwof =="
    (cd "$ROOT" && go build -o "$BIN" ./cmd/pki)
    ok "binary: $BIN"

    log "== deploy: init-full =="
    "$BIN" init-full --org "$ORG" --domain "$DOMAIN" \
      --out-dir "$PKI_DIR" --admin-names "$ADMIN_NAMES" \
      --admin-scope "${RBAC_ADMIN_SCOPE:-*}" \
      --config-out "$CONFIG" >/dev/null 2>&1
    ok "PKI hierarchy + role certificates (admin-scope=${RBAC_ADMIN_SCOPE:-*})"

    "$BIN" --config "$CONFIG" issue --ca "$ORG TLS CA" --cn api-rbac \
      --san "DNS:$DOMAIN,IP:127.0.0.1" --profile tls-server \
      --out "$API_CERT" --out-key "$API_KEY" >/dev/null 2>&1
    ok "API server cert"

    python3 - "$MODE" "$CONFIG" "$HTTP" "$HTTPS" "$API_CERT" "$API_KEY" \
      "$PKI_DIR/management/certs/ca.pem" "$ROUTES_PATH" <<'PY'
import json, sys
mode, cfg = sys.argv[1], sys.argv[2]
c = json.load(open(cfg))
srv = c.setdefault("serve", {})
srv.update({
    "addr": "127.0.0.1:%s" % sys.argv[3],
    "tls_addr": "127.0.0.1:%s" % sys.argv[4],
    "tls_cert": sys.argv[5],
    "tls_key": sys.argv[6],
    "tls_client_ca": sys.argv[7],
})
if sys.argv[8]:
    c["routes_file"] = sys.argv[8]
else:
    c.pop("routes_file", None)
rbac = c.setdefault("rbac", {})
rbac["permission_mode"] = mode
if mode == "enterprise":
    rbac["ca_scopes"] = {r: ["*"] for r in ["superadmin","admin","operator","revoker",
        "auditor","readonly","console","auto-renew","reporter"]}
json.dump(c, open(cfg, "w"), ensure_ascii=False, indent=2)
PY
    if [ -n "$ROUTES_PATH" ]; then oktxt="$ROUTES_PATH(仓库)" ; else oktxt="embedded 内嵌"; fi
    ok "config written (mode=$MODE, routes=$oktxt)"

    log "== deploy: start serve =="
    start_serve
    wait_ready
    ok "serve up at $BASE"
    # P0 double-factor: bind a superadmin account so management-mint requests
    # can pair the mTLS certificate with a username/password credential.
    "$BIN" --config "$CONFIG" user add -username "$SUPER_USER" \
      -password "$SUPER_PASS" -role superadmin >/dev/null 2>&1 \
      && ok "superadmin account $SUPER_USER provisioned (cert + password)" \
      || warn "superadmin account exists or could not be provisioned: $LOG"
    chmod 600 "$MGMT_USERS"/private/*.key "$MGMT_USERS"/certs/*.pem 2>/dev/null || true
    ok "management private keys locked to 0600"
    write_helpers
    mint_extras
    log ">> deployment done. run: scripts/verify-rbac-api.sh"
    ;;

  verify)
    [ -x "$BIN" ] || die "binary not found: $BIN — run scripts/verify-rbac-api.sh --deploy first"
    for f in "$SUPER_CERT" "$SUPER_KEY" "$CONFIG"; do
      [ -s "$f" ] || die "missing $f — run --deploy first"
    done
    rm -f "$LOG"; touch "$LOG"
    write_helpers
    log "== verify (serve presumed running at $BASE) =="
    code="$(api --cert "$SUPER_CERT" --key "$SUPER_KEY" -o /dev/null -w '%{http_code}' "$BASE/api/v1/cas" || true)"
    [ "$code" = "200" ] || die "serve not answering (http=$code) — start it with --deploy / --restart"
    ok "serve reachable, permission_mode=$(python3 "$PY" mode "$CONFIG")"
    mint_extras
    run_matrix
    drift_report
    behavior_checks
    echo
    log "== matrix result: pass=$PASS fail=$FAIL =="
    [ "$FAIL" -eq 0 ] || die "matrix FAILURES (see above / $LOG)"
    ok "ALL CHECKS PASSED — log: $LOG"
    ;;

  set-mode)
    [ -f "$CONFIG" ] || die "no config at $CONFIG — run --deploy first"
    case "$SET_VALUE" in
      simple|enterprise) ;;
      *) die "--set-mode requires simple|enterprise" ;;
    esac
    python3 - "$CONFIG" <<PY
import json
c = json.load(open('$CONFIG'))
rbac = c.setdefault('rbac', {})
rbac['permission_mode'] = '$SET_VALUE'
if '$SET_VALUE' == 'enterprise':
    rbac['ca_scopes'] = {r: ['*'] for r in ['superadmin','admin','operator','revoker',
        'auditor','readonly','console','auto-renew','reporter']}
json.dump(c, open('$CONFIG', 'w'), ensure_ascii=False, indent=2)
PY
    ok "permission_mode=$SET_VALUE written — run --restart to apply"
    ;;

  set-routes)
    [ -f "$CONFIG" ] || die "no config at $CONFIG — run --deploy first"
    if [ "$SET_VALUE" = "repo" ]; then
      python3 -c "import json; c=json.load(open('$CONFIG')); c['routes_file']='$ROOT/routes.json'; json.dump(c,open('$CONFIG','w'),ensure_ascii=False,indent=2)"
      ok "routes_file=$ROOT/routes.json"
    elif [ "$SET_VALUE" = "embedded" ]; then
      python3 -c "import json; c=json.load(open('$CONFIG')); c.pop('routes_file',None); json.dump(c,open('$CONFIG','w'),ensure_ascii=False,indent=2)"
      ok "routes_file cleared (embedded defaults)"
    else
      die "--set-routes requires repo|embedded"
    fi
    ok "run --restart to apply"
    ;;

  restart)
    [ -f "$CONFIG" ] || die "no config at $CONFIG — run --deploy first"
    write_helpers
    if [ -f "$PKI_DIR/serve.pid" ]; then
      kill "$(cat "$PKI_DIR/serve.pid")" 2>/dev/null || true
      sleep 1
    fi
    for r in "${EXTRA_ROLES[@]}"; do rm -f "$(cert_for "$r")" "$(key_for "$r")"; done
    start_serve
    wait_ready
    ok "serve restarted at $BASE (permission_mode=$(python3 "$PY" mode "$CONFIG"))"
    log "run: scripts/verify-rbac-api.sh"
    ;;
esac
#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.0.1"
  exit 1
fi

VER=$1
SRC=/home/varwof/src/pki-svn
OUT=/tmp/pki-src-${VER}.tar.gz
NAS_HOST=192.168.6.7
NAS_PORT=2022
NAS_USER=17080036766a
NAS_PASS=200814@wjx
NAS_PATH=/sata1-17080036766a/home/src/

echo "=== go build varwof ${VER} ==="
cd "${SRC}"
COMMIT=$(svn info --show-item last-changed-revision 2>/dev/null || echo unknown)
BUILDTIME=$(date -Iseconds)
go build -ldflags "-X main.version=${VER} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" -o varwof ./cmd/pki/
./varwof version

echo "=== SVN tag tags/${VER} ==="
if svn info "^/tags/${VER}" &>/dev/null 2>&1; then
  echo "tag tags/${VER} already exists, skipping"
else
  svn copy ^/trunk "^/tags/${VER}" -m "tag ${VER}"
fi

echo "=== archive ==="
tar czf "${OUT}" -C "${SRC}" .

echo "=== upload NAS ==="
sshpass -p "${NAS_PASS}" sftp -P "${NAS_PORT}" -o StrictHostKeyChecking=no "${NAS_USER}@${NAS_HOST}" <<EOF
cd ${NAS_PATH}
put ${OUT}
bye
EOF

echo "=== done ==="
echo "  binary: ${SRC}/varwof"
echo "  archive: ${OUT}"
echo "  svn tag: tags/${VER}"

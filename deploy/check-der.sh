#!/usr/bin/env bash
# Validate all PEM/DER artifacts with openssl asn1parse
# (OpenSSL 3.x asn1parse is strict by default)
set -uo pipefail
FAIL=0
PASS=0
workdir="${1:-.}"

for f in "$workdir"/testdata/*.pem "$workdir"/testdata/*.der; do
  [ -f "$f" ] || continue
  echo -n "  asn1parse $(basename "$f") ... "
  if openssl asn1parse -in "$f" > /dev/null 2>&1; then
    echo "OK"; PASS=$((PASS+1))
  else
    echo "FAIL"; FAIL=$((FAIL+1))
  fi
done

echo "PASS=$PASS FAIL=$FAIL"
exit $FAIL

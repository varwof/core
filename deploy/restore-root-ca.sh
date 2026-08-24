#!/bin/bash
# Root CA 密钥恢复脚本
# 用法: sudo ./restore-root-ca.sh /mnt/usb/pki-root-ca-backup-YYYYMMDD

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup-directory>"
    echo "Example: $0 /mnt/usb/pki-root-ca-backup-20260704"
    exit 1
fi

BACKUP="$1"
KEY="${BACKUP}/root-ca.key"
CERT="${BACKUP}/root-ca.pem"
SUM="${BACKUP}/checksums.txt"

if [ ! -f "$KEY" ] || [ ! -f "$CERT" ]; then
    echo "ERROR: Backup files not found in $BACKUP"
    exit 1
fi

if [ -f "$SUM" ]; then
    echo "验证备份完整性..."
    (cd "$BACKUP" && sha256sum -c checksums.txt)
fi

KEY_DST="/etc/varwof/core/pki/root/private/ca.key"
CERT_DST="/etc/varwof/core/pki/root/certs/ca.pem"

if [ -f "$KEY_DST" ]; then
    echo "WARNING: $KEY_DST already exists. 覆盖? (y/N)"
    read -r confirm
    if [ "$confirm" != "y" ]; then
        exit 1
    fi
fi

cp "$KEY" "$KEY_DST"
cp "$CERT" "$CERT_DST"
chmod 400 "$KEY_DST"
echo "Root CA 密钥已恢复到: $KEY_DST"

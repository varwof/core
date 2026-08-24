#!/bin/sh
# pki database backup script
# Called by systemd timer: pki-backup.timer
set -e

OUTDIR="${1:-/var/lib/pki/backups}"
mkdir -p "$OUTDIR"
varwof db backup --output "$OUTDIR/pki-$(date +%Y%m%d-%H%M%S).db"
echo "backup saved to $OUTDIR"

# Prune backups older than 90 days
find "$OUTDIR" -name 'pki-*.db' -mtime +90 -delete 2>/dev/null || true
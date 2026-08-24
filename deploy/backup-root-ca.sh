#!/bin/bash
# Root CA 密钥冷备脚本
# 用法: sudo ./backup-root-ca.sh /mnt/usb
# 将 Root CA 密钥备份到 USB 并 shred 源文件

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <usb-mount-path>"
    echo "Example: $0 /mnt/usb"
    exit 1
fi

USB="$1"
BACKUP_DIR="${USB}/pki-root-ca-backup-$(date +%Y%m%d)"
SRC="/etc/varwof/core/pki/root/private/ca.key"
CERT="/etc/varwof/core/pki/root/certs/ca.pem"

if [ ! -d "$USB" ]; then
    echo "ERROR: USB mount point $USB does not exist"
    exit 1
fi

if [ ! -f "$SRC" ]; then
    echo "ERROR: Root CA key not found at $SRC (already backed up?)"
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# Backup cert + key + chain info
cp "$CERT" "$BACKUP_DIR/root-ca.pem"
cp "$SRC" "$BACKUP_DIR/root-ca.key"
openssl x509 -in "$CERT" -noout -text > "$BACKUP_DIR/root-ca-details.txt"

# Create checksums
cd "$BACKUP_DIR"
sha256sum root-ca.pem root-ca.key > checksums.txt

echo "=== Root CA 密钥已备份到: $BACKUP_DIR ==="
echo "请验证备份完整性:"
echo "  cd $BACKUP_DIR && sha256sum -c checksums.txt"
echo ""
echo "确认备份完成后，源文件将被安全删除 (shred -u)"
echo "按 Ctrl+C 取消，或按 Enter 继续..."
read -r

# Securely delete original key
shred -u "$SRC"
echo "源文件已安全删除: $SRC"

# Remove from config to prevent accidental use
echo "请手动从 /etc/varwof/core/pki.json 移除或注释掉 Root CA 配置(可选)"

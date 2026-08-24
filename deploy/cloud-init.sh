#!/usr/bin/env bash
# pki 云服务器一键部署 — Ubuntu 22.04+
# 用法: curl -sSL https://your-host/cloud-init.sh | sudo bash
set -euo pipefail

echo "=== pki 云服务器一键部署 ==="
echo ""

# 1. 安装 Docker（如未安装）
if ! command -v docker &>/dev/null; then
    echo "[1/4] 安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    systemctl enable --now docker
else
    echo "[1/4] Docker 已安装"
fi

# 2. 创建持久化目录
DATA_DIR="/etc/pki"
mkdir -p "$DATA_DIR"
echo "[2/4] 数据目录: $DATA_DIR"

# 3. 启动 pki 容器
echo "[3/4] 启动 pki 服务..."
docker rm -f pki 2>/dev/null || true
docker run -d --name pki --restart unless-stopped \
    -p 4430:4430 \
    -v "$DATA_DIR:/etc/pki" \
    varwof/pki:latest serve
echo "  ✓ 容器已启动"

# 4. 开放防火墙
echo "[4/4] 配置防火墙..."
if command -v ufw &>/dev/null; then
    ufw allow 4430/tcp 2>/dev/null || true
    echo "  ✓ ufw 端口 4430 已开放"
fi
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --add-port=4430/tcp --permanent 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "  ✓ firewalld 端口 4430 已开放"
fi

echo ""
echo "=== 部署完成 ==="
echo ""
echo "您的云 CA 已就绪，请将 CLB 指向本机端口 4430。"
echo ""
echo "管理 API:  https://$(curl -s ifconfig.me):4430/api/v1/"
echo "文档:      https://github.com/varwof/pki"
echo ""
echo "快速验证:"
echo "  curl -k https://localhost:4430/api/v1/ca/list"
echo ""

#!/usr/bin/env bash
# pki 5 分钟快速体验
set -euo pipefail

echo "=== pki — 5 分钟快速体验 ==="
echo ""

# 1. 创建临时目录
TMP=$(mktemp -d /tmp/pki-quick-XXXXX)
cd "$TMP"
echo "[1/4] 工作目录: $TMP"

# 2. 下载 pki
if command -v varwof &>/dev/null; then
  PKI=$(command -v varwof)
  echo "[2/4] 使用系统 varwof: $PKI"
else
  echo "[2/4] 从 Docker 构建..."
  if command -v docker &>/dev/null; then
    docker build -t varwof/pki:latest -f- . <<'DOCKER'
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
RUN git clone https://github.com/varwof/pki.git .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /usr/local/bin/varwof ./cmd/pki/
FROM alpine:3.21
COPY --from=builder /usr/local/bin/varwof /usr/local/bin/varwof
RUN mkdir -p /etc/pki /var/lib/pki
EXPOSE 4430
ENTRYPOINT ["varwof"]
DOCKER
    PKI="docker run --rm -v $TMP:/data varwof/pki:latest"
    alias varwof="$PKI"
  else
    echo "请先安装 Go 或 Docker"
    exit 1
  fi
fi

# 3. 初始化根 CA
echo "[3/4] 初始化根 CA..."
mkdir -p root/certs root/private
$PKI init-ca --name "Quick Root CA" --key-type ecdsa-p256 \
  --out-cert root/certs/ca.pem --out-key root/private/ca.key
echo "  ✓ 根 CA 已创建"

# 4. 签发测试证书
echo "[4/4] 签发测试证书..."
$PKI issue --cn "hello.pki.example.com" --profile tls-server
echo "  ✓ 证书已签发"

echo ""
echo "=== 完成! ==="
echo ""
echo "证书文件: $(ls *.pem)"
echo ""
echo "下一步:"
echo "  varwof serve              # 启动 PKI 服务 (OCSP + TSA + Web)"
echo "  varwof --help             # 查看全部命令"
echo ""

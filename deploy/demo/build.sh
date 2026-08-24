#!/usr/bin/env bash
# Build pki demo stack
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== Building pki binary ==="
GOFLAGS=-buildvcs=false CGO_ENABLED=0 go build -o pki ./cmd/pki/

echo "=== Building Docker image ==="
docker compose -f deploy/demo/docker-compose.yml build

echo "=== Starting stack ==="
docker compose -f deploy/demo/docker-compose.yml up -d

echo ""
echo "=== pki demo started ==="
echo "  API:    https://localhost/api/v1/certs"
echo "  Admin:  admin / admin123"
echo ""
echo "To stop: docker compose -f deploy/demo/docker-compose.yml down -v"

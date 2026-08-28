# 部署指南

## 目录

1. [快速部署](#1-快速部署)
2. [数据库配置](#2-数据库配置)
3. [TLS 和反向代理](#3-tls-和反向代理)
4. [自动备份](#4-自动备份)
5. [安全加固](#5-安全加固)

---

## 1. 快速部署

### systemd（Linux 生产环境）

```bash
# 1. 安装二进制文件
cp varwof /usr/local/bin/varwof
cp deploy/init.sh /usr/local/bin/pki-init
cp deploy/pki-backup.sh /usr/local/bin/pki-backup

# 2. 配置
mkdir -p /etc/varwof/core
cp pki.json /etc/varwof/core/pki.json
# 编辑 /etc/varwof/core/pki.json

# 3. 安装服务
cp deploy/pki.service /etc/systemd/system/pki.service
systemctl daemon-reload
systemctl enable --now pki

# 4. 验证
curl http://localhost:8443/healthz
```

首次启动时，`pki-init` 自动执行：
- 创建根 CA
- 签发服务器 TLS 证书
- 创建管理员用户

### Docker

```bash
cd deploy
docker compose up -d
```

首次启动时，创建空数据库并应用所有迁移。

### init-full（推荐）

一条命令创建完整的 PKI 层级：

```bash
varwof init-full \
  --root-name "TestCorp Root CA" \
  --org "TestCorp" \
  --country CN \
  --base-dir /opt/pki \
  --encrypt-keys
```

这将创建：
- 根 CA + 8 个业务子 CA
- 服务器 TLS 证书
- 配置文件
- 初始 CRL

详情请参阅 [PKI 层级](https://github.com/varwof/dev-docs/blob/main/core/zh/pki-hierarchy.md)。

---

## 2. 数据库配置

### SQLite（默认）

```json
{
  "db": "/var/lib/pki/pki.db"
}
```

零配置，单节点。通过 `VACUUM INTO` 备份。

### PostgreSQL

```json
{
  "db": "postgres://user:password@localhost:5432/pkidb?sslmode=require"
}
```

```bash
createdb -U postgres pkidb
```

### MySQL / MariaDB

```json
{
  "db": "mysql://user:password@tcp(localhost:3306)/pkidb?charset=utf8mb4&parseTime=true"
}
```

```sql
CREATE DATABASE pkidb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pki'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL ON pkidb.* TO 'pki'@'localhost';
```

### 数据库对比

| 特性 | SQLite | PostgreSQL | MySQL/MariaDB |
|------|--------|------------|---------------|
| 部署 | 零配置 | 需要 PG 服务器 | 需要 MySQL 服务器 |
| 并发写入 | 单写入者 | 多写入者 | 多写入者 |
| 在线备份 | `varwof db backup` | pg_dump | mysqldump |
| 分布式锁 | noop | 咨询锁 | GET_LOCK |
| 推荐 | 单节点/开发 | 生产/多节点 | 生产/MySQL 生态系统 |
| 驱动 | modernc.org/sqlite（纯 Go） | pgx/v5（纯 Go） | go-sql-driver/mysql（纯 Go） |

### 数据库初始化

```bash
# SQLite（默认）
varwof db init

# PostgreSQL
varwof db init --dsn "postgres://user:pass@host:5432/pki?sslmode=disable"

# MySQL
varwof db init --dsn "mysql://user:pass@host:3306/pki?charset=utf8mb4&parseTime=true"
```

`varwof db init` 是幂等的。

---

## 3. TLS 和反向代理

### 直接 TLS（内置）

```json
{
  "serve": {
    "addr": ":4430",
    "tls_addr": ":4433",
    "tls_cert": "/etc/varwof/core/server.pem",
    "tls_key": "/etc/varwof/core/server.key"
  }
}
```

### Nginx 反向代理（推荐）

```nginx
server {
    listen 443 ssl http2;
    server_name pki.example.com;

    ssl_certificate     /etc/letsencrypt/live/pki.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pki.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # PKI API + Web UI
    location / {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # OCSP
    location /ocsp {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 10k;
    }

    # ACME
    location /acme {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket — SSE 仪表板
    location /api/v1/dashboard/events {
        proxy_pass http://127.0.0.1:4430;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
    server_name pki.example.com;
    return 301 https://$host$request_uri;
}
```

配置 `pki.json` 仅在内网上监听 HTTP：

```json
{
  "serve": {
    "addr": "127.0.0.1:4430"
  }
}
```

---

## 4. 自动备份

### systemd 定时器（推荐）

```bash
cp deploy/pki-backup.service /etc/systemd/system/pki-backup.service
cp deploy/pki-backup.timer /etc/systemd/system/pki-backup.timer
systemctl daemon-reload
systemctl enable --now pki-backup.timer
```

- 自动每日备份
- 备份路径：`/var/lib/pki/backups/pki-YYYYMMDD-HHMMSS.db`
- 保留 90 天
- 使用 `VACUUM INTO`（在线，无停机）

### 手动备份

```bash
varwof db backup --output /backup/pki-$(date +%Y%m%d).db
```

### 恢复备份

```bash
systemctl stop pki
cp /backup/pki-20260101.db /var/lib/pki/pki.db
systemctl start pki
```

---

## 5. 安全加固

### systemd 安全设置

内置在 `pki.service` 中：
- `NoNewPrivileges=true` — 防止权限提升
- `ProtectSystem=strict` — 只读根文件系统
- `ProtectHome=yes` — 隐藏主目录
- `PrivateTmp=true` — 隔离临时目录
- `DynamicUser=yes` — 动态创建隔离用户

### 防火墙

```bash
# 仅向反向代理暴露端口 4430
ufw allow from 127.0.0.1 to any port 4430

# 或 iptables
iptables -A INPUT -p tcp --dport 4430 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 4430 -j DROP
```

### 数据库加密

SQLite 不对静态数据加密。敏感数据（私钥）使用 PBKDF2+AES-256-CBC 加密存储。数据库级加密：
- SQLite：使用 LUKS 加密文件系统
- PostgreSQL：启用 `pgcrypto` + TDE
- MySQL：启用 `InnoDB` 表空间加密

### 密钥安全

- 保持根 CA 密钥离线（气隙）
- 使用 `varwof ca cold-backup` 进行加密备份
- 启用 `key_escrow` 用于管理员密钥恢复
- 通过 `POST /ca/{name}/rotate` 在到期前轮换 CA 主密钥

### RBAC

启用 RBAC 以实现细粒度访问控制：

```json
{
  "rbac": {
    "enabled": true,
    "mode": "simple"
  }
}
```

### 策略文件签名

防止 `authz.json` 和 `routes.json` 被篡改：

```json
{
  "policy_signing": {
    "enabled": true,
    "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
    "require_admin_ou": true,
    "require": true
  }
}
```

### 审计日志

启用审计日志完整性验证：

```json
{
  "serve": {
    "audit_salt": {
      "enabled": true,
      "retention_days": 365
    },
    "audit_verify": {
      "enabled": true,
      "interval": "24h"
    }
  }
}
```

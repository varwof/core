# varwof 部署指南

> 版本: v1
> 日期: 2026-07-01

## 目录

1. [快速部署](#1-快速部署)
2. [数据库配置](#2-数据库配置)
3. [TLS 与反向代理](#3-tls-与反向代理)
4. [自动备份](#4-自动备份)
5. [安全加固](#5-安全加固)

---

## 1. 快速部署

> **推荐**：完整 CA 层级 + 配置 + 服务证书 + 初始 CRL 一条命令生成的 `init-full` 方式，见
> `../dev-docs/core/security/deployment-playbook.md`（手把手部署手册，含冒烟验证与已踩坑清单）。
> 以下为经典 systemd 单 CA 方式（v1）。

### systemd（Linux 生产环境）

```bash
# 1. 安装二进制
cp pki /usr/local/bin/pki
cp deploy/init.sh /usr/local/bin/pki-init
cp deploy/pki-backup.sh /usr/local/bin/pki-backup

# 2. 配置
mkdir -p /etc/pki
cp deploy/pki.json /etc/varwof/core/pki.json
# 编辑 /etc/varwof/core/pki.json 修改数据库路径、监听地址等

# 3. 安装服务
cp deploy/pki.service /etc/systemd/system/pki.service
systemctl daemon-reload
systemctl enable --now pki

# 4. 验证
curl http://localhost:4430/healthz
```

首次启动时 `pki-init` 自动完成：
- 创建根 CA（`/var/lib/pki/certs/ca.pem`）
- 签发服务器 TLS 证书（路径由 `pki.json` 的 `tls_cert`/`tls_key` 指定）
- 创建 admin 用户（用户名密码由 `auth_username`/`auth_password` 指定）

### Docker

```bash
cd deploy
docker compose up -d
```

首次启动会自动创建空 DB 并执行所有迁移。

---

## 2. 数据库配置

### SQLite（默认）

```json
{
  "db": "/var/lib/pki/pki.db"
}
```

SQLite 适合单机部署，备份通过 `VACUUM INTO` 在线快照。

### PostgreSQL

```json
{
  "db": "postgres://user:password@localhost:5432/pkidb?sslmode=require"
}
```

```bash
# 需要先创建数据库
createdb -U postgres pkidb
```

DSN 通过 `pgx` 驱动解析，支持所有 `pgx` 连接参数：
- `host=localhost port=5432 dbname=pkidb user=postgres password=secret`
- 完整 URL: `postgres://user:pass@host:port/dbname?sslmode=require`

### MySQL / MariaDB

```json
{
  "db": "mysql://user:password@tcp(localhost:3306)/pkidb?charset=utf8mb4&parseTime=true"
}
```

```bash
# 需要先创建数据库和用户
CREATE DATABASE pkidb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pki'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL ON pkidb.* TO 'pki'@'localhost';
```

DSN 参数：
- `tcp(host:port)` — TCP 连接
- `unix(/path/to/socket)` — Unix socket 连接
- `charset=utf8mb4` — 字符集（推荐）
- `parseTime=true` — Go 时间解析（必须）

### 数据库对比

| 特性 | SQLite | PostgreSQL | MySQL/MariaDB |
|------|--------|------------|---------------|
| 部署复杂度 | 零配置 | 需安装 PG 服务 | 需安装 MySQL 服务 |
| 并发写入 | 单写 | 多写 | 多写 |
| 在线备份 | `varwof db backup` | pg_dump | mysqldump |
| 分布式锁 | noop | advisory lock | GET_LOCK |
| 推荐场景 | 单机/开发/小规模 | 生产/多节点 | 生产/MySQL 生态 |
| 驱动 | modernc.org/sqlite（纯 Go） | pgx/v5（纯 Go） | go-sql-driver/mysql（纯 Go） |

---

## 3. TLS 与反向代理

### 直接 TLS（varwof 内置）

```json
{
  "serve": {
    "listen": ":4430",
    "tls_addr": ":4433",
    "tls_cert": "/etc/varwof/core/server.pem",
    "tls_key": "/etc/varwof/core/server.key"
  }
}
```

- `listen` — HTTP（明文），建议仅内网或配合反向代理使用
- `tls_addr` — HTTPS，支持 TLS 1.2/1.3，使用强密码套件
- 首次部署时 `pki-init` 会自动用根 CA 签发服务器证书

### Nginx 反向代理（推荐）

```nginx
# /etc/nginx/sites-available/pki
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

    # OCSP — 需要更大的请求体
    location /ocsp {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 10k;
    }

    # ACME — Let's Encrypt 验证
    location /acme {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket — SSE Dashboard
    location /api/v1/dashboard/events {
        proxy_pass http://127.0.0.1:4430;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# HTTP → HTTPS 重定向
server {
    listen 80;
    server_name pki.example.com;
    return 301 https://$host$request_uri;
}
```

同时配置 `pki.json` 只用 HTTP 内网监听：

```json
{
  "serve": {
    "listen": "127.0.0.1:4430"
  }
}
```

---

## 4. 自动备份

### 数据库初始化

首次部署（或更换数据库）时，先初始化目标数据库：

```bash
# SQLite（默认，自动创建文件及父目录）
varwof db init

# PostgreSQL（自动建库 + 迁移到最新 schema）
varwof db init --dsn "postgres://user:pass@host:5432/pki?sslmode=disable"

# MySQL / MariaDB
varwof db init --dsn "mysql://user:pass@host:3306/pki?charset=utf8mb4&parseTime=true"
```

`varwof db init` 幂等：数据库已存在时直接迁移，不报错。PG/MySQL 建库要求连接用户具备建库权限（`CREATEDB` / `CREATE DATABASE` 权限）。DSN 缺省时取配置 `db` 字段，其次 `DATABASE_URL` 环境变量。

### systemd timer（推荐）

```bash
cp deploy/pki-backup.service /etc/systemd/system/pki-backup.service
cp deploy/pki-backup.timer /etc/systemd/system/pki-backup.timer
systemctl daemon-reload
systemctl enable --now pki-backup.timer
```

- 每天自动备份一次（`OnCalendar=daily`）
- 备份路径: `/var/lib/pki/backups/pki-YYYYMMDD-HHMMSS.db`
- 保留 90 天，自动清理旧备份
- 使用 `VACUUM INTO` 在线快照，无需停机

### 手动备份

```bash
varwof db backup --output /backup/pki-$(date +%Y%m%d).db
```

### 备份恢复

```bash
# 停止服务
systemctl stop pki

# 恢复
cp /backup/pki-20260101.db /var/lib/pki/pki.db

# 启动服务
systemctl start pki
```

---

## 5. 安全加固

### systemd 安全配置（`pki.service` 已内置）

- `NoNewPrivileges=true` — 禁止提权
- `ProtectSystem=strict` — 只读根文件系统
- `ProtectHome=yes` — 屏蔽家目录
- `PrivateTmp=true` — 隔离临时目录
- `DynamicUser=yes` — 动态创建隔离用户

### 防火墙

```bash
# 仅暴露 4430 给反向代理
ufw allow from 127.0.0.1 to any port 4430

# 或使用 iptables
iptables -A INPUT -p tcp --dport 4430 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 4430 -j DROP
```

### 数据库加密

SQLite 数据库文件本身不加密。敏感数据（私钥）已通过 PBKDF2+AES-256-CBC 加密存储。如需数据库层面加密：
- SQLite: 使用 LUKS 加密文件系统
- PostgreSQL: 启用 `pgcrypto` + TDE
- MySQL: 启用 `InnoDB` 表空间加密

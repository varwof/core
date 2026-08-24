# varwof Deployment Guide

> Version: v1
> Date: 2026-07-01

## Table of Contents

1. [Quick Deployment](#1-quick-deployment)
2. [Database Configuration](#2-database-configuration)
3. [TLS and Reverse Proxy](#3-tls-and-reverse-proxy)
4. [Automated Backup](#4-automated-backup)
5. [Security Hardening](#5-security-hardening)

---

## 1. Quick Deployment

> **Recommended**: the `init-full` approach, which generates the full CA hierarchy + config + service certificates + initial CRL in a single command; see
> `../dev-docs/core/security/deployment-playbook.md` (step-by-step deployment playbook, including smoke verification and a list of known pitfalls).
> The following describes the classic systemd single-CA approach (v1).

### systemd (Linux Production)

```bash
# 1. Install the binary
cp pki /usr/local/bin/pki
cp deploy/init.sh /usr/local/bin/pki-init
cp deploy/pki-backup.sh /usr/local/bin/pki-backup

# 2. Configure
mkdir -p /etc/pki
cp deploy/pki.json /etc/varwof/core/pki.json
# Edit /etc/varwof/core/pki.json to change the database path, listen address, etc.

# 3. Install the service
cp deploy/pki.service /etc/systemd/system/pki.service
systemctl daemon-reload
systemctl enable --now pki

# 4. Verify
curl http://localhost:4430/healthz
```

On first startup, `pki-init` automatically:
- Creates the root CA (`/var/lib/pki/certs/ca.pem`)
- Issues the server TLS certificate (paths specified by `tls_cert`/`tls_key` in `pki.json`)
- Creates the admin user (username/password specified by `auth_username`/`auth_password`)

### Docker

```bash
cd deploy
docker compose up -d
```

On first startup, an empty database is created automatically and all migrations are applied.

---

## 2. Database Configuration

### SQLite (default)

```json
{
  "db": "/var/lib/pki/pki.db"
}
```

SQLite suits single-node deployments; backups use online snapshots via `VACUUM INTO`.

### PostgreSQL

```json
{
  "db": "postgres://user:password@localhost:5432/pkidb?sslmode=require"
}
```

```bash
# The database must be created first
createdb -U postgres pkidb
```

The DSN is parsed by the `pgx` driver and supports all `pgx` connection parameters:
- `host=localhost port=5432 dbname=pkidb user=postgres password=secret`
- Full URL: `postgres://user:pass@host:port/dbname?sslmode=require`

### MySQL / MariaDB

```json
{
  "db": "mysql://user:password@tcp(localhost:3306)/pkidb?charset=utf8mb4&parseTime=true"
}
```

```bash
# The database and user must be created first
CREATE DATABASE pkidb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pki'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL ON pkidb.* TO 'pki'@'localhost';
```

DSN parameters:
- `tcp(host:port)` — TCP connection
- `unix(/path/to/socket)` — Unix socket connection
- `charset=utf8mb4` — Character set (recommended)
- `parseTime=true` — Go time parsing (required)

### Database Comparison

| Feature | SQLite | PostgreSQL | MySQL/MariaDB |
|---------|--------|------------|---------------|
| Deployment complexity | Zero config | Requires installing a PG server | Requires installing a MySQL server |
| Concurrent writes | Single writer | Multi-writer | Multi-writer |
| Online backup | `varwof db backup` | pg_dump | mysqldump |
| Distributed lock | noop | advisory lock | GET_LOCK |
| Recommended use | Single node/dev/small scale | Production/multi-node | Production/MySQL ecosystems |
| Driver | modernc.org/sqlite (pure Go) | pgx/v5 (pure Go) | go-sql-driver/mysql (pure Go) |

---

## 3. TLS and Reverse Proxy

### Direct TLS (built into varwof)

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

- `listen` — HTTP (plaintext); recommended only for intranets or behind a reverse proxy
- `tls_addr` — HTTPS; supports TLS 1.2/1.3 with strong cipher suites
- On first deployment, `pki-init` automatically issues the server certificate signed by the root CA

### Nginx Reverse Proxy (recommended)

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

    # OCSP — requires a larger request body
    location /ocsp {
        proxy_pass http://127.0.0.1:4430;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 10k;
    }

    # ACME — Let's Encrypt validation
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

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name pki.example.com;
    return 301 https://$host$request_uri;
}
```

Also configure `pki.json` to listen on HTTP for the intranet only:

```json
{
  "serve": {
    "listen": "127.0.0.1:4430"
  }
}
```

---

## 4. Automated Backup

### Database Initialization

On first deployment (or when switching databases), initialize the target database first:

```bash
# SQLite (default; creates the file and parent directories automatically)
varwof db init

# PostgreSQL (creates the database automatically + migrates to the latest schema)
varwof db init --dsn "postgres://user:pass@host:5432/pki?sslmode=disable"

# MySQL / MariaDB
varwof db init --dsn "mysql://user:pass@host:3306/pki?charset=utf8mb4&parseTime=true"
```

`varwof db init` is idempotent: if the database already exists it simply migrates without error. Creating PG/MySQL databases requires the connecting user to have database-creation privileges (`CREATEDB` / `CREATE DATABASE`). When no DSN is given, the `db` field from the config is used, falling back to the `DATABASE_URL` environment variable.

### systemd timer (recommended)

```bash
cp deploy/pki-backup.service /etc/systemd/system/pki-backup.service
cp deploy/pki-backup.timer /etc/systemd/system/pki-backup.timer
systemctl daemon-reload
systemctl enable --now pki-backup.timer
```

- Automatic daily backup (`OnCalendar=daily`)
- Backup path: `/var/lib/pki/backups/pki-YYYYMMDD-HHMMSS.db`
- Retained for 90 days; old backups are cleaned up automatically
- Uses `VACUUM INTO` online snapshots; no downtime required

### Manual Backup

```bash
varwof db backup --output /backup/pki-$(date +%Y%m%d).db
```

### Restoring a Backup

```bash
# Stop the service
systemctl stop pki

# Restore
cp /backup/pki-20260101.db /var/lib/pki/pki.db

# Start the service
systemctl start pki
```

---

## 5. Security Hardening

### systemd Security Settings (built into `pki.service`)

- `NoNewPrivileges=true` — prevents privilege escalation
- `ProtectSystem=strict` — read-only root filesystem
- `ProtectHome=yes` — hides home directories
- `PrivateTmp=true` — isolated temporary directory
- `DynamicUser=yes` — dynamically creates an isolated user

### Firewall

```bash
# Expose port 4430 only to the reverse proxy
ufw allow from 127.0.0.1 to any port 4430

# Or use iptables
iptables -A INPUT -p tcp --dport 4430 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 4430 -j DROP
```

### Database Encryption

The SQLite database file itself is not encrypted. Sensitive data (private keys) is already stored encrypted with PBKDF2+AES-256-CBC. For database-level encryption:
- SQLite: use a LUKS-encrypted filesystem
- PostgreSQL: enable `pgcrypto` + TDE
- MySQL: enable `InnoDB` tablespace encryption

# Deployment Guide

## Table of Contents

1. [Quick Deployment](#1-quick-deployment)
2. [Database Configuration](#2-database-configuration)
3. [TLS and Reverse Proxy](#3-tls-and-reverse-proxy)
4. [Automated Backup](#4-automated-backup)
5. [Security Hardening](#5-security-hardening)

---

## 1. Quick Deployment

### systemd (Linux Production)

```bash
# 1. Install the binary
cp varwof /usr/local/bin/varwof
cp deploy/init.sh /usr/local/bin/pki-init
cp deploy/pki-backup.sh /usr/local/bin/pki-backup

# 2. Configure
mkdir -p /etc/varwof/core
cp pki.json /etc/varwof/core/pki.json
# Edit /etc/varwof/core/pki.json

# 3. Install the service
cp deploy/pki.service /etc/systemd/system/pki.service
systemctl daemon-reload
systemctl enable --now pki

# 4. Verify
curl http://localhost:8443/healthz
```

On first startup, `pki-init` automatically:
- Creates the root CA
- Issues the server TLS certificate
- Creates the admin user

### Docker

```bash
cd deploy
docker compose up -d
```

On first startup, an empty database is created and all migrations are applied.

### init-full (Recommended)

One command to create the complete PKI hierarchy:

```bash
varwof init-full \
  --root-name "TestCorp Root CA" \
  --org "TestCorp" \
  --country CN \
  --base-dir /opt/pki \
  --encrypt-keys
```

This creates:
- Root CA + 8 business sub-CAs
- Server TLS certificate
- Config file
- Initial CRL

See [PKI Hierarchy](https://github.com/varwof/dev-docs/blob/main/core/en/pki-hierarchy.md) for details.

---

## 2. Database Configuration

### SQLite (Default)

```json
{
  "db": "/var/lib/pki/pki.db"
}
```

Zero-config, single-node. Backups via `VACUUM INTO`.

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

### Database Comparison

| Feature | SQLite | PostgreSQL | MySQL/MariaDB |
|---------|--------|------------|---------------|
| Deployment | Zero config | Requires PG server | Requires MySQL server |
| Concurrent writes | Single writer | Multi-writer | Multi-writer |
| Online backup | `varwof db backup` | pg_dump | mysqldump |
| Distributed lock | noop | advisory lock | GET_LOCK |
| Recommended | Single node/dev | Production/multi-node | Production/MySQL ecosystem |
| Driver | modernc.org/sqlite (pure Go) | pgx/v5 (pure Go) | go-sql-driver/mysql (pure Go) |

### Database Initialization

```bash
# SQLite (default)
varwof db init

# PostgreSQL
varwof db init --dsn "postgres://user:pass@host:5432/pki?sslmode=disable"

# MySQL
varwof db init --dsn "mysql://user:pass@host:3306/pki?charset=utf8mb4&parseTime=true"
```

`varwof db init` is idempotent.

---

## 3. TLS and Reverse Proxy

### Direct TLS (Built-in)

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

### Nginx Reverse Proxy (Recommended)

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

    # WebSocket — SSE Dashboard
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

Configure `pki.json` to listen on HTTP for intranet only:

```json
{
  "serve": {
    "addr": "127.0.0.1:4430"
  }
}
```

---

## 4. Automated Backup

### systemd Timer (Recommended)

```bash
cp deploy/pki-backup.service /etc/systemd/system/pki-backup.service
cp deploy/pki-backup.timer /etc/systemd/system/pki-backup.timer
systemctl daemon-reload
systemctl enable --now pki-backup.timer
```

- Automatic daily backup
- Backup path: `/var/lib/pki/backups/pki-YYYYMMDD-HHMMSS.db`
- Retained for 90 days
- Uses `VACUUM INTO` (online, no downtime)

### Manual Backup

```bash
varwof db backup --output /backup/pki-$(date +%Y%m%d).db
```

### Restoring a Backup

```bash
systemctl stop pki
cp /backup/pki-20260101.db /var/lib/pki/pki.db
systemctl start pki
```

---

## 5. Security Hardening

### systemd Security Settings

Built into `pki.service`:
- `NoNewPrivileges=true` — prevents privilege escalation
- `ProtectSystem=strict` — read-only root filesystem
- `ProtectHome=yes` — hides home directories
- `PrivateTmp=true` — isolated temporary directory
- `DynamicUser=yes` — dynamically creates isolated user

### Firewall

```bash
# Expose port 4430 only to reverse proxy
ufw allow from 127.0.0.1 to any port 4430

# Or iptables
iptables -A INPUT -p tcp --dport 4430 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 4430 -j DROP
```

### Database Encryption

SQLite is not encrypted at rest. Sensitive data (private keys) is stored encrypted with PBKDF2+AES-256-CBC. For database-level encryption:
- SQLite: use LUKS-encrypted filesystem
- PostgreSQL: enable `pgcrypto` + TDE
- MySQL: enable `InnoDB` tablespace encryption

### Key Security

- Keep root CA key offline (air-gapped)
- Use `varwof ca cold-backup` for encrypted backups
- Enable `key_escrow` for admin key recovery
- Rotate CA master keys before expiry via `POST /ca/{name}/rotate`

### RBAC

Enable RBAC for fine-grained access control:

```json
{
  "rbac": {
    "enabled": true,
    "mode": "simple"
  }
}
```

### Policy File Signing

Prevent tampering with `authz.json` and `routes.json`:

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

### Audit Logging

Enable audit log integrity verification:

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

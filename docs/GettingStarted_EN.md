# varwof Quick Start

## 1. Install

```bash
go install github.com/varwof/core@latest
# or build from source:
git clone https://github.com/varwof/core.git
cd /home/varwof/src/go/pki
go build -o /usr/local/bin/pki ./cmd/pki/
```

Verify:

```bash
varwof version
# varwof 1.0.0 linux/amd64 go1.26.2 (rev unknown, unknown)
```

---

## 2. Generate Config

```bash
varwof init-config > pki.json
```

Edit the config file, replace the example domain:

```bash
# sed -i 's|example\.com|mycompany.com|' pki.json
```

Or start fresh by placing it at the default path:

```bash
sudo mkdir -p /etc/pki
sudo cp pki.json /etc/varwof/core/
```

---

## 3. Initialize a Root CA

```bash
sudo varwof init-ca \
  --name root \
  --profile root-ca \
  --key-type ecdsa-p256 \
  --validity 3650 \
  --out-cert /etc/varwof/core/root/certs/ca.pem \
  --out-key /etc/varwof/core/root/private/ca.key
```

Update `pki.json` to add the root CA under `"cas"`.

---

## 4. Initialize an Issuing CA

```bash
sudo varwof init-ca \
  --name issuing \
  --profile sub-ca \
  --parent root \
  --key-type ecdsa-p256 \
  --validity 1825 \
  --out-cert /etc/varwof/core/issuing/certs/ca.pem \
  --out-key /etc/varwof/core/issuing/private/ca.key \
  --permitted-dns "varwof.com"
```

---

## 5. Start the Server

```bash
sudo varwof serve --config /etc/varwof/core/pki.json
```

The server listens on `:8443` by default. Test:

```bash
curl http://localhost:8443/healthz
# {"status":"ok","version":"pki/1.0","db":"ok"}
```

---

## 6. Issue a Certificate

```bash
varwof issue \
  --cn "server.varwof.com" \
  --profile tls-server \
  --ca issuing \
  --san "server.varwof.com" \
  --out-cert /tmp/server.pem \
  --out-key /tmp/server.key
```

Verify with openssl:

```bash
openssl x509 -in /tmp/server.pem -text -noout | head -20
```

---

## 7. Next Steps

- **ACME** — Enable ACME in config (`acme.enable: true`) for automatic cert issuance.
- **SCEP** — Enable SCEP for router/network-device enrollment.
- **OCSP** — Start an OCSP responder on `:8443`.
- **TSA** — Start a Time-Stamp Authority on `:8443`.
- **Web UI** — Open `http://localhost:8443/` for the admin interface.
- **See also** — `docs/Configuration_EN.md` for full configuration reference.

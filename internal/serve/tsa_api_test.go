package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/core/internal/tsa"
)

func newTestTSAServerWithConfig(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	d := newTestDB(t)
	seedAdmin(t, d)

	caCert, _ := newTestCA(t, "test-ca")
	d.InsertCAMeta(&db.CAMeta{
		Name:         "test-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(caCert.Raw),
	})

	dir := t.TempDir()
	certPath := dir + "/ca.pem"
	keyPath := dir + "/ca.key"
	writePEMFile(t, certPath, "CERTIFICATE", caCert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caCert)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)

	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Serve.Static = ""
	cfg.Defaults.CA = "test-ca"
	cfg.CAs = map[string]internal.CAConfig{
		"test-ca": {Cert: certPath, Key: keyPath},
	}

	srv := NewFull(&cfg, d, i18n.NewBundle(), nil, nil)
	ts := httptest.NewServer(WrapHandler(srv))
	t.Cleanup(ts.Close)
	return srv, ts
}

func newTestTSACert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			CommonName:   "Test TSA Signer",
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestServeTSACert(t *testing.T) {
	srv, _ := newTestTSAServerWithConfig(t)
	fx := newMTLSAdminFixture(t, WrapHandler(srv), "config:write", "config:read")

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/tsa/cert")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var info tsa.SignerCertInfo
	json.NewDecoder(resp.Body).Decode(&info)
	if info.SerialNumber == "" {
		t.Fatal("expected non-empty serial_number")
	}
	if info.Subject == "" {
		t.Fatal("expected non-empty subject")
	}
}

func TestServeTSACertNoConfig(t *testing.T) {
	srv, _ := newTestTSAServerWithConfig(t)
	fx := newMTLSAdminFixture(t, WrapHandler(srv), "config:write", "config:read")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/tsa/cert")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestServeTSACertRenewNoCoreURL(t *testing.T) {
	srv, _ := newTestTSAServerWithConfig(t)
	fx := newMTLSAdminFixture(t, WrapHandler(srv), "config:write", "config:read")

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/tsa/cert/renew", "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (no core_url), got %d", resp.StatusCode)
	}
}

func TestServeTSACertRotateNoCoreURL(t *testing.T) {
	srv, _ := newTestTSAServerWithConfig(t)
	fx := newMTLSAdminFixture(t, WrapHandler(srv), "config:write", "config:read")

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/tsa/cert/rotate", "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (no core_url), got %d", resp.StatusCode)
	}
}

func TestServeTSACARenew(t *testing.T) {
	srv, _ := newTestTSAServerWithConfig(t)
	fx := newMTLSAdminFixture(t, WrapHandler(srv), "config:write", "config:read")

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/tsa/ca/renew", "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "approval_required" {
		t.Fatalf("expected approval_required, got %s", result["status"])
	}
}

func TestServeTSACertNoAuth(t *testing.T) {
	srv, ts := newTestTSAServerWithConfig(t)

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	resp, err := http.Get(ts.URL + "/api/v1/tsa/cert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServeTSACARenewMethodNotAllowed(t *testing.T) {
	srv, ts := newTestTSAServerWithConfig(t)

	cert, _ := newTestTSACert(t)
	srv.SetTSAConfig(tsa.NewRuntimeConfig(&tsa.TSAConfig{SignerCert: cert}))

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/tsa/ca/renew", nil)
	req.SetBasicAuth("superadmin", "superadmin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestBuildTSARenewalConfig(t *testing.T) {
	cfg := &internal.Config{}
	cfg.TSA.CoreURL = "https://pki.example.com"
	cfg.TSA.SignerCert = "/path/to/cert.pem"
	cfg.TSA.SignerKey = "/path/to/key.pem"
	cfg.TSA.TLSCACert = "/path/to/ca.pem"
	cfg.TSA.CAName = "tsa"
	cfg.TSA.ValidityDays = 365
	cfg.TSA.TLSClientCert = "/path/to/client.pem"
	cfg.TSA.TLSClientKey = "/path/to/client-key.pem"
	cfg.TSA.RenewalWindow = "4h"

	rc := buildTSARenewalConfig(cfg)
	if rc.CoreURL != "https://pki.example.com" {
		t.Fatalf("expected core URL, got %s", rc.CoreURL)
	}
	if rc.CertFile != "/path/to/cert.pem" {
		t.Fatalf("expected cert path, got %s", rc.CertFile)
	}
	if rc.RenewalWindow != 4*time.Hour {
		t.Fatalf("expected 4h window, got %v", rc.RenewalWindow)
	}
}

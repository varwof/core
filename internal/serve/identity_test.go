// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// identityBridgeServer starts a mock bridge-ldap returning a fixed person.
func identityBridgeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v1/lookup" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dn":        "CN=张三,OU=内科,DC=hospital,DC=local",
			"staff_id":  "001",
			"full_name": "张三",
			"dept":      "内科",
			"email":     "zhangsan@hospital.local",
			"source":    "ad-main",
			"disabled":  false,
			"groups":    []string{"CN=医生,OU=Groups,DC=hospital,DC=local"},
		})
	}))
	return srv
}

// newTestServerWithIdentity builds a Server whose config points at the given
// identity bridge URL.
func newTestServerWithIdentity(t *testing.T, identityCfg *ca.IdentitySourceConfig) (*Server, http.Handler, *x509.Certificate) {
	t.Helper()
	d := newTestDB(t)
	seedAdmin(t, d)

	caCert, caKey := newTestCA(t, "test-ca")
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
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)

	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Serve.Static = ""
	cfg.Defaults.CA = "test-ca"
	cfg.TSA.SignerCert = ""
	cfg.TSA.SignerKey = ""
	cfg.OCSP.SignerCert = ""
	cfg.OCSP.SignerKey = ""
	cfg.CAs = map[string]internal.CAConfig{
		"test-ca": {Cert: certPath, Key: keyPath},
	}
	cfg.Identity = identityCfg

	tsaDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("tsa-ok"))
	})
	ocspDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write([]byte("ocsp-ok"))
	})
	srv := NewFull(&cfg, d, testBundle, tsaDummy, ocspDummy)
	return srv, WrapHandler(srv), caCert
}

func TestServeIssueIdentityUser(t *testing.T) {
	bridge := identityBridgeServer(t)
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type:       ca.IdentitySourceLDAP,
		SourceURL:  bridge.URL,
		Source:     "ad-main",
		TimeoutSec: 5,
		OUFromGroups: map[string]string{
			"CN=医生,OU=Groups,DC=hospital,DC=local": "gateway:ops",
		},
	}
	srv, _, _ := newTestServerWithIdentity(t, identityCfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"profile":"identity-user","identity_username":"001","key_type":"ecdsa-p256"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 1024)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
	var result struct {
		SerialNumber string `json:"serial_number"`
		CommonName   string `json:"common_name"`
		CertPEM      string `json:"cert_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.CommonName != "张三" {
		t.Fatalf("expected CN=张三 (from identity source), got %q", result.CommonName)
	}
	block, _ := pem.Decode([]byte(result.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "张三" {
		t.Fatalf("cert CN=%q", cert.Subject.CommonName)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "gateway:ops" {
		t.Fatalf("cert OU=%v", cert.Subject.OrganizationalUnit)
	}
	foundEmail := false
	for _, e := range cert.EmailAddresses {
		if e == "zhangsan@hospital.local" {
			foundEmail = true
			break
		}
	}
	if !foundEmail {
		t.Fatalf("expected email SAN zhangsan@hospital.local, got %v", cert.EmailAddresses)
	}
}

func TestServeIssueIdentityUserNotConfigured(t *testing.T) {
	srv, _, _ := newTestServerWithIdentity(t, nil)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"profile":"identity-user","identity_username":"001"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

func TestServeIssueIdentityUserDisabledAccount(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"staff_id": "001", "full_name": "张三", "disabled": true,
		})
	}))
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
	}
	srv, _, _ := newTestServerWithIdentity(t, identityCfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"profile":"identity-user","identity_username":"001"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

func TestServeIssueIdentityUserDisabledAccountAllowed(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"staff_id": "001", "full_name": "张三", "disabled": true,
		})
	}))
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
		DisabledOK: true,
	}
	srv, _, _ := newTestServerWithIdentity(t, identityCfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"profile":"identity-user","identity_username":"001"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

func TestServeIssueIdentityUserLookupFailure(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
	}
	srv, _, _ := newTestServerWithIdentity(t, identityCfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"profile":"identity-user","identity_username":"ghost"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 502, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

func TestServeIssueIdentityUserMissingUsername(t *testing.T) {
	bridge := identityBridgeServer(t)
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
	}
	srv, _, _ := newTestServerWithIdentity(t, identityCfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// No identity_username and no cn.
	body := `{"profile":"identity-user"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

func TestServeReloadRebuildsIdentitySource(t *testing.T) {
	d := newTestDB(t)
	seedAdmin(t, d)
	caCert, caKey := newTestCA(t, "test-ca")
	d.InsertCAMeta(&db.CAMeta{
		Name: "test-ca", CertDER: caCert.Raw, Subject: caCert.Subject.String(),
		NotBefore: caCert.NotBefore, NotAfter: caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256", Fingerprint: db.Fingerprint(caCert.Raw),
	})
	dir := t.TempDir()
	certPath := dir + "/ca.pem"
	keyPath := dir + "/ca.key"
	writePEMFile(t, certPath, "CERTIFICATE", caCert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)
	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Serve.Static = ""
	cfg.Defaults.CA = "test-ca"
	cfg.CAs = map[string]internal.CAConfig{"test-ca": {Cert: certPath, Key: keyPath}}
	srv := NewFull(&cfg, d, testBundle, nil, nil)

	// Initially nil.
	if srv.getIdentitySource() != nil {
		t.Fatal("expected nil identity source initially")
	}

	// Reload with identity config.
	bridge := identityBridgeServer(t)
	defer bridge.Close()
	cfg.Identity = &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
	}
	srv.Reload(&cfg, d, nil, nil)
	if srv.getIdentitySource() == nil {
		t.Fatal("expected identity source after reload")
	}

	// Reload clearing identity config → nil again.
	cfg.Identity = nil
	srv.Reload(&cfg, d, nil, nil)
	if srv.getIdentitySource() != nil {
		t.Fatal("expected nil identity source after clearing")
	}
}

func TestServeIssueIdentityUserWithDefaultProfile(t *testing.T) {
	bridge := identityBridgeServer(t)
	defer bridge.Close()

	identityCfg := &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: bridge.URL, TimeoutSec: 5,
	}
	d := newTestDB(t)
	seedAdmin(t, d)
	caCert, caKey := newTestCA(t, "test-ca")
	d.InsertCAMeta(&db.CAMeta{
		Name: "test-ca", CertDER: caCert.Raw, Subject: caCert.Subject.String(),
		NotBefore: caCert.NotBefore, NotAfter: caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256", Fingerprint: db.Fingerprint(caCert.Raw),
	})
	dir := t.TempDir()
	certPath := dir + "/ca.pem"
	keyPath := dir + "/ca.key"
	writePEMFile(t, certPath, "CERTIFICATE", caCert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)
	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Serve.Static = ""
	cfg.Defaults.CA = "test-ca"
	cfg.Defaults.Profile = "identity-user"
	cfg.CAs = map[string]internal.CAConfig{"test-ca": {Cert: certPath, Key: keyPath}}
	cfg.Identity = identityCfg
	srv := NewFull(&cfg, d, testBundle, nil, nil)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"identity_username":"001"}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

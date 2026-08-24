// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/engine/db"
)

// ─── helpers ──────────────────────────────────────────────────────

func newTestServerWithDB(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	// authScopesCache is a package-level global (30s TTL). When different tests
	// reuse the same username, the cached scopes from a previous test can pollute
	// the next test (e.g. operator-cert revoked fail-closed semantics). Each test
	// has its own Server/DB, so we reset the cache on every creation.
	authScopesMu.Lock()
	authScopesCache = nil
	authScopesMu.Unlock()

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
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
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
	k8sOn := true
	cfg.K8sEnabled = &k8sOn

	tsaDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("tsa-ok"))
	})
	ocspDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write([]byte("ocsp-ok"))
	})

	b := i18n.NewBundle()
	srv := NewFull(&cfg, d, b, tsaDummy, ocspDummy)
	return srv, WrapHandler(srv)
}

func seedTrustAnchors(t *testing.T, d *db.DB) {
	t.Helper()
	now := time.Now()
	d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "Root CA", HashID: "root-hash-1",
		CertDER: []byte{0x30, 0x01}, Subject: "CN=Root CA",
		NotBefore: now, NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		Issuer: "CN=Root CA", Trusted: true, Source: "import",
		SubjectO: "Test Org", SubjectC: "US", KeyAlgo: "RSA", KeySize: 4096,
		SHA1Fingerprint: "aa:bb:cc", PathLen: 1,
	})
	d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "Sub CA", HashID: "sub-hash-1",
		CertDER: []byte{0x30, 0x02}, Subject: "CN=Sub CA",
		NotBefore: now, NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		Issuer: "CN=Root CA", Trusted: false, Source: "manual",
		SubjectO: "Other Org", SubjectC: "CN", KeyAlgo: "ECDSA", KeySize: 256,
	})
}

func authedPatch(t *testing.T, ts *httptest.Server, path, ctype string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest("PATCH", ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", "admin")
	req.Header.Set("Content-Type", ctype)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ─── Trust API ───────────────────────────────────────────────────

func TestAPITrustList(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var list []jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) < 2 {
		t.Fatalf("expected >=2 anchors, got %d", len(list))
	}
}

func TestAPITrustList_FilterTrusted(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust?trusted=true")
	defer resp.Body.Close()
	var list []jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&list)
	for _, a := range list {
		if !a.Trusted {
			t.Fatalf("expected all trusted, got %+v", a)
		}
	}
}

func TestAPITrustList_FilterSource(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust?source=import")
	defer resp.Body.Close()
	var list []jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 import anchor, got %d", len(list))
	}
}

func TestAPITrustList_FilterHashID(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust?hash_id=root-hash-1")
	defer resp.Body.Close()
	var list []jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 || list[0].HashID != "root-hash-1" {
		t.Fatalf("expected root-hash-1, got %+v", list)
	}
}

func TestAPITrustList_Pagination(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust?page=1&size=1")
	defer resp.Body.Close()
	var list []jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 on page 1, got %d", len(list))
	}
}

func TestAPITrustGet(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust/root-hash-1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var a jsonTrustAnchor
	json.NewDecoder(resp.Body).Decode(&a)
	if a.Name != "Root CA" {
		t.Fatalf("expected Root CA, got %s", a.Name)
	}
}

func TestAPITrustGet_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust/nonexistent")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPITrustSet(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body := `{"trusted":true}`
	resp := authedPatch(t, ts, "/api/v1/trust/sub-hash-1", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITrustSet_BadJSON(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPatch(t, ts, "/api/v1/trust/sub-hash-1", "application/json", strings.NewReader("bad{json"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPITrustDelete(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/trust/sub-hash-1", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITrustDelete_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/trust/nonexistent", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// db.DeleteTrustAnchor may return 200 (no-op) or 404 depending on implementation
	// DeleteTrustAnchor is a no-op for an unknown hash
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestAPITrustStats(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust/stats")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["total"] == nil {
		t.Fatal("expected total in stats")
	}
}

func TestAPITrustImport_PEM(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	pemData := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHB0xWJzKJqMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnJv
b3RDQTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnJvb3RDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyF+LJzG3jFz0OQ
K4v0vZVYpZ9dC0L7QH4zKk8N4cM5+R3nT2sW8x7dF6bA3vJ4hY9kO1pI2mE5n
L8qW3dF7gB5cR2nT8sX4kY6jH0vM1pQ3wE9bA7dL2hF5nK8cR4sJ6tY3wE2
gQIDAQABo1MwUTAdBgNVHQ4EFgQUqHZJW7q3dF7gB5cR2nT8sX4kY6jHwH
DwMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4GBAI3kH7sF8
-----END CERTIFICATE-----`
	body, _ := json.Marshal(map[string]string{"pem_bundle": pemData})
	resp := authedPost(t, ts, "/api/v1/trust/import", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITrustImport_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust/import")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPITrustImport_BadJSON(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/trust/import", "application/json", strings.NewReader("not-json"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPITrustImport_URL_Fetch(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Fetch from a non-existent URL should error
	body, _ := json.Marshal(map[string]string{"url": "http://localhost:1/unreachable"})
	resp := authedPost(t, ts, "/api/v1/trust/import", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAPITrustImport_EmptyPEM(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"pem_bundle": ""})
	resp := authedPost(t, ts, "/api/v1/trust/import", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// 200 with imported=0 or error
	// empty pem_bundle imports nothing but succeeds
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestAPITrustImport_Rebase(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	seedTrustAnchors(t, srv.getDB())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]interface{}{
		"pem_bundle": "", "rebase": true,
	})
	resp := authedPost(t, ts, "/api/v1/trust/import", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// Rebase + empty PEM = 200 with imported=0
	// rebase with empty pem_bundle succeeds (imported=0)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestDispatchTrustAPI_UnknownMethod(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/trust/some-hash", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestDispatchTrustAPI_RootPath(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/trust/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Dashboard API ───────────────────────────────────────────────

func TestAPIDashboard(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dashboard")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var stats DashboardStats
	json.NewDecoder(resp.Body).Decode(&stats)
	if stats.UpdatedAt == "" {
		t.Fatal("expected UpdatedAt")
	}
}

// ─── Stats API ───────────────────────────────────────────────────

func TestAPIStats(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/stats")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["updated_at"] == nil {
		t.Fatal("expected updated_at")
	}
}

// ─── Compliance Report ───────────────────────────────────────────

func TestAPIComplianceReport_SOC2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/reports/compliance?soc2=1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "pdf") {
		t.Fatalf("expected PDF content-type, got %s", ct)
	}
}

func TestAPIComplianceReport_PCI(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/reports/compliance?pci=1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIComplianceReport_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/reports/compliance", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── CRL API ─────────────────────────────────────────────────────

func TestAPIGetCRL_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/crl/nonexistent")
	defer resp.Body.Close()
	// CRL for unknown CA not found
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected NotFound, got %d", resp.StatusCode)
	}
}

// ─── Cross-certs API ─────────────────────────────────────────────

func TestAPICrossCerts_ListEmpty(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cross-certs")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Cert export ─────────────────────────────────────────────────

func TestAPIExportCert_NotFoundV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/NONEXISTENT2/export", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Renew cert ──────────────────────────────────────────────────

func TestAPIRenewCert_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/NONEXISTENT2/renew", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// renew of a nonexistent certificate
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected NotFound, got %d", resp.StatusCode)
	}
}

// ─── K8s sign ────────────────────────────────────────────────────

func TestAPIK8sSign_BadRequest(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/k8s/sign", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// missing required k8s signing fields
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Cert list with filters ──────────────────────────────────────

func TestAPICertList_CAFilter(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?ca=test-ca")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPICertList_StatusFilter(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?status=V")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPICertList_CNFilter(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?cn=example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPICertList_PageSize(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?page=1&size=1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── CA tree ─────────────────────────────────────────────────────

func TestAPICATree(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cas/tree")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Admin config with bad body ──────────────────────────────────

func TestAPIAdminConfig_Put_BadContentType(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/admin/config", "text/plain", strings.NewReader("not-json"))
	defer resp.Body.Close()
	// POST is not supported on the config endpoint
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected MethodNotAllowed, got %d", resp.StatusCode)
	}
}

// ─── Agent register ──────────────────────────────────────────────

func TestAPIAgentRegister(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{
		"common_name": "test-agent-boost",
		"ou":          "admin",
	})
	resp := authedPost(t, ts, "/api/v1/agent/register", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// agent register requires an mTLS client certificate
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected Unauthorized, got %d", resp.StatusCode)
	}
}

// ─── User operations ─────────────────────────────────────────────

func TestAPIUsersInfo(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users/info")
	defer resp.Body.Close()
	// users/info requires X-Auth-Token, basic auth gives 401 — that's fine
	// users/info requires X-Auth-Token, basic auth is rejected
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected Unauthorized, got %d", resp.StatusCode)
	}
}

// ─── Webhook operations ──────────────────────────────────────────

func TestAPIWebhooks_ListEmpty(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/webhooks")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── CSR sign ────────────────────────────────────────────────────

func TestAPICSRSign_EmptyBody(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/pkcs10", strings.NewReader(""))
	defer resp.Body.Close()
	// empty body is invalid JSON
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Cert get ────────────────────────────────────────────────────

func TestAPIGetCert_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cert/test-ca/NONEXISTENT3")
	defer resp.Body.Close()
	// nonexistent certificate
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected NotFound, got %d", resp.StatusCode)
	}
}

// ─── Cert revoke ─────────────────────────────────────────────────

func TestAPIRevokeCert_NotFoundV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/NONEXISTENT4/revoke", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// revoking a nonexistent certificate
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected InternalServerError, got %d", resp.StatusCode)
	}
}

// ─── CAS list ────────────────────────────────────────────────────

func TestAPIListCAs(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cas")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── CA info ─────────────────────────────────────────────────────

func TestAPIGetCA(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/ca/test-ca")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIGetCA_NotFound(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/ca/nonexistent-ca")
	defer resp.Body.Close()
	// unknown CA
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected NotFound, got %d", resp.StatusCode)
	}
}

// ─── CRL generate ────────────────────────────────────────────────

func TestAPIGenerateCRL(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/crl/test-ca/generate", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// CRL generation succeeds for test-ca
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

// TestAPIGenerateCRL_PersistsToOutputDir verifies the API-generated CRL is
// written to the configured crl.output_dir, so /healthz CRL freshness
// reflects it (the same behavior as CLI `pki crl generate`).
func TestAPIGenerateCRL_PersistsToOutputDir(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	outDir := t.TempDir()

	// Point the running server's CRL output dir at a temp dir.
	cfg := srv.getConfig()
	cfgCopy := *cfg
	cfgCopy.CRL.OutputDir = outDir
	srv.cfgPtr.Store(&cfgCopy)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/crl/test-ca/generate", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a persisted CRL file in crl.output_dir")
	}
	data, err := os.ReadFile(filepath.Join(outDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read persisted CRL: %v", err)
	}
	if _, err := x509.ParseRevocationList(data); err != nil {
		t.Fatalf("persisted CRL is not a valid DER CRL: %v", err)
	}
}

// ─── Cross-cert issue ────────────────────────────────────────────

func TestAPICrossCertIssue_BadRequest(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/issue", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// missing issuer/target fields
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_BadRequest(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/revoke", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// missing issuer/serial fields
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Verify cert ─────────────────────────────────────────────────

func TestAPIVerifyCert_BadRequest(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// missing pem in request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Async submit ────────────────────────────────────────────────

func TestAPIAsyncSubmit_BadJSON(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/certs/async", "application/json", strings.NewReader("bad"))
	defer resp.Body.Close()
	// malformed JSON body
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Cert issue ──────────────────────────────────────────────────

func TestAPIIssueCert_BadJSON(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// empty request object is rejected
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Dashboard SSE ───────────────────────────────────────────────

func TestAPIDashboardSSE(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dashboard/events")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
}

// ─── Stats SSE ───────────────────────────────────────────────────

func TestAPIStatsSSE(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/stats/events")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
}

// ─── dispatchTrustAPI root/default paths ──────────────────────────

func TestDispatchTrustAPI_DefaultPath(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// /trust (no trailing slash) should list
	resp := authedGet(t, ts, "/api/v1/trust")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── unused import guard ─────────────────────────────────────────

var (
	_ = crypto.Signer(nil)
	_ = ecdsa.PublicKey{}
	_ = elliptic.P256()
	_ = (*x509.Certificate)(nil)
	_ = pem.Encode
	_ = big.NewInt
	_ = strings.NewReader
	_ = fmt.Sprintf
	_ = bytes.NewReader
)

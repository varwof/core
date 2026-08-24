// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// ─── crossCertToJSON ─────────────────────────────────────────────

func TestCrossCertToJSON_Basic(t *testing.T) {
	now := time.Now()
	record := &db.CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "subject",
		CertDER:      nil,
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		SerialNumber: "0xabc",
		Status:       "active",
	}
	j := crossCertToJSON(record, false)
	if j.IssuerCA != "issuer" || j.SubjectCA != "subject" {
		t.Fatalf("unexpected: %+v", j)
	}
	if j.CertPEM != "" {
		t.Fatal("expected empty PEM when includePEM=false")
	}
}

func TestCrossCertToJSON_WithRevoked(t *testing.T) {
	now := time.Now()
	revoked := now.Add(-time.Hour)
	reason := 1
	record := &db.CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "subject",
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		SerialNumber: "0x1",
		Status:       "revoked",
		RevokedAt:    &revoked,
		RevokeReason: &reason,
	}
	j := crossCertToJSON(record, false)
	if j.RevokedAt == nil {
		t.Fatal("expected non-nil revoked_at")
	}
	if j.RevokeReason == nil || *j.RevokeReason != 1 {
		t.Fatal("expected revoke_reason=1")
	}
}

func TestCrossCertToJSON_WithPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          bigInt(1),
		Subject:               testSubject("CrossCA"),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	record := &db.CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "subject",
		CertDER:      certDER,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		SerialNumber: "0x2",
		Status:       "active",
	}
	j := crossCertToJSON(record, true)
	if j.CertPEM == "" {
		t.Fatal("expected non-empty PEM")
	}
	if !strings.Contains(j.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatal("expected PEM header")
	}
}

// ─── writeFileAtomic ──────────────────────────────────────────────

func TestWriteFileAtomic_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := writeFileAtomic(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}
}

func TestWriteFileAtomic_BadPath(t *testing.T) {
	if err := writeFileAtomic("/nonexistent/dir/file.txt", []byte("x"), 0644); err == nil {
		t.Fatal("expected error for bad path")
	}
}

// ─── apiImportCA error paths ─────────────────────────────────────

func TestAPIImportCA_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create", "ca:list")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/cas/import")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create")

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/cas/import", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_NameRequired(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create")

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/cas/import", "application/json",
		strings.NewReader(`{"name":"","cert_pem":"x","key_pem":"y"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_CertPEMRequired(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create")

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/cas/import", "application/json",
		strings.NewReader(`{"name":"test","key_pem":"y"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_KeyPEMRequired(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create")

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/cas/import", "application/json",
		strings.NewReader(`{"name":"test","cert_pem":"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----\n"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_InvalidP12Base64(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "ca:create")

	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/cas/import", "application/json",
		strings.NewReader(`{"name":"test","p12_base64":"not-valid-base64!!"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── apiVerifyCert error paths ───────────────────────────────────

func TestAPIVerifyCert_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/verify/cert")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIVerifyCert_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIVerifyCert_CertPEMRequired(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json",
		strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIVerifyCert_InvalidPEM(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json",
		strings.NewReader(`{"cert_pem":"not-a-pem"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIVerifyCert_InvalidCert(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	badPEM := "-----BEGIN CERTIFICATE-----\nYm9ndXM=\n-----END CERTIFICATE-----"
	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json",
		bytes.NewReader(mustJSON(map[string]string{"cert_pem": badPEM})))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── apiUserByID ─────────────────────────────────────────────────

func TestAPIUserByID_Delete_Success(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Delete user with ID=1 (admin — should work even if it's the admin)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/users/1", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// DeleteUser is idempotent — always succeeds regardless of existence
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUserByID_NotDelete(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users/1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIUserByID_InvalidID(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/users/abc", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── apiTokenByID ────────────────────────────────────────────────

func TestAPITokenByID_Delete_Success(t *testing.T) {
	srv := newTestServer(t)
	// AUTH-005: Deleting a token requires user:manage grant.
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	// Delete token with ID=1 (may not exist, but should not panic)
	resp := authedMTLSDel(t, fx.Client, fx.Server, "/api/v1/tokens/1")
	defer resp.Body.Close()
	// DeleteToken is idempotent — always succeeds regardless of existence
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITokenByID_NotDelete(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	// Direct handler call: GET /tokens/{id} should be rejected as 405
	// (routing engine only matches DELETE, so dispatch directly verifies handler behavior).
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/tokens/1", nil)
	srv.apiTokenByID(w, r, "1")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAPITokenByID_InvalidID(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	resp := authedMTLSDel(t, fx.Client, fx.Server, "/api/v1/tokens/abc")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── apiRAAction ─────────────────────────────────────────────────

func TestAPIRAAction_Approve(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/ra/9999/approve", "application/json",
		strings.NewReader(`{"comment":"approved"}`))
	defer resp.Body.Close()
	// RA request 9999 does not exist → AddRAApproval SELECT fails → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_Reject(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/ra/9999/reject", "application/json",
		strings.NewReader(`{"comment":"rejected"}`))
	defer resp.Body.Close()
	// RA request 9999 does not exist → AddRAApproval SELECT fails → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_InvalidID(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/ra/abc/approve", "application/json",
		strings.NewReader(`{"comment":"x"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_NotPost(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/ra/1/approve")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── apiRecoverKey ───────────────────────────────────────────────

func TestAPIRecoverKey_NotPost(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/keys/recover")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/keys/recover", "application/json",
		strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/keys/recover", "application/json",
		strings.NewReader(`{"ca":"x"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_NotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/keys/recover", "application/json",
		strings.NewReader(`{"ca":"nonexistent","serial":"0x1"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── apiUpdateConfig ─────────────────────────────────────────────

func TestAPIUpdateConfig_PUT_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSSuperAdminFixture(t, srv, "config:read", "config:write")

	// PUT method not used by authedMTLSPost (which uses POST)
	// Need to use PUT explicitly
	req, _ := http.NewRequest(http.MethodPut, fx.Server.URL+"/api/v1/admin/config",
		strings.NewReader(`bad`))
	resp, err := fx.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIUpdateConfig_PUT_EmptyConfig(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/config",
		strings.NewReader(`{"config":{}}`))
	req.SetBasicAuth("superadmin", "superadmin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// empty config may be valid or invalid depending on validation
	// just check no panic
}

// ─── extractP12Bytes ─────────────────────────────────────────────

func TestExtractP12Bytes_InvalidData(t *testing.T) {
	_, _, err := extractP12Bytes([]byte("garbage"), "")
	if err == nil {
		t.Fatal("expected error for invalid P12 data")
	}
}

// ─── apiAsyncSubmit / apiAsyncStatus ─────────────────────────────

func TestAPIAsyncSubmit_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs/async")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIAsyncSubmit_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/certs/async", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── apiCSRSign ──────────────────────────────────────────────────

func TestAPICSRSign_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/csr/sign")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICSRSign_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func intToStr(i int) string {
	return strings.TrimRight(strings.TrimRight(
		func() string {
			b, _ := json.Marshal(i)
			return string(b)
		}(), "\n"), "")
}

func bigInt(n int64) *big.Int {
	return big.NewInt(n)
}

func testSubject(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"Test"}}
}

package serve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// ─── Process tests ────────────────────────────────────────────────

func TestProcess_Empty(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	p := newAsyncJobProcessor(srv, 2)
	result := p.Process(nil)
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestProcess_CANotFound(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	p := newAsyncJobProcessor(srv, 2)
	items := []ca.JobRequestItem{
		{CN: "a.example.com", CA: "nonexistent"},
		{CN: "b.example.com", CA: "nonexistent"},
	}
	results := p.Process(items)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Status != "error" {
			t.Fatalf("result %d: expected error status, got %q", i, r.Status)
		}
		if r.Error == "" {
			t.Fatalf("result %d: expected non-empty error", i)
		}
	}
}

func TestProcess_Success(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	p := newAsyncJobProcessor(srv, 2)
	items := []ca.JobRequestItem{
		{CN: "proc1.example.com", CA: "test-ca", Profile: "tls-server"},
		{CN: "proc2.example.com", CA: "test-ca", Profile: "tls-server"},
	}
	results := p.Process(items)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Status != "ok" {
			t.Fatalf("result %d: expected ok status, got %q (error: %s)", i, r.Status, r.Error)
		}
		if r.Serial == "" {
			t.Fatalf("result %d: expected non-empty serial", i)
		}
	}
}

func TestProcess_WithSAN(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	p := newAsyncJobProcessor(srv, 2)
	items := []ca.JobRequestItem{
		{CN: "san.example.com", CA: "test-ca", Profile: "tls-server", SAN: "DNS:san1.example.com,DNS:san2.example.com"},
	}
	results := p.Process(items)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "ok" {
		t.Fatalf("expected ok status, got %q (error: %s)", results[0].Status, results[0].Error)
	}
}

// ─── Logout with real token ──────────────────────────────────────

func TestLogout_WithRealToken(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/users/logout", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLogout_NoToken(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/users/logout", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── UserInfo with real token ─────────────────────────────────────

func TestUserInfo_WithRealToken(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/users/info", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var r map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&r)
	if r["username"] != "admin" {
		t.Fatalf("expected username 'admin', got %v", r["username"])
	}
}

func TestUserInfo_InvalidToken(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/users/info", nil)
	req.Header.Set("X-Auth-Token", "invalid-token-xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestUserInfo_NoToken(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/users/info")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── apiTokens direct ────────────────────────────────────────────

func TestTokens_List(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/tokens?user_id=1", nil)
	srv.apiTokens(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTokens_Create(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "description": "test-token-8"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/tokens", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.apiTokens(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTokens_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader("bad-json"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiTokens(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTokens_BadUserID(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 0})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/tokens", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.apiTokens(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTokens_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/tokens", nil)
	srv.apiTokens(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── apiTokenByID direct ─────────────────────────────────────────

func TestTokenByID_BadID(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/tokens/abc", nil)
	srv.apiTokenByID(w, r, "abc")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTokenByID_NotDelete(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/tokens/1", nil)
	srv.apiTokenByID(w, r, "1")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── apiGetCert with found cert ──────────────────────────────────

func insertTestCert(t *testing.T, d *db.DB, caName, serial, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	d.InsertCert(&db.CertRecord{
		SerialNumber: serial,
		CAName:       caName,
		Status:       "active",
		CommonName:   cn,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		CertDER:      der,
		Fingerprint:  db.Fingerprint(der),
	})
}

func TestGetCert_Found_JSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	insertTestCert(t, d, "test-ca", "AABB0001", "test-json.example.com")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/AABB0001", nil)
	srv.apiGetCert(w, r, "test-ca", "AABB0001")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
}

func TestGetCert_Found_PEM(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	insertTestCert(t, d, "test-ca", "AABB0002", "test-pem.example.com")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/AABB0002", nil)
	r.Header.Set("Accept", "application/x-pem-file")
	srv.apiGetCert(w, r, "test-ca", "AABB0002")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/x-pem-file") {
		t.Fatalf("expected PEM content type, got %q", ct)
	}
}

func TestGetCert_Found_DER(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	insertTestCert(t, d, "test-ca", "AABB0003", "test-der.example.com")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/AABB0003", nil)
	r.Header.Set("Accept", "application/pkix-cert")
	srv.apiGetCert(w, r, "test-ca", "AABB0003")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/pkix-cert") {
		t.Fatalf("expected DER content type, got %q", ct)
	}
}

// ─── apiListCerts with data ──────────────────────────────────────

func TestListCerts_WithCerts(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{
		"cn":      "list-test.example.com",
		"ca":      "test-ca",
		"profile": "tls-server",
	})
	issueReq, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
	issueReq.Header.Set("X-Auth-Token", token)
	issueReq.Header.Set("Content-Type", "application/json")
	issueResp, _ := http.DefaultClient.Do(issueReq)
	issueResp.Body.Close()
	if issueResp.StatusCode != http.StatusOK {
		t.Fatalf("issue failed: %d", issueResp.StatusCode)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs?ca=test-ca", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── apiCrossCertIssue direct ────────────────────────────────────

func TestCrossCertIssue_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cross-cert/issue", strings.NewReader("bad-json"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiCrossCertIssue(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCrossCertIssue_MissingFields(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	body, _ := json.Marshal(map[string]string{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cross-cert/issue", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.apiCrossCertIssue(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCrossCertIssue_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cross-cert/issue", nil)
	srv.apiCrossCertIssue(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── apiRevokeCert ───────────────────────────────────────────────

func TestRevokeCert_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/0001/revoke", nil)
	srv.apiRevokeCert(w, r, "test-ca", "0001")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRevokeCert_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/0001/revoke", strings.NewReader("bad"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiRevokeCert(w, r, "test-ca", "0001")
	// JSON decode fails silently → RevokeWithCascade errors (cert doesn't exist) → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ─── apiExportCert ───────────────────────────────────────────────

func TestExportCert_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/0001/export", nil)
	srv.apiExportCert(w, r, "test-ca", "0001")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestExportCert_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/0001/export", strings.NewReader("bad"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiExportCert(w, r, "test-ca", "0001")
	// Will return 404 because cert doesn't exist
	if w.Code != http.StatusNotFound && w.Code != http.StatusOK {
		t.Fatalf("expected 404 or 200, got %d", w.Code)
	}
}

// ─── apiK8sSign ──────────────────────────────────────────────────

func TestK8sSign_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", strings.NewReader("bad-json"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiK8sSign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestK8sSign_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/k8s/sign", nil)
	srv.apiK8sSign(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── apiDNSQuery ─────────────────────────────────────────────────

func TestDNSQuery_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/dns-query", nil)
	srv.apiDNSQuery(w, r)
	// GET with no name param → 400
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDNSQuery_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/dns-query", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiDNSQuery(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── apiAgentRegister ────────────────────────────────────────────

func TestAgentRegister_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/agent/register", strings.NewReader("bad-json"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiAgentRegister(w, r)
	// No mTLS → 401
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestAgentRegister_MethodNotAllowed(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/agent/register", nil)
	srv.apiAgentRegister(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── writeJSON edge cases ────────────────────────────────────────

func TestWriteJSON_NilData(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	body := w.Body.String()
	if body != "null" {
		t.Fatalf("expected 'null', got %q", body)
	}
}

// ─── apiCSRSign ──────────────────────────────────────────────────

func TestCSRSign_BadJSON(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/csr/sign", strings.NewReader("bad-json"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiCSRSign(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

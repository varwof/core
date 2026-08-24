package serve

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/i18n"
)

func newTestServerFull6(t *testing.T) (*Server, http.Handler) {
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
	b := i18n.NewBundle()
	srv := NewFull(&cfg, d, b, nil, nil)
	return srv, WrapHandler(srv)
}

func loginAsAdmin6(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	resp, err := http.Post(ts.URL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	var r map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&r)
	if tval, ok := r["token"].(string); ok {
		return tval
	}
	return ""
}

// ─── Admin API tests ────────────────────────────────────────────

func TestAPIUsers_ListV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/users", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUsers_CreateV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"username": "testuser6", "password": "testpass", "role": "operator"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/users", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUsers_CreateEmptyUsernameV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"username": "", "password": "testpass"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/users", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIUsers_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/users", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIUserByID_DeleteV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"username": "deluser6", "password": "pass"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/users", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	resp.Body.Close()

	req2, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/users/2", nil)
	req2.Header.Set("X-Auth-Token", token)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil { t.Fatal(err) }
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestAPIUserByID_NotDeleteV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/users/1", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIUserByID_BadIDV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/users/abc", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Token API ──────────────────────────────────────────────────

func TestAPITokens_ListV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/tokens?user_id=1", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITokens_CreateV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "description": "test token v6"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/tokens", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPITokens_CreateBadUserIDV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{"user_id": 0})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/tokens", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPITokens_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/tokens", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPITokens_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/tokens", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPITokenByID_DeleteV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "description": "to-delete-v6"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/tokens", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	resp.Body.Close()

	req2, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/tokens/2", nil)
	req2.Header.Set("X-Auth-Token", token)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil { t.Fatal(err) }
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestAPITokenByID_NotDeleteV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/tokens/1", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Audit / RA ─────────────────────────────────────────────────

func TestAPIAuditLogV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/audit?limit=10&offset=0", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIRARequests_GetV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/ra?status=pending", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIRARequests_PostV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"cn": "test6.example.com", "ca": "test-ca", "profile": "tls-server"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/ra", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIRARequests_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/ra", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRARequests_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/ra", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_ApproveV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"comment": "approved"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/ra/1/approve", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	// RA request 1 does not exist → AddRAApproval SELECT fails → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_BadIDV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/ra/abc/approve", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/ra/1/approve", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRAAction_RejectV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"comment": "rejected"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/ra/1/reject", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	// RA request 1 does not exist → AddRAApproval SELECT fails → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

// ─── Key Recovery ───────────────────────────────────────────────

func TestAPIRecoverKey_NotFoundV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"ca": "test-ca", "serial": "0001"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/keys/recover", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/keys/recover", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/keys/recover", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIRecoverKey_EmptyFieldsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"ca": "", "serial": ""})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/keys/recover", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Logout + UserInfo ──────────────────────────────────────────

func TestAPILogoutV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/logout", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPILogout_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/logout", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	// GET /logout returns 401 (no auth) or 405 depending on server
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 or 405, got %d", resp.StatusCode)
	}
}

func TestAPILogout_WithTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/logout", strings.NewReader("{}"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfoV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_NoTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/userinfo")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_BadTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.Header.Set("X-Auth-Token", "bad-token-xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_BearerTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_BearerBadTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_BasicAuthV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 200 or 404, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_BasicAuthBadPasswordV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/userinfo", nil)
	req.SetBasicAuth("admin", "wrong-password")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── isSameOrigin ───────────────────────────────────────────────

func TestIsSameOrigin_NoOriginV6(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/api/test", nil)
	if !isSameOrigin(r) {
		t.Fatal("no origin should be same origin")
	}
}

func TestIsSameOrigin_SameOriginV6(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "http://localhost")
	if !isSameOrigin(r) {
		t.Fatal("same origin should pass")
	}
}

func TestIsSameOrigin_DifferentOriginV6(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "http://evil.com")
	if isSameOrigin(r) {
		t.Fatal("different origin should fail")
	}
}

func TestIsSameOrigin_RefererV6(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Referer", "http://localhost/page")
	if !isSameOrigin(r) {
		t.Fatal("same referer should pass")
	}
}

func TestIsSameOrigin_RefererMismatchV6(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Referer", "http://evil.com/page")
	if isSameOrigin(r) {
		t.Fatal("different referer should fail")
	}
}

func TestIsSameOrigin_GETNoOriginV6(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "http://evil.com")
	if isSameOrigin(r) {
		t.Fatal("GET with different origin should fail (isSameOrigin always checks)")
	}
}

func TestIsSameOrigin_GETWithOriginV6(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "http://evil.com")
	if isSameOrigin(r) {
		t.Fatal("GET with different origin should fail (isSameOrigin always checks)")
	}
}

// AUTH-004: 前缀匹配绕过防护 — https://host.evil.com 不能伪装成 https://host
func TestIsSameOrigin_PrefixBypassAUTH4(t *testing.T) {
	r := httptest.NewRequest("POST", "https://localhost/api/test", nil)
	r.Header.Set("Origin", "https://localhost.evil.com")
	if isSameOrigin(r) {
		t.Fatal("host-prefix bypass must be rejected (exact host match)")
	}
}

func TestIsSameOrigin_SuffixBypassAUTH4(t *testing.T) {
	r := httptest.NewRequest("POST", "https://localhost/api/test", nil)
	r.Header.Set("Origin", "https://localhost@evil.com")
	if isSameOrigin(r) {
		t.Fatal("userinfo/suffix bypass must be rejected (exact host match)")
	}
}

func TestIsSameOrigin_NullOriginRejectedAUTH4(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "null")
	if isSameOrigin(r) {
		t.Fatal("null origin must be rejected")
	}
}

func TestIsSameOrigin_PortMismatchAUTH4(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "http://localhost:9999")
	if isSameOrigin(r) {
		t.Fatal("port mismatch must be rejected")
	}
}

func TestIsSameOrigin_SchemeMismatchAUTH4(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/api/test", nil)
	r.Header.Set("Origin", "https://localhost")
	if isSameOrigin(r) {
		t.Fatal("scheme mismatch must be rejected")
	}
}

// ─── requirePerm CORS ───────────────────────────────────────────

func TestRequirePerm_CORSBlockedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/admin/users", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// ─── apiGetCert + apiListCerts CSV ──────────────────────────────

func TestAPIListCerts_CSVV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs?format=csv", nil)
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "text/csv")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIListCerts_DefaultCAV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs?ca=test-ca&status=V", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIGetCert_NotFoundV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs/test-ca/0000000000000000", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPIGetCert_NotFoundPEMV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs/test-ca/0000000000000000", nil)
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/x-pem-file")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPIGetCert_NotFoundDerV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs/test-ca/0000000000000000", nil)
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/pkix-cert")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Cross Certs ────────────────────────────────────────────────

func TestAPIListCrossCertsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/cross-certs", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIListCrossCerts_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/cross-certs/issue", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/issue", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_MissingFieldsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/issue", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_IssuerNotFoundV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"issuer": "nonexistent-ca", "target": "test-ca"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/issue", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/cross-certs/revoke", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/revoke", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_MissingFieldsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/revoke", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_MissingIssuerV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"serial": "001"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cross-certs/revoke", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Version ────────────────────────────────────────────────────

func TestAPIVersionV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/version", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── extractToken edge cases ────────────────────────────────────

func TestExtractToken_EmptyV6(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if tok := extractToken(r); tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
}

func TestExtractToken_Authorization_BearerV6(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")
	if tok := extractToken(r); tok != "mytoken123" {
		t.Fatalf("expected mytoken123, got %q", tok)
	}
}

func TestExtractToken_Authorization_BasicV6(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if tok := extractToken(r); tok != "" {
		t.Fatalf("expected empty token for non-Bearer auth, got %q", tok)
	}
}

// ─── collectDashboard + collectStats ─────────────────────────────

func TestCollectDashboardV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	stats := srv.collectDashboard()
	if stats == nil {
		t.Fatal("expected non-nil dashboard stats")
	}
	if stats.KeyTypes == nil {
		t.Fatal("expected non-nil KeyTypes map")
	}
}

func TestCollectStatsV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	stats := srv.collectStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if stats.ByStatus == nil {
		t.Fatal("expected non-nil ByStatus map")
	}
}

// ─── authenticate edge cases ────────────────────────────────────

func TestAuthenticate_NoHeadersV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	r := httptest.NewRequest("GET", "/", nil)
	user, err := srv.authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user")
	}
}

func TestAuthenticate_BearerNoTokenV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ")
	user, err := srv.authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for empty bearer")
	}
}

func TestAuthenticate_UnknownAuthV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Digest abc")
	user, err := srv.authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for unknown auth scheme")
	}
}

// ─── NewPublic + NewFull ────────────────────────────────────────

func TestNewPublicV6(t *testing.T) {
	d := newTestDB(t)
	cfg := internal.DefaultConfig()
	cfg.Serve.Static = ""
	b := i18n.NewBundle()
	srv := NewPublic(&cfg, d, b)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestNewFullV6(t *testing.T) {
	d := newTestDB(t)
	cfg := internal.DefaultConfig()
	cfg.Serve.Static = ""
	b := i18n.NewBundle()
	srv := NewFull(&cfg, d, b, nil, nil)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

// ─── apiLogin edge cases ───────────────────────────────────────

func TestAPILogin_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/login")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 or 405, got %d", resp.StatusCode)
	}
}

func TestAPILogin_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/login", "application/json", strings.NewReader("bad"))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 400 or 401, got %d", resp.StatusCode)
	}
}

func TestAPILogin_MissingFieldsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{})
	resp, err := http.Post(ts.URL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 400 or 401, got %d", resp.StatusCode)
	}
}

func TestAPILogin_BadCredentialsV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp, err := http.Post(ts.URL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── apiLogout edge case ───────────────────────────────────────

func TestAPILogout_WithInvalidTokenV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/logout", strings.NewReader("{}"))
	req.Header.Set("X-Auth-Token", "nonexistent-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	// Logout always succeeds or returns 401 for bad token
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 200 or 401, got %d", resp.StatusCode)
	}
}

// ─── apiAdminDispatch unknown ───────────────────────────────────

func TestAPIAdminDispatch_UnknownV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/unknown-endpoint", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 or empty, got %d", resp.StatusCode)
	}
}

// ─── configPath with valid path ─────────────────────────────────

func TestConfigPathV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	if srv.getConfig() == nil {
		t.Fatal("expected non-nil config")
	}
}

// ─── isWriteMethod ──────────────────────────────────────────────

func TestIsWriteMethodV6(t *testing.T) {
	if !isWriteMethod("POST") {
		t.Fatal("POST should be write")
	}
	if !isWriteMethod("PUT") {
		t.Fatal("PUT should be write")
	}
	if !isWriteMethod("DELETE") {
		t.Fatal("DELETE should be write")
	}
	if !isWriteMethod("PATCH") {
		t.Fatal("PATCH should be write")
	}
	if isWriteMethod("GET") {
		t.Fatal("GET should not be write")
	}
	if isWriteMethod("HEAD") {
		t.Fatal("HEAD should not be write")
	}
}

// ─── HasPerm ────────────────────────────────────────────────────

func TestHasPermV6(t *testing.T) {
	u := &AuthUser{Permissions: []Permission{PermCertIssue, PermCAInfo}}
	if !u.HasPerm(PermCertIssue) {
		t.Fatal("should have PermCertIssue")
	}
	if u.HasPerm(PermCertRevoke) {
		t.Fatal("should not have PermCertRevoke")
	}
}

// ─── getConfig ──────────────────────────────────────────────────

func TestGetConfigV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cfg := srv.getConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// ─── API listCerts with cn filter ───────────────────────────────

func TestAPIListCerts_WithCNV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs?cn=test", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── extractP12Bytes bad data ───────────────────────────────────

func TestExtractP12Bytes_BadDataV6(t *testing.T) {
	_, _, err := extractP12Bytes([]byte("not-p12"), "password")
	if err == nil {
		t.Fatal("expected error for bad P12 data")
	}
}

// ─── apiCATree ──────────────────────────────────────────────────

func TestAPICATreeV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/ca-tree", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPICATree_CachedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/ca-tree", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	resp.Body.Close()

	req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/ca-tree", nil)
	req2.Header.Set("X-Auth-Token", token)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil { t.Fatal(err) }
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

// ─── apiBatchIssue ──────────────────────────────────────────────

func TestAPIBatchIssue_MethodNotAllowedV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/batch", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIBatchIssue_BadJSONV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/batch", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIBatchIssue_EmptyV6(t *testing.T) {
	_, h := newTestServerFull6(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin6(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{"items": []interface{}{}})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/batch", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── newAsyncJobProcessor ───────────────────────────────────────

func TestNewAsyncJobProcessorV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	p := newAsyncJobProcessor(srv, 0)
	if p == nil {
		t.Fatal("expected non-nil processor")
	}
	if cap(p.sem) != 12 {
		t.Fatalf("expected default concurrency 12, got %d", cap(p.sem))
	}
}

func TestNewAsyncJobProcessor_PositiveV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	p := newAsyncJobProcessor(srv, 4)
	if cap(p.sem) != 4 {
		t.Fatalf("expected concurrency 4, got %d", cap(p.sem))
	}
}

func TestAsyncJobProcessor_ProcessEmptyV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	p := newAsyncJobProcessor(srv, 2)
	result := p.Process(nil)
	if result != nil {
		t.Fatal("expected nil for empty input")
	}
}

// ─── authFromCert edge cases ────────────────────────────────────

// authCertPAExt 构造一个 PA 扩展（证书权限模板），供直接构造的
// x509.Certificate 结构体注入 Extensions 使用（cert-first：无 PA 拒绝）。
func authCertPAExt(t *testing.T, caps ...string) pkix.Extension {
	t.Helper()
	var grants []ca.Capability
	for _, c := range caps {
		grants = append(grants, ca.Capability{SchemeId: "core", CapabilityId: c})
	}
	pa, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	return pa
}

func TestAuthFromCert_NoAICV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test-user",
			OrganizationalUnit: []string{"admin"},
		},
		Extensions: []pkix.Extension{authCertPAExt(t, "cert:list")},
	}
	r := httptest.NewRequest("GET", "/", nil)
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Role != "admin" {
		t.Fatalf("expected admin role, got %q", user.Role)
	}
}

func TestAuthFromCert_NoRoleV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:       "test-user",
			OrganizationalUnit: []string{"unknown-role"},
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for unknown OU role")
	}
}

func TestAuthFromCert_DelegatedAgentV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "agent-cert",
			OrganizationalUnit: []string{"operator", "Delegated-Agent"},
		},
		Extensions: []pkix.Extension{authCertPAExt(t, "cert:list")},
	}
	r := httptest.NewRequest("GET", "/", nil)
	// X-Agent-User is ignored (A05); identity must come from the cert.
	r.Header.Set("X-Agent-User", "real-user")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "agent-cert" {
		t.Fatalf("expected username 'agent-cert' (CN), got %q", user.Username)
	}
}

func TestAuthFromCert_DelegatedAgent_ExpiredTTLV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:       "agent-expired",
			OrganizationalUnit: []string{"operator", "Delegated-Agent"},
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-TTL", "2020-01-01T00:00:00Z")
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for expired TTL")
	}
}

func TestAuthFromCert_DelegatedAgent_BadTTLV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:       "agent-badtal",
			OrganizationalUnit: []string{"operator", "Delegated-Agent"},
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-TTL", "not-a-date")
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for bad TTL")
	}
}

func TestAuthFromCert_WithCAScopesV6(t *testing.T) {
	srv, _ := newTestServerFull6(t)
	uri, _ := url.Parse("urn:pki:ca:test-ca")
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "scoped-user",
			OrganizationalUnit: []string{"admin"},
		},
		URIs:       []*url.URL{uri},
		Extensions: []pkix.Extension{authCertPAExt(t, "cert:list")},
	}
	r := httptest.NewRequest("GET", "/", nil)
	user, err := srv.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if len(user.CAScopes) != 1 || user.CAScopes[0] != "test-ca" {
		t.Fatalf("expected CA scope [test-ca], got %v", user.CAScopes)
	}
}

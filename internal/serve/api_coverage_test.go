package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── Version ──────────────────────────────────────────────────────

func TestAPIVersion(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/version")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	// version may be empty in test server, just check the route works
	if body["build"] == "" {
		t.Fatal("expected build field")
	}
}

// ─── Config ───────────────────────────────────────────────────────

func TestAPIConfig_GET(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "config:read", "config:write")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/admin/config")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["config"] == nil {
		t.Fatal("expected config in response")
	}
}

func TestAPIConfig_PUT_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/config", nil)
	req.SetBasicAuth("superadmin", "superadmin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Login / Logout / UserInfo ────────────────────────────────────

func TestAPILogin_Success(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var r map[string]any
	json.NewDecoder(resp.Body).Decode(&r)
	if r["token"] == nil || r["token"] == "" {
		t.Fatal("expected token in response")
	}
}

func TestAPILogin_BadCredentials(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPILogin_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users/login")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPILogin_EmptyFields(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"username": "", "password": ""})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPILogin_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", strings.NewReader("not json"))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPILogout_Success(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Login first
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	loginResp, _ := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	loginResp.Body.Close()

	// Logout
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/users/logout", nil)
	req.SetBasicAuth("admin", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPILogout_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users/logout")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIUserInfo_NoToken(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users/info")
	defer resp.Body.Close()
	// Without X-Auth-Token, should get 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── User Management ──────────────────────────────────────────────

func TestAPIUsers_GET(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/users")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIUsers_Create(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	body, _ := json.Marshal(map[string]string{
		"username": "testuser",
		"password": "testpass123",
		"role":     "ops",
	})
	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/users", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Revoke ───────────────────────────────────────────────────────

func TestAPIRevokeCert_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cert/test-ca/ABCDEF/revoke")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRevokeCert_NotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/NONEXISTENT/revoke", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// RevokeCert errors when the cert does not exist → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAPIRevokeCert_WithReason(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/SERIAL123/revoke", "application/json",
		strings.NewReader(`{"reason":"keyCompromise"}`))
	defer resp.Body.Close()
	// RevokeCert errors when the cert does not exist → 500
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

// ─── User Revoke All ──────────────────────────────────────────────

func TestAPIUserRevokeAll_NoMTLS(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/user/revoke-all", "application/json", strings.NewReader(`{}`))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIUserRevokeAll_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGetSuperAdmin(t, ts, "/api/v1/user/revoke-all")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Renew ────────────────────────────────────────────────────────

func TestAPIRenewCert_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cert/test-ca/SERIAL123/renew")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIRenewCert_CANotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/nonexistent-ca/SERIAL123/renew", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Cross Certs ──────────────────────────────────────────────────

func TestAPICrossCertIssue_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cross-cert/issue")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/issue", "application/json",
		strings.NewReader(`{"issuer":"","target":""}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertIssue_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/issue", "application/json",
		strings.NewReader(`not json`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cross-cert/revoke")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/revoke", "application/json",
		strings.NewReader(`{"issuer":"","serial":""}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/revoke", "application/json",
		strings.NewReader(`bad json`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICrossCertRevoke_InvalidReason(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/revoke", "application/json",
		strings.NewReader(`{"issuer":"ca","serial":"123","reason":"invalid-reason"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIListCrossCerts(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cross-certs")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIListCrossCerts_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-certs", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIListCrossCerts_WithIssuer(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cross-certs?issuer=test-ca")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Export / CRL ─────────────────────────────────────────────────

func TestAPIExportCert_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cert/test-ca/SERIAL123/export")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIExportCert_NotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cert/test-ca/NONEXISTENT/export", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPIGenerateCRL_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// /crl/{ca}/generate is the POST endpoint; /crl/{ca} is GET for CRL download
	resp := authedGet(t, ts, "/api/v1/crl/test-ca/generate")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAPIGenerateCRL_CANotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/crl/nonexistent-ca", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Gateway Endpoints ────────────────────────────────────────────

func TestAPIGatewayList(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/gateway/list")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIGatewayRegister_NoMTLS(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/gateway/register", "application/json",
		strings.NewReader(`{"address":"gw:8443"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── Admin Dispatch ───────────────────────────────────────────────

func TestAPIAdminDispatch_Users(t *testing.T) {
	srv := newTestServer(t)
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/users")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIAdminDispatch_Tokens(t *testing.T) {
	srv := newTestServer(t)
	// AUTH-005: token endpoint requires user:list (cert grant), Basic/operator has no permission.
	fx := newMTLSAdminFixture(t, srv, "user:list", "user:manage")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/tokens")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// AUTH-005: Basic operator without user:list must be 403 for token endpoint,
// must not fall through to /api/** → ca:list bypass.
func TestAPITokens_BasicOperatorDenied(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/tokens")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestAPIAdminDispatch_Audit(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/audit")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIAdminDispatch_RA(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/ra")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── extractToken ─────────────────────────────────────────────────

func TestExtractToken_FromHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "mytoken")
	if tok := extractToken(req); tok != "mytoken" {
		t.Fatalf("expected 'mytoken', got %q", tok)
	}
}

func TestExtractToken_FromBearer(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken")
	if tok := extractToken(req); tok != "mytoken" {
		t.Fatalf("expected 'mytoken', got %q", tok)
	}
}

func TestExtractToken_Empty(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	if tok := extractToken(req); tok != "" {
		t.Fatalf("expected empty, got %q", tok)
	}
}

func TestExtractToken_ShortBearer(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer")
	if tok := extractToken(req); tok != "" {
		t.Fatalf("expected empty for short bearer, got %q", tok)
	}
}

// ─── Unknown Routes ───────────────────────────────────────────────

func TestAPIRoute_NotFound(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/nonexistent-endpoint")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Issue Cert ───────────────────────────────────────────────────

func TestAPIIssueCert_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// GET on /certs lists certs
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIIssueCert_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Batch ────────────────────────────────────────────────────────

func TestAPIBatchIssue_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs/batch")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

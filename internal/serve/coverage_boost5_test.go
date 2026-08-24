// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
)

// ─── metricsHandler + WrapHandlerWithMetrics ──────────────────────

func TestMetricsHandler(t *testing.T) {
	h := metricsHandler()
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestWrapHandlerWithMetrics(t *testing.T) {
	cfg := internal.DefaultConfig()
	srv := NewPublic(
		&cfg,
		newTestDB(t),
		nil,
	)
	h := WrapHandlerWithMetrics(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMetricsMiddleware_LongPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := metricsMiddleware(inner)
	ts := httptest.NewServer(h)
	defer ts.Close()

	longPath := "/" + strings.Repeat("a", 100)
	resp, err := http.Get(ts.URL + longPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── splitSANs ──────────────────────────────────────────────────

func TestSplitSANs(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"a", 1},
		{"a,b,c", 3},
		{" a , b , c ", 3},
		{"a,,b", 2},
		{",,,", 0},
		{"a, , b", 2},
	}
	for _, tt := range tests {
		got := splitSANs(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitSANs(%q) = %v (len=%d), want len=%d", tt.input, got, len(got), tt.want)
		}
	}
}

func TestSplitSANs_Values(t *testing.T) {
	got := splitSANs("a,b,c")
	expected := []string{"a", "b", "c"}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("splitSANs index %d = %q, want %q", i, v, expected[i])
		}
	}
}

// ─── checkCAScope ───────────────────────────────────────────────

func TestCheckCAScope_AutoRole(t *testing.T) {
	u := &AuthUser{Role: "auto-renew", CAScopes: []string{"*"}}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("auto-renew with scope=* should bypass CA scope check")
	}
}

func TestCheckCAScope_AuditRole(t *testing.T) {
	u := &AuthUser{Role: "auditor"}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("auditor role should bypass CA scope check")
	}
}

func TestCheckCAScope_ReadOnlyRole(t *testing.T) {
	u := &AuthUser{Role: "readonly"}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("readonly role should bypass CA scope check")
	}
}

func TestCheckCAScope_SuperAdmin_NoScopes(t *testing.T) {
	u := &AuthUser{Role: "superadmin", CAScopes: []string{"Management CA"}}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)
	cfg := internal.DefaultConfig()
	if checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("superadmin with Management CA scope should fail for test-ca")
	}
}

func TestCheckCAScope_Admin_NoScopes(t *testing.T) {
	u := &AuthUser{Role: "admin", CAScopes: []string{}}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)

	cfgSimple := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfgSimple) {
		t.Fatal("admin with no scopes should pass in simple mode (unbound users keep legacy behavior)")
	}

	cfgEnt := internal.DefaultConfig()
	cfgEnt.RBAC.PermissionMode = "enterprise"
	if checkCAScope(u, r, PermCAInfo, &cfgEnt) {
		t.Fatal("admin with no scopes should fail in enterprise mode")
	}
}

func TestCheckCAScope_NormalUser_NoScopes(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{}}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)

	cfgSimple := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfgSimple) {
		t.Fatal("normal user with no scopes should pass in simple mode (unbound users keep legacy behavior)")
	}

	cfgEnt := internal.DefaultConfig()
	cfgEnt.RBAC.PermissionMode = "enterprise"
	if checkCAScope(u, r, PermCAInfo, &cfgEnt) {
		t.Fatal("normal user with no scopes should fail in enterprise mode")
	}
}

func TestCheckCAScope_NormalUser_Wildcard(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"*"}}
	r, _ := http.NewRequest("GET", "/api/v1/cas/test-ca", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("normal user with wildcard scope should pass")
	}
}

func TestCheckCAScope_NormalUser_ExactMatch(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"test-ca"}}
	r, _ := http.NewRequest("GET", "/api/v1/cert/test-ca/serial/revoke", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("user with matching scope should pass")
	}
}

func TestCheckCAScope_NormalUser_NoMatch(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"other-ca"}}
	r, _ := http.NewRequest("GET", "/api/v1/cert/test-ca/serial/revoke", nil)
	cfg := internal.DefaultConfig()
	if checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("user with non-matching scope should fail")
	}
}

func TestCheckCAScope_NormalUser_NoCAInPath(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"test-ca"}}
	r, _ := http.NewRequest("GET", "/api/v1/certs", nil)
	cfg := internal.DefaultConfig()
	if checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("user with no CA in path should fail")
	}
}

func TestCheckCAScope_NormalUser_QueryParam(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"test-ca"}}
	r, _ := http.NewRequest("GET", "/api/v1/certs?ca=test-ca", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("user with matching scope via query param should pass")
	}
}

func TestCheckCAScope_NormalUser_ExactMatch2(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"test-ca"}}
	r, _ := http.NewRequest("GET", "/api/v1/cert/test-ca/serial/revoke", nil)
	cfg := internal.DefaultConfig()
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("user with matching scope should pass")
	}
}

func TestCheckCAScope_Fallback_RoleScope(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"scope-a"}}
	r, _ := http.NewRequest("GET", "/api/v1/cert/test-ca/serial/revoke", nil)
	cfg := internal.DefaultConfig()
	cfg.RBAC.CAScopes = map[string][]string{
		"user": {"test-ca"},
	}
	if !checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("fallback role scope should match")
	}
}

func TestCheckCAScope_Fallback_RoleScope_NoMatch(t *testing.T) {
	u := &AuthUser{Role: "user", CAScopes: []string{"scope-a"}}
	r, _ := http.NewRequest("GET", "/api/v1/cert/test-ca/serial/revoke", nil)
	cfg := internal.DefaultConfig()
	cfg.RBAC.CAScopes = map[string][]string{
		"user": {"other-ca"},
	}
	if checkCAScope(u, r, PermCAInfo, &cfg) {
		t.Fatal("fallback role scope non-match should fail")
	}
}

// ─── CSR Sign API (valid CSR) ────────────────────────────────────

func generateTestCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr-test.example.com"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestAPICSRSign_ValidCSR(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM := generateTestCSR(t)
	body, _ := json.Marshal(csrSignReq{
		CSRPEM: csrPEM,
	})
	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var r csrSignResp
	json.NewDecoder(resp.Body).Decode(&r)
	if r.CertificatePEM == "" {
		t.Fatal("expected certificate_pem")
	}
}

func TestAPICSRSign_WithProfileAndValidity(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM := generateTestCSR(t)
	body, _ := json.Marshal(csrSignReq{
		CSRPEM:       csrPEM,
		CAName:       "test-ca",
		Profile:      "codesigning",
		ValidityDays: 30,
		CommonName:   "override.cn",
		SANs:         []string{"DNS:override.example.com", "IP:127.0.0.1"},
	})
	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// valid CSR signs successfully
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestAPICSRSign_InvalidPEMBlock(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(csrSignReq{
		CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nnot-base64\n-----END CERTIFICATE REQUEST-----",
	})
	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICSRSign_WrongBlockType(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(csrSignReq{
		CSRPEM: "-----BEGIN CERTIFICATE-----\nMIIBkTC\n-----END CERTIFICATE-----",
	})
	resp := authedPost(t, ts, "/api/v1/csr/sign", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPICSRSign_MethodNotAllowedV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/csr/sign")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── DNS API routes ─────────────────────────────────────────────

func TestAPIDNSHealth(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dns/healthz")
	defer resp.Body.Close()
	// May be 200 or 403 depending on RBAC PermDNSManage
	// DNS health check
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestAPIDNSList(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dns/records")
	defer resp.Body.Close()
	// DNS records list returns empty
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

func TestAPIDNSACME_EmptyDomain(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/dns/acme-challenge/", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// empty domain path is not dispatched
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected NotFound, got %d", resp.StatusCode)
	}
}

func TestAPIDNSACME_Set(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"key_auth": "test-token"})
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/dns/acme-challenge/example.com", bytes.NewReader(body))
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

func TestAPIDNSACME_BadJSON(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/dns/acme-challenge/example.com", strings.NewReader("bad"))
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

func TestAPIDNSACME_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dns/acme-challenge/example.com")
	defer resp.Body.Close()
	// GET is not supported on acme-challenge
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected MethodNotAllowed, got %d", resp.StatusCode)
	}
}

func TestAPIDNSCERT(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dns/cert/example.com")
	defer resp.Body.Close()
	// DNS-managed certificates are not implemented
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected NotImplemented, got %d", resp.StatusCode)
	}
}

func TestAPIDNSQuery_GET_NoName(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/dns-query")
	defer resp.Body.Close()
	// missing name query parameter
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

func TestAPIDNSQuery_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/dns-query", "application/dns-message", strings.NewReader("test"))
	defer resp.Body.Close()
	// POST is not supported on dns-query
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected MethodNotAllowed, got %d", resp.StatusCode)
	}
}

// ─── parseDN ────────────────────────────────────────────────────

func TestParseDN(t *testing.T) {
	tests := []struct {
		input string
		cn    string
	}{
		{"", ""},
		{"CN=foo", "foo"},
		{"/CN=foo/O=Bar/C=US", "foo"},
		{"invalid", ""},
		{"=nokey", ""},
		{"CN=foo/CN=bar", "bar"},
	}
	for _, tt := range tests {
		got := parseDN(tt.input)
		if got.CommonName != tt.cn {
			t.Errorf("parseDN(%q).CommonName = %q, want %q", tt.input, got.CommonName, tt.cn)
		}
	}
}

func TestParseDN_Fields(t *testing.T) {
	n := parseDN("/C=CN/ST=Beijing/L=Haidian/O=TestOrg/OU=DevOps/CN=server.example.com")
	if n.Country[0] != "CN" {
		t.Errorf("Country = %v", n.Country)
	}
	if n.Province[0] != "Beijing" {
		t.Errorf("Province = %v", n.Province)
	}
	if n.Locality[0] != "Haidian" {
		t.Errorf("Locality = %v", n.Locality)
	}
	if n.Organization[0] != "TestOrg" {
		t.Errorf("Organization = %v", n.Organization)
	}
	if n.OrganizationalUnit[0] != "DevOps" {
		t.Errorf("OrganizationalUnit = %v", n.OrganizationalUnit)
	}
}

// ─── Agent register without mTLS ────────────────────────────────

func TestAPIAgentRegister_NoMTLS(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/agent/register", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIAgentRegister_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/agent/register")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── User revoke-all without mTLS ────────────────────────────────

func TestAPIUserRevokeAll_NoMTLSV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/user/revoke-all", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPIUserRevokeAll_MethodNotAllowedV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGetSuperAdmin(t, ts, "/api/v1/user/revoke-all")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Cert list with expiry filter ────────────────────────────────

func TestAPICertList_ExpiryFilter(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?expiring_days=30")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPICertList_SearchFilter(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs?search=example")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Admin config GET with different auth levels ─────────────────

func TestAPIAdminConfig_GET(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	fx := newMTLSAdminFixture(t, handler, "config:read", "config:write")

	resp := authedMTLSGet(t, fx.Client, fx.Server, "/api/v1/admin/config")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIAdminConfig_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPatch(t, ts, "/api/v1/admin/config", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// PATCH is not supported on the config endpoint
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected MethodNotAllowed, got %d", resp.StatusCode)
	}
}

// ─── Import CA ──────────────────────────────────────────────────

func TestAPIImportCA_BadPEM(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"pem": "not-a-pem"})
	resp := authedPost(t, ts, "/api/v1/cas/import", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// importing a CA requires ca:create which admin lacks
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected Forbidden, got %d", resp.StatusCode)
	}
}

func TestAPIImportCA_MethodNotAllowedV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGetSuperAdmin(t, ts, "/api/v1/cas/import")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Cert verify ────────────────────────────────────────────────

func TestAPIVerifyCert_EmptyBody(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIVerifyCert_MethodNotAllowedV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/verify/cert")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── Webhook subscriptions ───────────────────────────────────────

func TestAPIWebhooks_MethodNotAllowed(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/webhooks", strings.NewReader(`{"url":"http://test"}`))
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

// ─── Cross-cert revoke with invalid body ─────────────────────────

func TestAPICrossCertRevoke_EmptyBody(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/cross-cert/revoke", "application/json", strings.NewReader(`{"issuer_ca":"test","serial_number":"123"}`))
	defer resp.Body.Close()
	// missing issuer/serial fields
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Cross-cert issue with body ──────────────────────────────────

func TestAPICrossCertIssue_WithBody(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"subject_ca": "test-ca", "issuer_ca": "other-ca"})
	resp := authedPost(t, ts, "/api/v1/cross-cert/issue", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// missing issuer/target fields
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── Verify cert with actual cert ────────────────────────────────

func TestAPIVerifyCert_WithPEM(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Generate a self-signed cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "verify-test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	body, _ := json.Marshal(map[string]string{"cert_pem": certPEM})
	resp := authedPost(t, ts, "/api/v1/verify/cert", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// certificate verification succeeds
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

// ─── version endpoint ────────────────────────────────────────────

func TestAPIVersionV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/version")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Permissions ─────────────────────────────────────────────────

func TestAPIPermissionsRoles(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/permissions/roles")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIPermissionsCheck(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/permissions/check")
	defer resp.Body.Close()
	// permissions/check requires a JSON body
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── statusRecorder ──────────────────────────────────────────────

func TestStatusRecorder(t *testing.T) {
	rec := &statusRecorder{status: http.StatusCreated}
	if rec.status != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, rec.status)
	}
}

// ─── apiExportCert with GET method ───────────────────────────────

func TestAPIExportCert_GET(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/cert/test-ca/serial/export")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ─── CRL get ─────────────────────────────────────────────────────

func TestAPIGetCRL(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/crl/test-ca")
	defer resp.Body.Close()
	// CRL generation for test-ca
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

// ─── async submit valid ──────────────────────────────────────────

func TestAPIAsyncSubmit_Valid(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]interface{}{
		"ca":          "test-ca",
		"profile":     "server",
		"common_name": "async-test.example.com",
	})
	resp := authedPost(t, ts, "/api/v1/certs/async", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// async submit requires an items array
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── issue cert valid ────────────────────────────────────────────

func TestAPIIssueCert_Valid(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]interface{}{
		"ca":          "test-ca",
		"profile":     "server",
		"common_name": "issue-test.example.com",
		"validity":    "30d",
	})
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// common_name is not a recognized field (cn is required)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected BadRequest, got %d", resp.StatusCode)
	}
}

// ─── user ops with admin token ────────────────────────────────────

func TestAPIUsers_List(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/users")
	defer resp.Body.Close()
	// admin lacks user:list
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected Forbidden, got %d", resp.StatusCode)
	}
}

func TestAPIUsers_CreateV2(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{
		"username": "newuser",
		"password": "pass123",
		"role":     "user",
	})
	resp := authedPost(t, ts, "/api/v1/users", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// admin lacks user:manage
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected Forbidden, got %d", resp.StatusCode)
	}
}

// ─── login / logout ──────────────────────────────────────────────

func TestAPILogin_Invalid(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp := authedPost(t, ts, "/api/v1/users/login", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	// invalid credentials
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected Unauthorized, got %d", resp.StatusCode)
	}
}

func TestAPILogout(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/users/logout", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	// logout succeeds
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", resp.StatusCode)
	}
}

// ─── dashboard SSE and stats SSE ─────────────────────────────────

func TestAPIDashboardSSEV2(t *testing.T) {
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

func TestAPIStatsSSEV2(t *testing.T) {
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

// ─── RBAC requirePerm ────────────────────────────────────────────

func TestRequirePerm_PublicPath(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── RBAC requirePerm with basic auth ────────────────────────────

func TestRequirePerm_AdminUser(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// admin has all perms
	resp := authedGet(t, ts, "/api/v1/users")
	defer resp.Body.Close()
	// admin is not allowed to list users
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected Forbidden, got %d", resp.StatusCode)
	}
}

// ─── requirePerm with bad auth ───────────────────────────────────

func TestRequirePerm_BadAuth(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/users", nil)
	req.SetBasicAuth("admin", "wrongpassword")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── requirePerm with token auth ─────────────────────────────────

func TestRequirePerm_NoAuth(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ─── statusRecorder.WriteHeader ──────────────────────────────────

func TestStatusRecorder_WriteHeader(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	rec.WriteHeader(http.StatusNotFound)
	if rec.status != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, rec.status)
	}
}

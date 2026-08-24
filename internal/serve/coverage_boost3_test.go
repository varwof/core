package serve

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/varwof/engine/db"
)

// ─── rbac.go: parseCAScopes ──────────────────────────────────────

func TestParseCAScopes(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"ca-a", 1},
		{"ca-a,ca-b", 2},
		{"ca-a, ca-b , ca-c", 3},
		{"ca-a,,ca-b", 2},
		{" , , ", 0},
	}
	for _, tt := range tests {
		got := parseCAScopes(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseCAScopes(%q) = %v (len=%d), want len=%d", tt.input, got, len(got), tt.want)
		}
	}
}

// ─── rbac.go: scopeMatch ─────────────────────────────────────────

func TestScopeMatch_Star(t *testing.T) {
	if !scopeMatch("*", "any-ca") {
		t.Fatal("* should match everything")
	}
}

func TestScopeMatch_Exact(t *testing.T) {
	if !scopeMatch("ca-a", "ca-a") {
		t.Fatal("exact match should work")
	}
	if scopeMatch("ca-a", "ca-b") {
		t.Fatal("non-match should fail")
	}
}

// ─── rbac.go: extractPolicyCAFromChain ───────────────────────────

func TestExtractPolicyCAFromChain_NilTLS(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	got := extractPolicyCAFromChain(r)
	if got != "" {
		t.Fatalf("expected empty for nil TLS, got %q", got)
	}
}

func TestExtractPolicyCAFromChain_EmptyChains(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{}}
	got := extractPolicyCAFromChain(r)
	if got != "" {
		t.Fatalf("expected empty for empty chains, got %q", got)
	}
}

func TestExtractPolicyCAFromChain_TooShort(t *testing.T) {
	// Chain with only 2 certs (leaf + root, no subCA)
	r, _ := http.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{&x509.Certificate{}, &x509.Certificate{}},
		},
	}
	got := extractPolicyCAFromChain(r)
	if got != "" {
		t.Fatalf("expected empty for short chain, got %q", got)
	}
}

func TestExtractPolicyCAFromChain_FullChain(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	subCA := &x509.Certificate{Subject: pkix.Name{CommonName: "PolicySubCA"}}
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{&x509.Certificate{}, subCA, &x509.Certificate{}},
		},
	}
	got := extractPolicyCAFromChain(r)
	if got != "PolicySubCA" {
		t.Fatalf("expected PolicySubCA, got %q", got)
	}
}

// ─── permissions.go: HasPerm / Roles ─────────────────────────────

func TestHasPerm_AdminCanIssue(t *testing.T) {
	if !HasPerm("admin", PermCertIssue) {
		t.Fatal("admin should be able to issue certs")
	}
}

func TestHasPerm_ReadonlyCannotIssue(t *testing.T) {
	if HasPerm("readonly", PermCertIssue) {
		t.Fatal("readonly should not be able to issue certs")
	}
}

func TestRoles_NotEmpty(t *testing.T) {
	roles := Roles()
	if len(roles) == 0 {
		t.Fatal("expected non-empty roles")
	}
}

// ─── metrics.go ──────────────────────────────────────────────────

func TestMetricsMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	handler := metricsMiddleware(inner)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRecordCertIssued(t *testing.T) {
	certIssuedTotal.Reset()
	recordCertIssued("test-ca", "web")
	got := testutil.ToFloat64(certIssuedTotal.WithLabelValues("test-ca", "web"))
	if got != 1 {
		t.Fatalf("expected cert_issued_total=1, got %v", got)
	}
}

func TestRecordCertRevoked(t *testing.T) {
	certRevokedTotal.Reset()
	recordCertRevoked("test-ca")
	got := testutil.ToFloat64(certRevokedTotal.WithLabelValues("test-ca"))
	if got != 1 {
		t.Fatalf("expected cert_revoked_total=1, got %v", got)
	}
}

func TestUpdateInventoryMetrics(t *testing.T) {
	activeCertsGauge.Set(0)
	revokedCertsGauge.Set(0)
	updateInventoryMetrics(10, 5)
	if got := testutil.ToFloat64(activeCertsGauge); got != 10 {
		t.Fatalf("expected active_certs=10, got %v", got)
	}
	if got := testutil.ToFloat64(revokedCertsGauge); got != 5 {
		t.Fatalf("expected revoked_certs=5, got %v", got)
	}
}

// ─── api_trust.go: trustAnchorToJSON ─────────────────────────────

func TestTrustAnchorToJSON(t *testing.T) {
	now := time.Now()
	a := &db.TrustAnchor{
		ID:        1,
		Name:      "Test Root",
		HashID:    "abc123",
		Subject:   "CN=Test Root",
		NotBefore: now,
		NotAfter:  now.Add(10 * 365 * 24 * time.Hour),
		Issuer:    "CN=Test Root",
		Trusted:   true,
		Source:    "curl.se",
	}
	j := trustAnchorToJSON(a)
	if j.ID != 1 || j.Name != "Test Root" || j.HashID != "abc123" {
		t.Fatalf("unexpected: %+v", j)
	}
	if j.NotBefore == "" || j.NotAfter == "" {
		t.Fatal("expected non-empty dates")
	}
	if !j.Trusted {
		t.Fatal("expected trusted=true")
	}
}

// ─── report.go: truncate ─────────────────────────────────────────

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 3); got != "hel" {
		t.Fatalf("expected hel, got %s", got)
	}
	if got := truncate("hi", 10); got != "hi" {
		t.Fatalf("expected hi, got %s", got)
	}
	if got := truncate("", 5); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
	if got := truncate("exact", 5); got != "exact" {
		t.Fatalf("expected exact, got %s", got)
	}
}

// ─── auth_api.go: apiPermissionCheck / apiPermissionRoles ────────

func TestAPIPermissionRoles(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/permissions/roles")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAPIPermissionCheck_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/permissions/check", "application/json", strings.NewReader(`bad`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIPermissionCheck_InvalidPEM(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/permissions/check", "application/json",
		strings.NewReader(`{"pem":"not-pem","permission":"cert.issue"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIPermissionCheck_InvalidCert(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	badPEM := "-----BEGIN CERTIFICATE-----\nYm9ndXM=\n-----END CERTIFICATE-----"
	resp := authedPost(t, ts, "/api/v1/permissions/check", "application/json",
		strings.NewReader(`{"pem":"`+badPEM+`","permission":"cert.issue"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAPIPermissionCheck_ValidCert(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Create a test cert with OU=admin
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "test", OrganizationalUnit: []string{"admin"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	body, _ := json.Marshal(map[string]string{
		"pem":        strings.TrimSpace(string(certPEM)),
		"permission": "cert.issue",
	})
	resp := authedPost(t, ts, "/api/v1/permissions/check", "application/json",
		strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── apiAsyncStatus ──────────────────────────────────────────────

func TestAPIAsyncStatus(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp := authedGet(t, ts, "/api/v1/certs/async/nonexistent-job-id")
	defer resp.Body.Close()
	// Should return 404 or similar
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for nonexistent job")
	}
}

// ─── ouToRole / hasOU ────────────────────────────────────────────

func TestOuToRole(t *testing.T) {
	tests := []struct {
		ous  []string
		want string
	}{
		{[]string{"SuperAdmin"}, "superadmin"},
		{[]string{"admin"}, "admin"},
		{[]string{"Operator"}, "operator"},
		{[]string{"operator"}, "operator"},
		{[]string{"Auditor"}, "auditor"},
		{[]string{"Revoker"}, "revoker"},
		{[]string{"ReadOnly"}, "readonly"},
		{[]string{"Console"}, "console"},
		{[]string{"AutoRenew"}, "auto-renew"},
		{[]string{"Reporter"}, "reporter"},
		{[]string{"unknown"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		got := ouToRole(tt.ous)
		if got != tt.want {
			t.Errorf("ouToRole(%v) = %q, want %q", tt.ous, got, tt.want)
		}
	}
}

func TestHasOU_CoverageBoost(t *testing.T) {
	if !hasOU([]string{"admin", "ops"}, "admin") {
		t.Fatal("should find admin")
	}
	if hasOU([]string{"admin"}, "ops") {
		t.Fatal("should not find ops")
	}
	if hasOU(nil, "admin") {
		t.Fatal("nil slice should not match")
	}
}

// ─── checkCAScope ────────────────────────────────────────────────

func TestCheckCAScope_AutoRenew(t *testing.T) {
	user := &AuthUser{Role: "auto-renew", CAScopes: []string{"*"}}
	r, _ := http.NewRequest("GET", "/", nil)
	if !checkCAScope(user, r, PermCertIssue, nil) {
		t.Fatal("auto-renew should always pass")
	}
}

func TestCheckCAScope_Auditor(t *testing.T) {
	user := &AuthUser{Role: "auditor"}
	r, _ := http.NewRequest("GET", "/", nil)
	if !checkCAScope(user, r, PermCertIssue, nil) {
		t.Fatal("auditor should always pass")
	}
}

func TestCheckCAScope_ReadOnly(t *testing.T) {
	user := &AuthUser{Role: "readonly"}
	r, _ := http.NewRequest("GET", "/", nil)
	if !checkCAScope(user, r, PermCertIssue, nil) {
		t.Fatal("readonly should always pass")
	}
}

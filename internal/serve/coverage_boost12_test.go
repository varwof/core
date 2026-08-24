package serve

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/engine/db"
)

// ─── apiGatewayList ───────────────────────────────────────────────

func TestGatewayListEdges(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)

	w := httptest.NewRecorder()
	srv.apiGatewayList(w, httptest.NewRequest("POST", "/api/v1/gateways", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	w2 := httptest.NewRecorder()
	srv.apiGatewayList(w2, httptest.NewRequest("GET", "/api/v1/gateways", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
}

// ─── apiTrustDelete ───────────────────────────────────────────────

func TestTrustDelete(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	d := srv.getDB()

	// seed a trust anchor, then delete it → 200
	d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "Root CA", HashID: "root-hash-1",
		CertDER: []byte{0x30, 0x01}, Subject: "CN=Root CA",
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		Issuer: "CN=Root CA", Trusted: true,
	})
	w := httptest.NewRecorder()
	srv.apiTrustDelete(w, httptest.NewRequest("DELETE", "/api/v1/trust/root-hash-1", nil), "root-hash-1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// delete missing → 404 (DB error path via closed DB)
	w2 := httptest.NewRecorder()
	srv.getDB().Close()
	srv.apiTrustDelete(w2, httptest.NewRequest("DELETE", "/api/v1/trust/nope", nil), "nope")
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w2.Code)
	}
}

// ─── apiGetSubCA not-found branch ─────────────────────────────────

func TestGetSubCANotFound(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	superCert := scopedAdminCert(t, srv.getDB(), "SuperAdmin", "Management CA")

	// wrong method → 405
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sub-ca/whatever", nil)
	r.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiGetSubCA(w, r, "whatever")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// missing sub-CA with valid admin cert → 404
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/sub-ca/nope", nil)
	r2.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiGetSubCA(w2, r2, "nope")
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w2.Code)
	}
}

// ─── apiPermissionRoles ───────────────────────────────────────────

func TestPermissionRoles(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)

	w := httptest.NewRecorder()
	srv.apiPermissionRoles(w, httptest.NewRequest("GET", "/api/v1/permissions/roles", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ─── apiTSACA / apiTSACARenew ─────────────────────────────────────

func TestTSACA(t *testing.T) {
	srv, _, caCert, _ := newTestServerWithCA(t)

	// Force chain unset → 404
	cfg := srv.getConfig()
	cfg.TSA.Chain = ""
	w := httptest.NewRecorder()
	srv.apiTSACA(w, httptest.NewRequest("GET", "/tsa/ca", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	// bad chain file → 500
	badDir := t.TempDir()
	badPath := filepath.Join(badDir, "bad.pem")
	os.WriteFile(badPath, []byte("nope"), 0644)
	cfg.TSA.Chain = badPath
	w2 := httptest.NewRecorder()
	srv.apiTSACA(w2, httptest.NewRequest("GET", "/tsa/ca", nil))
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w2.Code)
	}

	// good chain → 200
	goodPath := filepath.Join(badDir, "good.pem")
	writePEMFile(t, goodPath, "CERTIFICATE", caCert.Raw)
	cfg.TSA.Chain = goodPath
	w3 := httptest.NewRecorder()
	srv.apiTSACA(w3, httptest.NewRequest("GET", "/tsa/ca", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	// apiTSACARenew 405
	w4 := httptest.NewRecorder()
	srv.apiTSACARenew(w4, httptest.NewRequest("GET", "/tsa/ca/renew", nil))
	if w4.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w4.Code)
	}
	// apiTSACARenew success
	w5 := httptest.NewRecorder()
	srv.apiTSACARenew(w5, httptest.NewRequest("POST", "/tsa/ca/renew", nil))
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w5.Code)
	}
}

// ─── apiAgentRegister success path ───────────────────────────────

func TestAgentRegisterSuccess(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// wrong method → 405
	w := httptest.NewRecorder()
	srv.apiAgentRegister(w, httptest.NewRequest("GET", "/api/v1/agent/register", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}

	// no mTLS → 401
	w2 := httptest.NewRecorder()
	srv.apiAgentRegister(w2, httptest.NewRequest("POST", "/api/v1/agent/register", strings.NewReader(`{}`)))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w2.Code)
	}

	// mTLS cert without AIC extension → falls back to body fields.
	// OU "admin" maps to the admin role so mTLS authentication succeeds.
	userCert, _ := newUserCertOU(t, caCert, caKey, "agent@example.com", []string{"admin"}, "agent:manage")
	body := `{"agent_id":"agent-42","principal_uid":"agent@example.com"}`
	w3 := httptest.NewRecorder()
	r3 := mtlsRequest(t, userCert, body)
	r3.SetBasicAuth("admin", "admin")
	srv.apiAgentRegister(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	// missing fields → 400
	w4 := httptest.NewRecorder()
	r4 := mtlsRequest(t, userCert, `{"agent_id":"only-agent"}`)
	r4.SetBasicAuth("admin", "admin")
	srv.apiAgentRegister(w4, r4)
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w4.Code)
	}
}

// ─── authScopesCache edge cases ──────────────────────────────────

func TestAuthScopesCacheEdges(t *testing.T) {
	authScopesMu.Lock()
	authScopesCache = make(map[string]authScopesEntry)
	authScopesMu.Unlock()

	// miss
	if _, ok := authScopesCached("nobody"); ok {
		t.Fatal("expected cache miss")
	}
	// remember + hit
	rememberAuthScopes("alice", []string{"A", "B"})
	scopes, ok := authScopesCached("alice")
	if !ok || len(scopes) != 2 {
		t.Fatalf("expected cached scopes, got %v ok=%v", scopes, ok)
	}
	// expired entry → miss
	authScopesMu.Lock()
	authScopesCache["bob"] = authScopesEntry{scopes: []string{"X"}, exp: time.Now().Add(-time.Minute)}
	authScopesMu.Unlock()
	if _, ok := authScopesCached("bob"); ok {
		t.Fatal("expected expired cache miss")
	}

	// max-entries eviction branch
	authScopesMu.Lock()
	authScopesCache = make(map[string]authScopesEntry)
	for i := 0; i < authScopesCacheMaxEntries; i++ {
		authScopesCache[itoa(i)] = authScopesEntry{scopes: []string{"S"}, exp: time.Now().Add(time.Minute)}
	}
	authScopesMu.Unlock()
	rememberAuthScopes("overflow-user", []string{"Z"})
	authScopesMu.Lock()
	_, exists := authScopesCache["overflow-user"]
	authScopesMu.Unlock()
	if !exists {
		t.Fatal("expected overflow-user to be evicted-in (LRU keeps it)")
	}
	// cleanup: clear cache
	authScopesMu.Lock()
	authScopesCache = nil
	authScopesMu.Unlock()
}

func itoa(i int) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.Join([]string{string(rune('a' + i%26)), string(rune('0' + i%10)), string(rune('0' + (i/10)%10))}, ""), " ", ""))
}

// ─── getRolePerms with policy ────────────────────────────────────

func TestGetRolePermsWithPolicy(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)

	// Save/restore the global policy so other tests are unaffected.
	prev := auth.GetPolicy()
	defer auth.SetPolicy(prev)

	p, err := auth.LoadPolicyData([]byte(`{
		"version": "v2",
		"roles": {
			"admin": {"grants": ["ca:list","cert:issue"], "ou": ["admin"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	auth.SetPolicy(p)

	perms := getRolePerms("admin")
	if len(perms) != 2 {
		t.Fatalf("expected 2 perms from policy, got %d", len(perms))
	}
	// unknown role with policy loaded → empty
	if perms := getRolePerms("nope"); len(perms) != 0 {
		t.Fatalf("expected empty perms for unknown role, got %v", perms)
	}

	// getRolePerms without policy → hardcoded fallback
	auth.SetPolicy(nil)
	if perms := getRolePerms("admin"); len(perms) == 0 {
		t.Fatal("expected hardcoded fallback perms")
	}

	_ = srv
}

// ─── apiCreateSubCA error branches ───────────────────────────────

func TestCreateSubCAErrors(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	superCert := scopedAdminCert(t, srv.getDB(), "SuperAdmin", "Management CA")

	// wrong method → 405
	w := httptest.NewRecorder()
	srv.apiCreateSubCA(w, httptest.NewRequest("GET", "/api/v1/sub-cas", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// no admin cert → 401
	w2 := httptest.NewRecorder()
	srv.apiCreateSubCA(w2, httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(`{}`)))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w2.Code)
	}
	// bad json → 400
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader("{bad"))
	r3.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(w3, r3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3.Code)
	}
	// missing name → 400
	w4 := httptest.NewRecorder()
	r4 := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(`{"parent_ca":"test-ca"}`))
	r4.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(w4, r4)
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w4.Code)
	}
	// invalid validity → 400
	w5 := httptest.NewRecorder()
	r5 := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(`{"name":"x","parent_ca":"test-ca","validity":"nope"}`))
	r5.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(w5, r5)
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w5.Code)
	}
	// missing parent CA → 404
	w6 := httptest.NewRecorder()
	r6 := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(`{"name":"x","parent_ca":"ghost"}`))
	r6.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(w6, r6)
	if w6.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w6.Code)
	}
}

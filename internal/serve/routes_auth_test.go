// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AUTH-005: token endpoints must have precise rules (user:list/user:manage), not be covered by fallback.
// /api/** → ca:list hit (otherwise any role with ca:list could enumerate/create/delete tokens).
func TestDefaultRulesTokenEndpoints(t *testing.T) {
	rr := LoadDefaultRouteRules()
	if rr == nil {
		t.Fatal("LoadDefaultRouteRules() = nil")
	}
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/api/v1/tokens", "user:list"},
		{"POST", "/api/v1/tokens", "user:manage"},
		{"DELETE", "/api/v1/tokens/42", "user:manage"},
	}
	for _, c := range cases {
		rule, _ := rr.MatchWithParams(c.method, c.path)
		if rule == nil {
			t.Fatalf("%s %s: no rule matched", c.method, c.path)
		}
		if rule.Permission != c.want {
			t.Errorf("%s %s: permission = %q, want %q", c.method, c.path, rule.Permission, c.want)
		}
	}
	// Fallback rule still works: unregistered /api/v1/foo hits ca:list.
	rule, _ := rr.MatchWithParams("GET", "/api/v1/foo")
	if rule == nil || rule.Permission != "ca:list" {
		t.Errorf("GET /api/v1/foo: got %v, want ca:list fallback", rule)
	}
}

// S1: CSR/K8s issuance endpoints must require cert:issue, not fall through to
// the /api/** → ca:list catch-all (otherwise any ca:list holder — including
// readonly — could mint certificates).
func TestDefaultRulesCsrK8sIssueEndpoints(t *testing.T) {
	rr := LoadDefaultRouteRules()
	if rr == nil {
		t.Fatal("LoadDefaultRouteRules() = nil")
	}
	cases := []struct {
		method, path, want string
	}{
		{"POST", "/api/v1/csr/sign", "cert:issue"},
		{"POST", "/api/v1/k8s/sign", "cert:issue"},
	}
	for _, c := range cases {
		rule, _ := rr.MatchWithParams(c.method, c.path)
		if rule == nil {
			t.Fatalf("%s %s: no rule matched", c.method, c.path)
		}
		if rule.Permission != c.want {
			t.Errorf("%s %s: permission = %q, want %q", c.method, c.path, rule.Permission, c.want)
		}
	}
}

// S4: gateway management endpoints must require agent:manage / user:revoke-all,
// not fall through to the /api/** → ca:list catch-all.
func TestDefaultRulesGatewayEndpoints(t *testing.T) {
	rr := LoadDefaultRouteRules()
	if rr == nil {
		t.Fatal("LoadDefaultRouteRules() = nil")
	}
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/api/v1/gateway/list", "agent:manage"},
		{"POST", "/api/v1/gateway/disconnect-agent", "agent:manage"},
		{"POST", "/api/v1/gateway/disconnect-user", "user:revoke-all"},
	}
	for _, c := range cases {
		rule, _ := rr.MatchWithParams(c.method, c.path)
		if rule == nil {
			t.Fatalf("%s %s: no rule matched", c.method, c.path)
		}
		if rule.Permission != c.want {
			t.Errorf("%s %s: permission = %q, want %q", c.method, c.path, rule.Permission, c.want)
		}
	}
}

// M13: the DNS resolver endpoint must no longer be a public path (it was an
// open unauthenticated resolver); resolving now requires dns:manage.
func TestDefaultRulesDNSQueryNotPublic(t *testing.T) {
	rr := LoadDefaultRouteRules()
	if rr == nil {
		t.Fatal("LoadDefaultRouteRules() = nil")
	}
	if rr.IsPublic("/api/v1/dns-query") {
		t.Fatal("GET /api/v1/dns-query must not be a public path (was open resolver)")
	}
	rule, _ := rr.MatchWithParams("GET", "/api/v1/dns-query")
	if rule == nil {
		t.Fatal("GET /api/v1/dns-query: no rule matched")
	}
	if rule.Permission != "dns:manage" {
		t.Fatalf("GET /api/v1/dns-query: permission = %q, want dns:manage", rule.Permission)
	}
}

// AUTH-012: Login failure must write structured audit log (LogAudit).
func TestLoginFailureAuditedAUTH12(t *testing.T) {
	_, database, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// User not found → login_failed_user_not_found
	body, _ := json.Marshal(map[string]string{"username": "nosuchuser", "password": "x"})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// Wrong password → login_failed_bad_password
	body2, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp2, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp2.StatusCode)
	}

	entries, err := database.GetAllAuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	var foundUserNotFound, foundBadPassword bool
	for _, e := range entries {
		switch e.Action {
		case "login_failed_user_not_found":
			foundUserNotFound = true
		case "login_failed_bad_password":
			foundBadPassword = true
		}
	}
	if !foundUserNotFound {
		t.Error("missing login_failed_user_not_found audit entry")
	}
	if !foundBadPassword {
		t.Error("missing login_failed_bad_password audit entry")
	}
	// Audit chain should remain intact after new failure entries (AUTH-016 cross-validation).
	if n, err := database.VerifyAuditChain(); err != nil || n == 0 {
		t.Fatalf("audit chain must stay intact after login failures: n=%d err=%v", n, err)
	}
}

// M12: the auditLog helper (used by issuance/revocation/key-recovery/sub-CA/
// CA-import/cross-cert handlers that previously skipped audit) must persist an
// audit entry.
func TestAuditLogHelperWritesEntryM12(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/csr/sign", nil)
	srv.auditLog(req, "test_m12_action", "detail=1")
	entries, err := srv.getDB().GetAllAuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "test_m12_action" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("auditLog did not persist test_m12_action entry")
	}
}

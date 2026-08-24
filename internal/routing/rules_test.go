// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package routing

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestLiteralMatch(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"POST","path":"/api/v1/certs","permission":"cert:issue"},
			{"method":"GET","path":"/api/v1/certs","permission":"cert:list"}
		]
	}`)

	tests := []struct {
		method string
		path   string
		want   string // permission
	}{
		{"POST", "/api/v1/certs", "cert:issue"},
		{"GET", "/api/v1/certs", "cert:list"},
		{"DELETE", "/api/v1/certs", ""}, // no match
		{"POST", "/api/v1/cert", ""},    // wrong path
		{"POST", "/api/v1/certs/", ""},  // trailing slash
	}
	for _, tt := range tests {
		r := rules.Match(tt.method, tt.path)
		got := ""
		if r != nil {
			got = r.Permission
		}
		if got != tt.want {
			t.Errorf("%s %s: got %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestWildcardMatch(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"*","path":"/api/v1/ca/*","permission":"ca:*"},
			{"method":"GET","path":"/api/v1/cert/**","permission":"cert:list"}
		]
	}`)

	tests := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/api/v1/ca/issuing-ca", "ca:*"},
		{"DELETE", "/api/v1/ca/my-ca", "ca:*"},
		{"GET", "/api/v1/ca/issuing-ca/revoke", ""}, // single * doesn't match sub-paths
		{"GET", "/api/v1/cert/issuing-ca/12345", "cert:list"},
		{"GET", "/api/v1/cert/issuing-ca/12345/revoke", "cert:list"},
		{"GET", "/api/v1/certs", ""}, // no * match for /certs
	}
	for _, tt := range tests {
		r := rules.Match(tt.method, tt.path)
		got := ""
		if r != nil {
			got = r.Permission
		}
		if got != tt.want {
			t.Errorf("%s %s: got %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestParamExtraction(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"DELETE","path":"/api/v1/cert/{ca}/{serial}","permission":"cert:revoke"},
			{"method":"POST","path":"/api/v1/cert/{ca}/{serial}/renew","permission":"cert:renew"}
		]
	}`)

	// Test param extraction
	r, params := rules.MatchWithParams("DELETE", "/api/v1/cert/issuing-ca/ABCD1234")
	if r == nil {
		t.Fatal("expected match")
	}
	if r.Permission != "cert:revoke" {
		t.Errorf("permission: got %q, want cert:revoke", r.Permission)
	}
	if params["ca"] != "issuing-ca" {
		t.Errorf("ca param: got %q, want issuing-ca", params["ca"])
	}
	if params["serial"] != "ABCD1234" {
		t.Errorf("serial param: got %q, want ABCD1234", params["serial"])
	}

	// Test renewal
	r, params = rules.MatchWithParams("POST", "/api/v1/cert/issuing-ca/ABCD1234/renew")
	if r == nil {
		t.Fatal("expected match")
	}
	if r.Permission != "cert:renew" {
		t.Errorf("permission: got %q, want cert:renew", r.Permission)
	}
}

func TestMethodWildcard(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"*","path":"/api/v1/version","permission":"web:view"}
		]
	}`)

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		r := rules.Match(method, "/api/v1/version")
		if r == nil {
			t.Errorf("%s: expected match", method)
			continue
		}
		if r.Permission != "web:view" {
			t.Errorf("%s: got %q, want web:view", method, r.Permission)
		}
	}
}

func TestPriorityMostSpecificFirst(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"*","path":"/api/v1/cert/**","permission":"cert:list"},
			{"method":"POST","path":"/api/v1/cert/{ca}/{serial}/revoke","permission":"cert:revoke"},
			{"method":"POST","path":"/api/v1/cert/{ca}/{serial}/renew","permission":"cert:renew"}
		]
	}`)

	// More specific param pattern should match before ** wildcard
	r := rules.Match("POST", "/api/v1/cert/issuing-ca/123/revoke")
	if r == nil {
		t.Fatal("expected match")
	}
	if r.Permission != "cert:revoke" {
		t.Errorf("got %q, want cert:revoke (most specific should win)", r.Permission)
	}
}

func TestPublicPaths(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [{"method":"GET","path":"/api/v1/version","permission":"ca:list"}],
		"public_paths": ["/healthz", "/readyz", "/api/v1/version"]
	}`)

	if !rules.IsPublic("/healthz") {
		t.Error("/healthz should be public")
	}
	if !rules.IsPublic("/readyz") {
		t.Error("/readyz should be public")
	}
	if !rules.IsPublic("/api/v1/version") {
		t.Error("/api/v1/version should be public")
	}
	if rules.IsPublic("/api/v1/certs") {
		t.Error("/api/v1/certs should NOT be public")
	}
}

func TestCAScope(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"DELETE","path":"/api/v1/cert/{ca}/{serial}","permission":"cert:revoke","ca_scope":true}
		]
	}`)

	r := rules.Match("DELETE", "/api/v1/cert/issuing-ca/123")
	if r == nil {
		t.Fatal("expected match")
	}
	if !r.CAScope {
		t.Error("ca_scope should be true")
	}
}

func TestRequireRole(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"DELETE","path":"/api/v1/ca/{name}","permission":"ca:delete","require_role":["superadmin"]}
		]
	}`)

	r := rules.Match("DELETE", "/api/v1/ca/issuing-ca")
	if r == nil {
		t.Fatal("expected match")
	}
	if len(r.RequireRole) != 1 || r.RequireRole[0] != "superadmin" {
		t.Errorf("require_role: got %v, want [superadmin]", r.RequireRole)
	}
}

func TestNoMatchReturnsNil(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"GET","path":"/api/v1/certs","permission":"cert:list"}
		]
	}`)

	r := rules.Match("GET", "/api/v1/nonexistent")
	if r != nil {
		t.Errorf("expected nil, got %v", r)
	}
}

func TestCount(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"GET","path":"/a","permission":"a"},
			{"method":"GET","path":"/b","permission":"b"},
			{"method":"GET","path":"/c","permission":"c"}
		]
	}`)
	if rules.Count() != 3 {
		t.Errorf("Count() = %d, want 3", rules.Count())
	}
}

func TestAllRules(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"GET","path":"/a","permission":"a","description":"desc"}
		]
	}`)
	r := rules.AllRules()
	if len(r) != 1 {
		t.Fatalf("AllRules() returned %d, want 1", len(r))
	}
	if r[0].Description != "desc" {
		t.Errorf("Description = %q, want desc", r[0].Description)
	}
}

func TestConcurrentAccess(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"GET","path":"/api/v1/certs","permission":"cert:list"},
			{"method":"POST","path":"/api/v1/certs","permission":"cert:issue"}
		]
	}`)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rules.Match("GET", "/api/v1/certs")
			if r == nil || r.Permission != "cert:list" {
				t.Errorf("concurrent match failed")
			}
		}()
	}
	wg.Wait()
}

func TestCompileError(t *testing.T) {
	_, err := LoadData([]byte(`{
		"version": "v1",
		"rules": [
			{"method":"GET","path":"/api/{}/bad","permission":"test"}
		]
	}`))
	if err == nil {
		t.Error("expected error for empty param name")
	}
}

func TestInvalidJSON(t *testing.T) {
	_, err := LoadData([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFile(t *testing.T) {
	// LoadFile with nonexistent path
	_, err := LoadFile("/nonexistent/routes.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestMethodCaseInsensitive(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"get","path":"/test","permission":"test"}
		]
	}`)
	r := rules.Match("GET", "/test")
	if r == nil {
		t.Error("expected case-insensitive method match")
	}
}

func TestDoubleWildcard(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"*","path":"/api/v1/log/**","permission":"log:read"}
		]
	}`)

	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/log/entries", true},
		{"/api/v1/log/entries/123", true},
		{"/api/v1/log/entries/123/detail", true},
		{"/api/v1/logs", false},
		{"/api/v1/log", false},
	}
	for _, tt := range tests {
		r := rules.Match("GET", tt.path)
		got := r != nil
		if got != tt.want {
			t.Errorf("GET %s: matched=%v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestAllowAICToggle(t *testing.T) {
	rules := mustLoad(t, `{
		"version": "v1",
		"rules": [
			{"method":"POST","path":"/api/v1/certs","permission":"cert:issue","allow_aic":false}
		]
	}`)

	r := rules.Match("POST", "/api/v1/certs")
	if r == nil {
		t.Fatal("expected match")
	}
	if r.AllowAIC != nil && *r.AllowAIC {
		t.Error("allow_aic should be false")
	}
}

// --- helpers ---

func mustLoad(t *testing.T, jsonStr string) *RouteRules {
	t.Helper()
	rr, err := LoadData([]byte(jsonStr))
	if err != nil {
		t.Fatalf("LoadData: %v", err)
	}
	return rr
}

func TestEmptyRules(t *testing.T) {
	// M21 fix: empty rule table is now rejected fail-closed at compile time.
	_, err := LoadData([]byte(`{"version":"v1","rules":[]}`))
	if err == nil {
		t.Fatal("expected compile error for empty rules (fail-closed)")
	}
}

func TestDefaultPermission(t *testing.T) {
	data := `{"version":"v1","rules":[{"method":"GET","path":"/api/v1/version","permission":"ca:list"}],"default_permission":"ca:list"}`
	rr, err := LoadData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if rr.DefaultPermission != "ca:list" {
		t.Errorf("DefaultPermission = %q, want ca:list", rr.DefaultPermission)
	}
	def := rr.DefaultRule()
	if def == nil {
		t.Fatal("DefaultRule() returned nil")
	}
	if def.Permission != "ca:list" {
		t.Errorf("DefaultRule().Permission = %q, want ca:list", def.Permission)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	rr := &RouteRules{
		Version: "v1",
		Rules: []RouteRule{
			{Method: "GET", Path: "/test", Permission: "test:read"},
		},
	}
	data, err := json.Marshal(rr)
	if err != nil {
		t.Fatal(err)
	}
	rr2, err := LoadData(data)
	if err != nil {
		t.Fatal(err)
	}
	if rr2.Count() != 1 {
		t.Errorf("round-trip rules count = %d, want 1", rr2.Count())
	}
}

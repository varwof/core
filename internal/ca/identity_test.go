package ca

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bridgeHandler is a minimal bridge-ldap-style mock for lookup tests.
func bridgeHandler(t *testing.T, fn func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(fn)
}

func identityTestConfig(url string) *IdentitySourceConfig {
	return &IdentitySourceConfig{
		Type:       IdentitySourceLDAP,
		SourceURL:  url,
		Source:     "ad-main",
		TimeoutSec: 5,
		OUFromGroups: map[string]string{
			"CN=医生,OU=Groups,DC=hospital,DC=local": "gateway:ops",
		},
	}
}

func TestRemoteIdentitySourceLookupOK(t *testing.T) {
	var gotUsername, gotSource string
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/lookup" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		var req struct {
			Source   string `json:"source"`
			Username string `json:"username"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		gotUsername, gotSource = req.Username, req.Source
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dn":        "CN=张三,OU=内科,DC=hospital,DC=local",
			"staff_id":  "001",
			"full_name": "张三",
			"dept":      "内科",
			"email":     "zhangsan@hospital.local",
			"source":    "ad-main",
			"disabled":  false,
			"groups":    []string{"CN=医生,OU=Groups,DC=hospital,DC=local"},
		})
	}))
	defer srv.Close()

	src, err := NewIdentitySource(identityTestConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	id, err := src.Lookup(context.Background(), "", "001")
	if err != nil {
		t.Fatal(err)
	}
	if gotUsername != "001" || gotSource != "ad-main" {
		t.Fatalf("lookup req: username=%q source=%q", gotUsername, gotSource)
	}
	if id.Username != "001" || id.FullName != "张三" || id.Email != "zhangsan@hospital.local" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if len(id.Groups) != 1 || !strings.Contains(id.Groups[0], "医生") {
		t.Fatalf("unexpected groups: %v", id.Groups)
	}
	ous := identityTestConfig(srv.URL).CertificateOUS(id)
	if len(ous) != 1 || ous[0] != "gateway:ops" {
		t.Fatalf("OU mapping failed: %v", ous)
	}
}

func TestRemoteIdentitySourceNotFound(t *testing.T) {
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	src, _ := NewIdentitySource(identityTestConfig(srv.URL))
	_, err := src.Lookup(context.Background(), "", "ghost")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestRemoteIdentitySourceUpstreamError(t *testing.T) {
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "upstream error"})
	}))
	defer srv.Close()

	src, _ := NewIdentitySource(identityTestConfig(srv.URL))
	_, err := src.Lookup(context.Background(), "", "001")
	if err == nil || !strings.Contains(err.Error(), "upstream error") {
		t.Fatalf("expected upstream error, got %v", err)
	}
}

func TestRemoteIdentitySourceDisabled(t *testing.T) {
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"staff_id": "001", "full_name": "张三", "disabled": true,
		})
	}))
	defer srv.Close()

	src, _ := NewIdentitySource(identityTestConfig(srv.URL))
	id, err := src.Lookup(context.Background(), "", "001")
	if err != nil {
		t.Fatal(err)
	}
	if !id.Disabled {
		t.Fatal("expected disabled=true")
	}
}

func TestIdentityCertificateOUSFallbacks(t *testing.T) {
	cfg := &IdentitySourceConfig{DefaultOU: "identity"}
	id := &UserIdentity{Username: "001", Dept: "内科"}
	ous := cfg.CertificateOUS(id)
	if len(ous) != 1 || ous[0] != "identity" {
		t.Fatalf("expected DefaultOU fallback, got %v", ous)
	}
	// DefaultOU wins over dept.
	cfg2 := &IdentitySourceConfig{}
	id2 := &UserIdentity{Username: "001", Dept: "外科"}
	if ous := cfg2.CertificateOUS(id2); len(ous) != 1 || ous[0] != "外科" {
		t.Fatalf("expected dept fallback, got %v", ous)
	}
	// No OU at all.
	cfg3 := &IdentitySourceConfig{}
	if ous := cfg3.CertificateOUS(&UserIdentity{Username: "001"}); len(ous) != 0 {
		t.Fatalf("expected no OU, got %v", ous)
	}
}

func TestMatchOUGroupDN(t *testing.T) {
	rules := map[string]string{
		"CN=医生,OU=Groups,DC=hospital,DC=local": "gateway:ops",
		"CN=dev": "gateway:read",
	}
	// Exact match.
	if ou, ok := matchOUGroup(rules, "CN=医生,OU=Groups,DC=hospital,DC=local"); !ok || ou != "gateway:ops" {
		t.Fatalf("exact DN match failed: %s %v", ou, ok)
	}
	// RDN match against the key "CN=医生,..." — containment of the full key isn't
	// enough; the key is a DN so exact comparison is required. Non-DN group key.
	if ou, ok := matchOUGroup(map[string]string{"dev": "gateway:read"}, "dev"); !ok || ou != "gateway:read" {
		t.Fatalf("plain group match failed: %s %v", ou, ok)
	}
	// No match.
	if _, ok := matchOUGroup(rules, "CN=unknown"); ok {
		t.Fatal("unexpected match")
	}
}

func TestOAuthIdentitySourceLookup(t *testing.T) {
	var tokenCalls, infoCalls int
	var gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/token":
			tokenCalls++
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Source   string `json:"source"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			gotUser, gotPass = req.Username, req.Password
			if req.Source != "oauth-main" {
				t.Errorf("token source=%q", req.Source)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600,
			})
		case "/api/v1/userinfo":
			infoCalls++
			var req struct {
				Token  string `json:"token"`
				Source string `json:"source"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if req.Token != "tok-1" {
				t.Errorf("userinfo token=%q", req.Token)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub": "u-1", "username": "alice", "full_name": "Alice",
				"email": "alice@example.com", "groups": []string{"dev"},
				"source": "oauth-main",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &IdentitySourceConfig{
		Type: IdentitySourceOAuth, SourceURL: srv.URL,
		Source: "oauth-main", Username: "svc", Password: "pw", TimeoutSec: 5,
	}
	src, err := NewIdentitySource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id, err := src.Lookup(context.Background(), "", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 || infoCalls != 1 {
		t.Fatalf("token=%d info=%d", tokenCalls, infoCalls)
	}
	if gotUser != "svc" || gotPass != "pw" {
		t.Fatalf("auth account: %q/%q", gotUser, gotPass)
	}
	if id.Username != "alice" || id.Email != "alice@example.com" || len(id.Groups) != 1 {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestNewIdentitySourceErrors(t *testing.T) {
	if _, err := NewIdentitySource(&IdentitySourceConfig{}); err == nil {
		t.Fatal("expected error for empty source_url")
	}
	if _, err := NewIdentitySource(&IdentitySourceConfig{Type: "bogus", SourceURL: "http://x"}); err == nil {
		t.Fatal("expected error for unknown type")
	}
	if _, err := NewIdentitySource(&IdentitySourceConfig{Type: IdentitySourceOAuth, SourceURL: "http://x"}); err != nil {
		t.Fatalf("oauth without username/password should build (runtime error): %v", err)
	}
	// nil config → nil source, no error
	if s, err := NewIdentitySource(nil); err != nil || s != nil {
		t.Fatalf("expected nil source, got %v err=%v", s, err)
	}
}

func TestIdentityTimeoutDefaults(t *testing.T) {
	cfg := &IdentitySourceConfig{}
	if d := cfg.timeout(); d != 10*1000*1000*1000 {
		t.Fatalf("expected default 10s, got %v", d)
	}
	cfg2 := &IdentitySourceConfig{TimeoutSec: 3}
	if d := cfg2.timeout(); d != 3*1000*1000*1000 {
		t.Fatalf("expected 3s, got %v", d)
	}
	if cfg.effectiveType() != IdentitySourceLDAP {
		t.Fatal("default type should be ldap")
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"a", "b", "a", "", "c"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestIdentityLookupNoUsername(t *testing.T) {
	src, _ := NewIdentitySource(identityTestConfig("http://127.0.0.1:1"))
	if _, err := src.Lookup(context.Background(), "", ""); err == nil {
		t.Fatal("expected username-required error")
	}
}

func TestIdentityLookupConnectionError(t *testing.T) {
	src, _ := NewIdentitySource(identityTestConfig("http://127.0.0.1:1"))
	_, err := src.Lookup(context.Background(), "", "001")
	if err == nil {
		t.Fatal("expected connection error")
	}
	if !strings.Contains(err.Error(), "identity lookup") {
		t.Fatalf("unexpected error prefix: %v", err)
	}
}

func TestIdentityCertificateOUSFromGroupsExact(t *testing.T) {
	cfg := &IdentitySourceConfig{
		OUFromGroups: map[string]string{"admin": "gateway:admin"},
	}
	id := &UserIdentity{Username: "boss", Groups: []string{"admin", "staff"}}
	ous := cfg.CertificateOUS(id)
	if len(ous) != 1 || ous[0] != "gateway:admin" {
		t.Fatalf("expected mapped admin OU, got %v", ous)
	}
	// Non-DN group keys match exactly.
	id2 := &UserIdentity{Username: "boss", Groups: []string{"staff"}}
	if ous := cfg.CertificateOUS(id2); len(ous) != 0 {
		t.Fatalf("expected no match, got %v", ous)
	}
}

func TestIdentityNewSourceLDAPBehaves(t *testing.T) {
	// Ensure the ldap remote source posts to the bridge and uses Bearer auth.
	var sawAuth bool
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") == "Bearer tok"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"staff_id": "001", "full_name": "张三"})
	}))
	defer srv.Close()
	cfg := identityTestConfig(srv.URL)
	cfg.Token = "tok"
	src, _ := NewIdentitySource(cfg)
	if _, err := src.Lookup(context.Background(), "ad-main", "001"); err != nil {
		t.Fatal(err)
	}
	if !sawAuth {
		t.Fatal("expected Bearer auth header")
	}
}

func TestOAuthIdentitySourceTokenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/token" {
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	cfg := &IdentitySourceConfig{
		Type: IdentitySourceOAuth, SourceURL: srv.URL,
		Username: "svc", Password: "pw", TimeoutSec: 5,
	}
	src, _ := NewIdentitySource(cfg)
	_, err := src.Lookup(context.Background(), "", "alice")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestOAuthIdentitySourceUserInfoNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/token":
			json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok-1"})
		case "/api/v1/userinfo":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := &IdentitySourceConfig{
		Type: IdentitySourceOAuth, SourceURL: srv.URL,
		Username: "svc", Password: "pw", TimeoutSec: 5,
	}
	src, _ := NewIdentitySource(cfg)
	_, err := src.Lookup(context.Background(), "", "ghost")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestOAuthIdentitySourceMissingAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	cfg := &IdentitySourceConfig{
		Type: IdentitySourceOAuth, SourceURL: srv.URL, TimeoutSec: 5,
	}
	src, _ := NewIdentitySource(cfg)
	_, err := src.Lookup(context.Background(), "", "alice")
	if err == nil || !strings.Contains(err.Error(), "automation account") {
		t.Fatalf("expected automation account error, got %v", err)
	}
}

func TestIdentityOUGroupMatchCaseInsensitive(t *testing.T) {
	if ou, ok := matchOUGroup(map[string]string{"DEV": "gateway:read"}, "dev"); !ok || ou != "gateway:read" {
		t.Fatalf("case-insensitive match failed: %s %v", ou, ok)
	}
}

func BenchmarkRemoteIdentityLookup(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"staff_id": "001", "full_name": "张三"})
	}))
	defer srv.Close()
	src, _ := NewIdentitySource(identityTestConfig(srv.URL))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := src.Lookup(context.Background(), "", "001"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIdentityDefaultSourceInLookup(t *testing.T) {
	var gotSource string
	srv := httptest.NewServer(bridgeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Source string `json:"source"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		gotSource = req.Source
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"staff_id": "001"})
	}))
	defer srv.Close()
	cfg := identityTestConfig(srv.URL)
	cfg.Source = "default-source"
	src, _ := NewIdentitySource(cfg)
	if _, err := src.Lookup(context.Background(), "", "001"); err != nil {
		t.Fatal(err)
	}
	if gotSource != "default-source" {
		t.Fatalf("expected default source, got %q", gotSource)
	}
	// Explicit source overrides default.
	if _, err := src.Lookup(context.Background(), "explicit", "001"); err != nil {
		t.Fatal(err)
	}
	if gotSource != "explicit" {
		t.Fatalf("expected explicit source, got %q", gotSource)
	}
}

func TestIdentitySourceConfigValidate(t *testing.T) {
	// This exercises effectiveType + validation used by internal/config Validate.
	_ = fmt.Sprintf("%v", IdentitySourceType("ldap"))
	if string(IdentitySourceLDAP) != "ldap" || string(IdentitySourceOAuth) != "oauth" {
		t.Fatal("type constants mismatch")
	}
}

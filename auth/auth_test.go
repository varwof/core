// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	_ "embed"
	"testing"
)

//go:embed authz.json
var authzData []byte

func TestLoadPolicy(t *testing.T) {
	p, err := LoadPolicyData(authzData)
	if err != nil {
		t.Fatalf("LoadPolicyData: %v", err)
	}
	if p.Version != "v2" {
		t.Fatalf("version: expected v2, got %s", p.Version)
	}
	if len(p.Roles) == 0 {
		t.Fatal("no roles loaded")
	}
}

func TestPolicy_HasGrant(t *testing.T) {
	p, err := LoadPolicyData(authzData)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		role       string
		capability string
		want       bool
	}{
		{"superadmin", "ca:create", true},
		{"superadmin", "ca:delete", true},
		{"superadmin", "cert:issue", true},
		{"admin", "ca:create", false},
		{"admin", "cert:issue", true},
		{"admin", "log:read", true},
		{"admin", "web:view", true},
		{"admin", "nonexistent:foo", false},
		{"operator", "cert:issue", true},
		{"operator", "cert:revoke", true},
		{"operator", "ca:create", false},
		{"operator", "user:manage", false},
		{"revoker", "cert:revoke", true},
		{"revoker", "cert:issue", false},
		{"auditor", "log:read", true},
		{"auditor", "log:export", true},
		{"auditor", "cert:revoke", false},
		{"readonly", "swagger:view", true},
		{"readonly", "ca:list", true},
		{"readonly", "cert:revoke", false},
		{"agent", "gateway:admin", true},
		{"agent", "gateway:ops", true},
		{"agent", "cert:issue", false},
		{"nonexistent", "ca:list", false},
	}
	for _, tt := range tests {
		got := p.HasGrant(tt.role, tt.capability)
		if got != tt.want {
			t.Errorf("HasGrant(%q, %q) = %v, want %v", tt.role, tt.capability, got, tt.want)
		}
	}
}

func TestPolicy_RoleGrants(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	grants := p.RoleGrants("admin")
	if len(grants) == 0 {
		t.Fatal("admin grants empty")
	}
	grants = p.RoleGrants("nonexistent")
	if grants != nil {
		t.Fatal("expected nil for nonexistent role")
	}
}

func TestPolicy_ProfileRoles(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	roles := p.ProfileRoles("m-admin")
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("m-admin profile: expected [admin], got %v", roles)
	}
	roles = p.ProfileRoles("m-superadmin")
	if len(roles) != 1 || roles[0] != "superadmin" {
		t.Fatalf("m-superadmin profile: expected [superadmin], got %v", roles)
	}
	roles = p.ProfileRoles("agent-proxy")
	if len(roles) != 1 || roles[0] != "agent" {
		t.Fatalf("agent-proxy profile: expected [agent], got %v", roles)
	}
	roles = p.ProfileRoles("m-operator")
	if len(roles) != 0 {
		t.Fatalf("m-operator profile: expected [] (operator has no cert profile), got %v", roles)
	}
	roles = p.ProfileRoles("nonexistent")
	if len(roles) != 0 {
		t.Fatalf("nonexistent profile: expected [], got %v", roles)
	}
}

func TestPolicy_RoleByOU(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	tests := []struct {
		ou   string
		want string
	}{
		{"admin", "admin"},
		{"SuperAdmin", "superadmin"},
		{"operator", "operator"},
		{"auditor", "auditor"},
		{"revoker", "revoker"},
		{"readonly", "readonly"},
		{"console", "console"},
		{"auto-renew", "auto-renew"},
		{"reporter", "reporter"},
		{"gateway:admin", ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		got := p.RoleByOU(tt.ou)
		if got != tt.want {
			t.Errorf("RoleByOU(%q) = %q, want %q", tt.ou, got, tt.want)
		}
	}
}

func TestPolicy_MatchGrants(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	matched := p.MatchGrants([]string{"admin"}, []string{"cert:issue", "cert:revoke", "invalid:foo"})
	if len(matched) != 2 {
		t.Fatalf("admin match: expected 2, got %v", matched)
	}
	matched = p.MatchGrants([]string{"superadmin"}, []string{"ca:create", "ca:delete"})
	if len(matched) != 2 {
		t.Fatalf("superadmin match: expected 2, got %v", matched)
	}
	matched = p.MatchGrants([]string{"operator"}, []string{"ca:create", "cert:issue"})
	if len(matched) != 1 || matched[0] != "cert:issue" {
		t.Fatalf("operator match: expected [cert:issue], got %v", matched)
	}
	matched = p.MatchGrants([]string{"nonexistent"}, []string{"ca:create"})
	if matched != nil {
		t.Fatalf("nonexistent role: expected nil, got %v", matched)
	}
}

func TestPolicy_IntersectGrants(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	result := p.IntersectGrants([]string{"admin"}, []string{"cert:issue", "some:random"})
	if len(result) != 1 || result[0] != "cert:issue" {
		t.Fatalf("admin intersect: expected [cert:issue], got %v", result)
	}
	result = p.IntersectGrants([]string{"superadmin"}, []string{"ca:create", "some:random"})
	if len(result) != 1 || result[0] != "ca:create" {
		t.Fatalf("superadmin intersect: expected [ca:create], got %v", result)
	}
	result = p.IntersectGrants([]string{"operator"}, []string{"ca:create", "cert:issue"})
	if len(result) != 1 || result[0] != "cert:issue" {
		t.Fatalf("operator intersect: expected [cert:issue], got %v", result)
	}
	result = p.IntersectGrants([]string{"auditor"}, []string{"cert:revoke", "cert:issue"})
	if result != nil {
		t.Fatalf("auditor intersect: expected nil, got %v", result)
	}
}

func TestHasPerm_WithPolicy(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	SetPolicy(p)
	defer SetPolicy(nil)

	if !HasPerm("superadmin", PermCACreate) {
		t.Fatal("superadmin should have ca:create via policy")
	}
	if HasPerm("admin", PermCACreate) {
		t.Fatal("admin should NOT have ca:create via policy")
	}
	if !HasPerm("admin", PermCertIssue) {
		t.Fatal("admin should have cert:issue via policy")
	}
	if HasPerm("operator", PermCACreate) {
		t.Fatal("operator should NOT have ca:create via policy")
	}
	if !HasPerm("auditor", PermLogRead) {
		t.Fatal("auditor should have log:read via policy")
	}
}

func TestHasPerm_Fallback(t *testing.T) {
	SetPolicy(nil)
	if !HasPerm("admin", PermCertIssue) {
		t.Fatal("admin should have cert:issue via fallback")
	}
	if HasPerm("operator", PermCACreate) {
		t.Fatal("operator should NOT have ca:create via fallback")
	}
	if HasPerm("nonexistent", PermCAList) {
		t.Fatal("nonexistent role should have no permissions")
	}
}

func TestPolicy_PatternMatching(t *testing.T) {
	p := &Policy{
		Version: "v1",
		Roles: map[string]RoleDef{
			"test": {
				Grants: []string{"ca:*", "cert:list", "gateway:*"},
			},
		},
	}
	tests := []struct {
		cap  string
		want bool
	}{
		{"ca:create", true},
		{"ca:delete", true},
		{"cert:list", true},
		{"cert:issue", false},
		{"gateway:admin", true},
		{"gateway:ops", true},
		{"unknown:foo", false},
	}
	for _, tt := range tests {
		got := p.HasGrant("test", tt.cap)
		if got != tt.want {
			t.Errorf("HasGrant(test, %q) = %v, want %v", tt.cap, got, tt.want)
		}
	}
}

func TestLoadPolicy_Errors(t *testing.T) {
	_, err := LoadPolicyData([]byte(`{}`))
	if err == nil {
		t.Fatal("expected error for empty policy")
	}
	_, err = LoadPolicyData([]byte(`{"version":"v1","roles":{}}`))
	if err == nil {
		t.Fatal("expected error for empty roles")
	}
	_, err = LoadPolicyData([]byte(`invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestValidateOUS(t *testing.T) {
	if err := ValidateOUS([]string{"gateway:admin", "admin"}); err != nil {
		t.Fatalf("valid OUs rejected: %v", err)
	}
	if err := ValidateOUS([]string{"gateway:mysql-prod"}); err != nil {
		t.Fatalf("valid namespaced OU rejected: %v", err)
	}
	for _, bad := range [][]string{
		{"*"},
		{"gateway:*"},
		{"web:*"},
		{"admin", "*"},
		{"admin", ""},
		{"admin", "gateway:?"},
		{"line\nbreak"},
	} {
		if err := ValidateOUS(bad); err == nil {
			t.Errorf("ValidateOUS(%q) should reject wildcard/empty/control OU", bad)
		}
	}
}

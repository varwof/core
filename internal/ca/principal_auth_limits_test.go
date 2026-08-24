package ca

import (
	"testing"
)

func TestValidatePA_GrantsLimit(t *testing.T) {
	// 256 grants → pass.
	caps := make([]Capability, MaxGrantEntries)
	for i := range caps {
		caps[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	if err := validatePA(caps); err != nil {
		t.Fatalf("256 grants should pass: %v", err)
	}
	// 257 grants → reject.
	over := make([]Capability, MaxGrantEntries+1)
	for i := range over {
		over[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	if err := validatePA(over); err == nil {
		t.Fatal("257 grants should be rejected")
	}
	// Empty → pass.
	if err := validatePA(nil); err != nil {
		t.Fatalf("nil grants should pass: %v", err)
	}
}

func TestValidatePA_SchemeCapLength(t *testing.T) {
	// schemeId 128 / capabilityId 256 → pass.
	ok := Capability{SchemeId: string(make([]byte, 128)), CapabilityId: string(make([]byte, 256))}
	if err := validatePA([]Capability{ok}); err != nil {
		t.Fatalf("max length should pass: %v", err)
	}
	// Overflow → reject.
	bad := Capability{SchemeId: "", CapabilityId: "c"}
	if err := validatePA([]Capability{bad}); err == nil {
		t.Fatal("empty schemeId should be rejected")
	}
}

func TestBuildPrincipalAuthorizationExtension_Overflow(t *testing.T) {
	over := make([]Capability, MaxGrantEntries+1)
	for i := range over {
		over[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	if _, err := BuildPrincipalAuthorizationExtension(PrincipalAuthorizationConfig{Grants: over}); err == nil {
		t.Fatal("over-limit grants should be rejected at build time")
	}
}

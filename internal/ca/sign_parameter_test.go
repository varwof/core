// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"strings"
	"testing"
)

func TestValidateParameterSubset_MaxRows(t *testing.T) {
	granted := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}
	// declared ≤ granted → allow.
	ok := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}
	if err := ValidateParameterSubset(granted, ok); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	// declared out of bounds → reject.
	over := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":5000}`)}
	err := ValidateParameterSubset(granted, over)
	if err == nil {
		t.Fatal("expected error for over-bound declared max_rows")
	}
	if !strings.Contains(err.Error(), "max_rows") {
		t.Fatalf("error should mention max_rows: %v", err)
	}
}

func TestValidateParameterSubset_MaxConcurrent(t *testing.T) {
	granted := Capability{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:query", Parameters: []byte(`{"max":8}`)}
	// declared larger → reject.
	over := Capability{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:query", Parameters: []byte(`{"max":16}`)}
	if err := ValidateParameterSubset(granted, over); err == nil {
		t.Fatal("expected error for over-bound max")
	}
	// declared smaller → allow.
	ok := Capability{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:query", Parameters: []byte(`{"max":4}`)}
	if err := ValidateParameterSubset(granted, ok); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestValidateParameterSubset_NoParams(t *testing.T) {
	// No declared parameters → allow.
	granted := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}
	declared := Capability{SchemeId: "report", CapabilityId: "query"}
	if err := ValidateParameterSubset(granted, declared); err != nil {
		t.Fatalf("expected pass for no declared params, got %v", err)
	}
	// Grant has no parameters → treated as unlimited, allow.
	granted2 := Capability{SchemeId: "report", CapabilityId: "query"}
	declared2 := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":9999}`)}
	if err := ValidateParameterSubset(granted2, declared2); err != nil {
		t.Fatalf("expected pass for unbounded grant, got %v", err)
	}
}

func TestValidateParameterSubset_UnknownScheme(t *testing.T) {
	granted := Capability{SchemeId: "custom-scheme", CapabilityId: "x", Parameters: []byte(`{"foo":1}`)}
	declared := Capability{SchemeId: "custom-scheme", CapabilityId: "x", Parameters: []byte(`{"foo":99}`)}
	if err := ValidateParameterSubset(granted, declared); err != nil {
		t.Fatalf("unknown scheme should pass, got %v", err)
	}
}

func TestValidateParameterSubset_SchemeVersionBump(t *testing.T) {
	// M3 fix: scheme version bump (report → report-v2, gateway → gateway-v2) must
	// still enforce numeric boundaries instead of silently disabling them.
	granted := Capability{SchemeId: "report-v2", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}
	over := Capability{SchemeId: "report-v2", CapabilityId: "query", Parameters: []byte(`{"max_rows":5000}`)}
	if err := ValidateParameterSubset(granted, over); err == nil {
		t.Fatal("report-v2 over-bound max_rows should be rejected")
	}
	ok := Capability{SchemeId: "report-v2", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}
	if err := ValidateParameterSubset(granted, ok); err != nil {
		t.Fatalf("report-v2 in-bound should pass: %v", err)
	}

	gGranted := Capability{SchemeId: "gateway-v2", CapabilityId: "query", Parameters: []byte(`{"max":8}`)}
	gOver := Capability{SchemeId: "gateway-v2", CapabilityId: "query", Parameters: []byte(`{"max":16}`)}
	if err := ValidateParameterSubset(gGranted, gOver); err == nil {
		t.Fatal("gateway-v2 over-bound max should be rejected")
	}
}

func TestValidateParameterSubset_MalformedJSONFailClosed(t *testing.T) {
	// M3 fix: malformed parameter JSON must be an error (fail-closed), not
	// silently treated as "no boundary".
	granted := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}
	bad := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{not-json`)}
	if err := ValidateParameterSubset(granted, bad); err == nil {
		t.Fatal("malformed declared parameters should fail closed")
	}
	badGrant := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{oops`)}
	ok := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}
	if err := ValidateParameterSubset(badGrant, ok); err == nil {
		t.Fatal("malformed granted parameters should fail closed")
	}

	gGranted := Capability{SchemeId: "gateway-v1", CapabilityId: "query", Parameters: []byte(`{"max":8}`)}
	gBad := Capability{SchemeId: "gateway-v1", CapabilityId: "query", Parameters: []byte(`{"max":"high"}`)}
	if err := ValidateParameterSubset(gGranted, gBad); err == nil {
		t.Fatal("non-integer max should fail closed")
	}
}

func TestValidatePrincipalAuthForAIC_ParameterOverflow(t *testing.T) {
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":5000}`)}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}},
	}
	err := validatePrincipalAuthForAIC(aic, pa)
	if err == nil {
		t.Fatal("expected overflow rejection")
	}
	if !strings.Contains(err.Error(), "max_rows") {
		t.Fatalf("expected max_rows in error: %v", err)
	}
}

func TestValidatePrincipalAuthForAIC_ParameterOK(t *testing.T) {
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}},
	}
	if err := validatePrincipalAuthForAIC(aic, pa); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestValidatePrincipalAuthForAIC_SchemeMismatch(t *testing.T) {
	// H10 fix: a grant whose scheme differs from the AIC capability's scheme must
	// NOT cover it (previously CapabilityId-only matching let a "other-scheme"
	// grant cover a "report" capability — cross-scheme escalation).
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "report", CapabilityId: "query"}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "other-scheme", CapabilityId: "query"}},
	}
	err := validatePrincipalAuthForAIC(aic, pa)
	if err == nil {
		t.Fatal("cross-scheme grant must NOT cover a scheme-scoped AIC capability (H10)")
	}
}

func TestValidatePrincipalAuthForAIC_GenericSchemeMatches(t *testing.T) {
	// Backward compatibility: an empty (generic) scheme on either side still
	// matches by CapabilityId (historical capabilities had no scheme).
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "", CapabilityId: "query"}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "report", CapabilityId: "query"}},
	}
	if err := validatePrincipalAuthForAIC(aic, pa); err != nil {
		t.Fatalf("generic AIC scheme should be covered by any grant scheme: %v", err)
	}
}

func TestValidatePrincipalAuthForAIC_SchemeMismatchParamNotChecked(t *testing.T) {
	// Cross-scheme is rejected outright now (H10), so this scenario cannot
	// reach parameter comparison.
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":9999}`)}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "other", CapabilityId: "query", Parameters: []byte(`{"max_rows":1}`)}},
	}
	if err := validatePrincipalAuthForAIC(aic, pa); err == nil {
		t.Fatal("cross-scheme should be rejected before parameter check (H10)")
	}
}

func TestValidatePrincipalAuthForAIC_SameSchemeCovers(t *testing.T) {
	// Exact-scheme match covers and performs parameter-level validation.
	aic := &AICConfig{
		Capabilities: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}},
	}
	pa := &PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":1000}`)}},
	}
	if err := validatePrincipalAuthForAIC(aic, pa); err != nil {
		t.Fatalf("same-scheme coverage should pass: %v", err)
	}
}

package capregistry

import (
	"strings"
	"testing"

	pki "github.com/varwof/types"
)

func TestLoadEmbeddedAndValidate(t *testing.T) {
	cr := New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("LoadAndSet: %v", err)
	}
	if !cr.Enabled() {
		t.Fatal("expected enabled")
	}
	// Valid capability
	if err := cr.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("valid capability rejected: %v", err)
	}
	// Invalid capability
	err := cr.ValidateCapability("varwof/core:no:such")
	if err == nil {
		t.Error("expected error for unknown capability")
	}
	if !strings.Contains(err.Error(), "unknown capability") {
		t.Errorf("error = %q, want 'unknown capability'", err)
	}
	// Unknown scheme
	err = cr.ValidateCapability("bogus/vendor:foo")
	if err == nil {
		t.Error("expected error for unknown scheme")
	}
}

func TestValidateAICCapabilities(t *testing.T) {
	cr := New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("LoadAndSet: %v", err)
	}
	// All valid
	caps := []pki.Capability{
		{SchemeId: "varwof/core", CapabilityId: "cert:issue"},
		{SchemeId: "varwof/core", CapabilityId: "ca:list"},
	}
	if err := cr.ValidateAICCapabilities(caps); err != nil {
		t.Errorf("valid AIC caps rejected: %v", err)
	}
	// Contains an invalid capability
	caps = append(caps, pki.Capability{SchemeId: "varwof/core", CapabilityId: "no:such"})
	err := cr.ValidateAICCapabilities(caps)
	if err == nil {
		t.Error("expected error for invalid AIC cap")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want 'not registered'", err)
	}
}

func TestNilSafety(t *testing.T) {
	cr := New() // Not loaded
	// nil safe: should not block
	if err := cr.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("nil registry should not error: %v", err)
	}
	if err := cr.ValidateAICCapabilities(nil); err != nil {
		t.Errorf("nil registry should not error: %v", err)
	}
	if cr.Enabled() {
		t.Error("expected disabled")
	}
}

func TestLoadAndSetOverride(t *testing.T) {
	// Loading again after initial load (hot-reload path) should succeed without losing schemes
	cr := New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := cr.ValidateCapability("varwof/gateway:proxy:http"); err != nil {
		t.Errorf("gateway capability not loaded: %v", err)
	}
}

func TestValidateClaim(t *testing.T) {
	cr := New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("LoadAndSet: %v", err)
	}
	if err := cr.ValidateClaim("varwof/core", "cert:issue"); err != nil {
		t.Errorf("valid claim rejected: %v", err)
	}
	if err := cr.ValidateClaim("varwof/core", "no:such"); err == nil {
		t.Error("expected error for unknown claim capability")
	}
}

package ca

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ── A6: Parameter-level subset validation (spec §issuance validation + P2-B-05) ──
//
// CA validates each AIC capability's parameters against PA grant parameter boundaries
// at issuance time. Capability-level (capabilityId) subset validation is in
// validatePrincipalAuthForAIC; this file supplements parameter-level (parameters)
// boundary checks. Aligned with gateway-lib's MaxRowsValidator semantics:
// declared ≤ granted, out-of-bounds rejects issuance.

// ValidateParameterSubset checks whether the declared (AIC capability) parameters
// fall within the granted (PA grant authorization boundary) parameter range.
// Scheme mismatch or grant has no parameters → no parameter-level rules, pass.
// Out-of-bounds returns a non-nil error.
func ValidateParameterSubset(granted, declared Capability) error {
	if len(declared.Parameters) == 0 {
		// Declared has no parameters: always pass (capability-level validated elsewhere).
		return nil
	}
	if len(granted.Parameters) == 0 {
		// Grant specifies no parameter boundary → treated as unlimited (aligned with gateway maxRowsValidator).
		return nil
	}
	// M3 fix: match parameter semantics by scheme *prefix* (e.g. "report" matches
	// "report", "report-v1", "report-v2") so a scheme version bump does not
	// silently disable all numeric boundaries (fail-open). The scheme namespace
	// is semantic — "report"/"gateway" families carry max_rows/max respectively.
	switch {
	case hasSchemePrefix(declared.SchemeId, "report"):
		return validateMaxRowsParam(granted, declared)
	case hasSchemePrefix(declared.SchemeId, "gateway"):
		return validateMaxConcurrentParam(granted, declared)
	default:
		// Unknown scheme: parameter semantics defined by scheme, CA does not infer values, pass
		// (capability-level subset already ensures AIC caps ⊆ PA grants).
		return nil
	}
}

// hasSchemePrefix reports whether the scheme identifier belongs to a known
// parameter-semantics family (prefix match on the scheme segment). The scheme
// namespace historically uses both "report"/"gateway" and the "varwof-"
// qualified forms ("varwof-gateway-v1"), so both prefixes are accepted. The ':'
// in a full capability id ("gateway-v2:query") is never part of the scheme, so
// a bare prefix on SchemeId cannot over-match across families.
func hasSchemePrefix(schemeID, family string) bool {
	if schemeID == family || strings.HasPrefix(schemeID, family+"-") {
		return true
	}
	return strings.HasPrefix(schemeID, "varwof-"+family)
}

// validateMaxRowsParam validates the max_rows boundary (declared ≤ granted).
func validateMaxRowsParam(granted, declared Capability) error {
	g, gOK, err := parseMaxRows(granted.Parameters)
	if err != nil {
		return fmt.Errorf("capability %s.%s: %v", granted.SchemeId, granted.CapabilityId, err)
	}
	d, dOK, err := parseMaxRows(declared.Parameters)
	if err != nil {
		return fmt.Errorf("capability %s.%s: %v", declared.SchemeId, declared.CapabilityId, err)
	}
	if !dOK {
		return nil
	}
	if gOK && d > g {
		return fmt.Errorf("capability %s.%s: declared max_rows %d exceeds granted boundary %d",
			declared.SchemeId, declared.CapabilityId, d, g)
	}
	return nil
}

// validateMaxConcurrentParam validates the max-concurrent boundary (declared ≤ granted).
func validateMaxConcurrentParam(granted, declared Capability) error {
	g, gOK, err := parseNumericParam(granted.Parameters, "max")
	if err != nil {
		return fmt.Errorf("capability %s.%s: %v", granted.SchemeId, granted.CapabilityId, err)
	}
	d, dOK, err := parseNumericParam(declared.Parameters, "max")
	if err != nil {
		return fmt.Errorf("capability %s.%s: %v", declared.SchemeId, declared.CapabilityId, err)
	}
	if !dOK {
		return nil
	}
	if gOK && d > g {
		return fmt.Errorf("capability %s.%s: declared max %d exceeds granted boundary %d",
			declared.SchemeId, declared.CapabilityId, d, g)
	}
	return nil
}

// parseMaxRows parses {"max_rows": N} (returns g as the granted boundary value).
func parseMaxRows(raw []byte) (int64, bool, error) {
	var p struct {
		MaxRows *int64 `json:"max_rows"`
	}
	if len(raw) == 0 {
		return 0, false, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, false, fmt.Errorf("invalid parameters JSON: %v", err)
	}
	if p.MaxRows == nil || *p.MaxRows < 0 {
		return 0, false, nil
	}
	return *p.MaxRows, true, nil
}

// parseNumericParam parses a numeric parameter for the specified key in a JSON object.
// M3 fix: malformed JSON is returned as an error (fail-closed) instead of being
// silently treated as "not set" (fail-open) — a corrupted/broken parameter block
// must not silently skip the boundary check.
func parseNumericParam(raw []byte, key string) (int64, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, false, fmt.Errorf("invalid parameters JSON: %v", err)
	}
	v, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	var n int64
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, false, fmt.Errorf("parameter %q must be an integer: %v", key, err)
	}
	return n, true, nil
}

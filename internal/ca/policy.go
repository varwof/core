// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PolicyRule struct {
	Comment         string   `json:"comment,omitempty"`
	AllowedCNs      []string `json:"allowed_cns,omitempty"`
	DeniedCNs       []string `json:"denied_cns,omitempty"`
	AllowedSANs     []string `json:"allowed_sans,omitempty"`
	DeniedSANs      []string `json:"denied_sans,omitempty"`
	AllowedProfiles []string `json:"allowed_profiles,omitempty"`
	AllowedKeyTypes []string `json:"allowed_key_types,omitempty"`
	AllowedCAs      []string `json:"allowed_cas,omitempty"`
	MaxValidityDays int      `json:"max_validity_days,omitempty"`
}

type Policy struct {
	Rules []PolicyRule `json:"rules"`
}

func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy file: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("policy parse: %w", err)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("policy must contain at least one rule")
	}
	return &p, nil
}

func CheckPolicy(sc *SignConfig) error {
	if sc.Policy == nil {
		return nil
	}

	for _, rule := range sc.Policy.Rules {
		if matchRule(sc, rule) {
			return nil
		}
	}

	return fmt.Errorf("no policy rule matched: CN=%q profile=%q ca=%q", sc.CommonName, sc.Profile, sc.CAName)
}

func matchRule(sc *SignConfig, rule PolicyRule) bool {
	if !matchGlobList(sc.CommonName, rule.AllowedCNs, rule.DeniedCNs) {
		return false
	}

	for _, san := range sc.SANs {
		if !matchGlobList(san, rule.AllowedSANs, rule.DeniedSANs) {
			return false
		}
	}

	if len(rule.AllowedProfiles) > 0 {
		found := false
		for _, p := range rule.AllowedProfiles {
			if string(sc.Profile) == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rule.AllowedKeyTypes) > 0 {
		found := false
		kt := sc.KeyType
		if kt == "" {
			kt = "ecdsa-p256"
		}
		for _, a := range rule.AllowedKeyTypes {
			if kt == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rule.AllowedCAs) > 0 {
		found := false
		for _, a := range rule.AllowedCAs {
			if sc.CAName == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if rule.MaxValidityDays > 0 {
		maxDur := time.Duration(rule.MaxValidityDays) * 24 * time.Hour
		if sc.Validity > maxDur {
			return false
		}
	}

	return true
}

func matchGlobList(val string, allowed, denied []string) bool {
	matched := false
	if len(allowed) == 0 {
		matched = true
	} else {
		for _, a := range allowed {
			if globMatch(val, a) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return false
	}
	for _, d := range denied {
		if globMatch(val, d) {
			return false
		}
	}
	return true
}

func globMatch(val, pattern string) bool {
	if pattern == "*" {
		return true
	}
	// M13 fix: DNS hostnames are case-insensitive, so a deny rule like
	// "*.example.com" must also block "ATTACKER.EXAMPLE.COM". Normalize both
	// sides to lowercase before matching.
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(val, pattern)
	}
	val = strings.ToLower(val)
	pattern = strings.ToLower(pattern)

	// M13 fix: support an arbitrary number of "*" segments (the old code only
	// handled a single "*", silently failing on legitimate multi-wildcard
	// patterns and thus breaking availability of deny lists).
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(val, parts[0]) {
		return false
	}
	if !strings.HasSuffix(val, parts[len(parts)-1]) {
		return false
	}
	rest := val[len(parts[0]) : len(val)-len(parts[len(parts)-1])]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(rest, part)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(part):]
	}
	return true
}

func DefaultPolicyPath(cfgDir string) string {
	return filepath.Join(cfgDir, "policy.json")
}

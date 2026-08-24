// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package routing implements JSON-configured URL-level authorization for varwof-core.
//
// It replaces the hardcoded switch-case in mux.go with a configurable route table.
// Each route maps (method, path pattern) → required permission + constraints.
//
// Adding a new API endpoint = adding a JSON entry. No code change needed.
package routing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// RouteRule defines a single authorization rule for an API endpoint.
type RouteRule struct {
	Method      string   `json:"method"`                 // HTTP method: GET/POST/PUT/DELETE/PATCH/* (wildcard)
	Path        string   `json:"path"`                   // URL path pattern: /api/v1/cert/{ca}/{serial}
	Permission  string   `json:"permission"`             // Required permission: cert:issue, cert:revoke, etc.
	Description string   `json:"description,omitempty"`  // Human-readable description (for audit/docs)
	CAScope     bool     `json:"ca_scope,omitempty"`     // Enable CA scope check (enterprise mode)
	RequireRole []string `json:"require_role,omitempty"` // Additional role whitelist (above permission)
	AllowAIC    *bool    `json:"allow_aic,omitempty"`    // Allow AIC agent access (nil = true)
	MaxValidity string   `json:"max_validity,omitempty"` // Max cert validity for issuance (e.g. "720h", "30d")
}

// compiledRule is a pre-compiled rule with parsed path pattern.
type compiledRule struct {
	rule     *RouteRule
	pattern  pathPattern
	priority int // lower = higher priority
}

// pathPattern is the interface for compiled path patterns.
type pathPattern interface {
	// Match returns (matched, params) where params extracts {name} segments.
	Match(path string) (bool, map[string]string)
	// Specificity returns a priority score (higher = more specific).
	Specificity() int
}

// RouteRules is the full authorization configuration.
type RouteRules struct {
	Version           string      `json:"version"`
	Rules             []RouteRule `json:"rules"`
	DefaultPermission string      `json:"default_permission,omitempty"`
	PublicPaths       []string    `json:"public_paths,omitempty"`

	mu       sync.RWMutex
	compiled []compiledRule
	public   map[string]bool
}

// LoadFile reads and parses a route rules JSON file.
func LoadFile(path string) (*RouteRules, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("routing: read %s: %w", path, err)
	}
	return LoadData(data)
}

// LoadData parses route rules from JSON bytes.
func LoadData(data []byte) (*RouteRules, error) {
	var rr RouteRules
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("routing: parse: %w", err)
	}
	if err := rr.Compile(); err != nil {
		return nil, err
	}
	return &rr, nil
}

// Compile pre-parses all rules for fast matching. Called automatically by Load*.
func (rr *RouteRules) Compile() error {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	// M21 fix: reject an empty rules table — silently falling back to a hardcoded
	// chain (or worse, allowing everything) is a fail-open trap. Operators must
	// supply explicit rules; use the embedded default when no file is configured.
	if len(rr.Rules) == 0 {
		return fmt.Errorf("routing: no rules defined — refusing to compile empty route table (fail-closed)")
	}

	rr.compiled = make([]compiledRule, 0, len(rr.Rules))
	for i, rule := range rr.Rules {
		pat, err := compilePath(rule.Path)
		if err != nil {
			return fmt.Errorf("routing: rule %d (%s): %w", i, rule.Path, err)
		}
		rr.compiled = append(rr.compiled, compiledRule{
			rule:     &rr.Rules[i],
			pattern:  pat,
			priority: pat.Specificity(),
		})
	}
	// Sort by specificity descending (most specific first).
	sort.Slice(rr.compiled, func(i, j int) bool {
		return rr.compiled[i].priority > rr.compiled[j].priority
	})

	rr.public = make(map[string]bool, len(rr.PublicPaths))
	for _, p := range rr.PublicPaths {
		rr.public[p] = true
	}
	return nil
}

// IsPublic returns true if the path is in the public paths list (no auth required).
// Supports glob patterns ending with /* (prefix match).
func (rr *RouteRules) IsPublic(path string) bool {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	if rr.public[path] {
		return true
	}
	for p := range rr.public {
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "/*")
			// M18 fix: match only at a path boundary — "/health/*" must not make
			// "/healthXYZ" public. A bare "/*" matches everything (by design).
			if prefix == "" {
				return true
			}
			if strings.HasPrefix(path, prefix) && (len(path) == len(prefix) || path[len(prefix)] == '/') {
				return true
			}
		}
	}
	return false
}

// Match finds the first rule matching (method, path).
// Returns nil if no rule matches (caller should decide: deny or fallback).
func (rr *RouteRules) Match(method, path string) *RouteRule {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	for _, cr := range rr.compiled {
		if !matchMethod(cr.rule.Method, method) {
			continue
		}
		ok, _ := cr.pattern.Match(path)
		if ok {
			return cr.rule
		}
	}
	return nil
}

// DefaultRule returns a synthetic rule carrying the configured default permission
// (M21 fix: DefaultPermission was dead config). It allows the server to enforce a
// deny-by-default permission for unmatched routes instead of silently falling back
// to a hardcoded chain. Returns nil when no default is configured.
func (rr *RouteRules) DefaultRule() *RouteRule {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	if rr.DefaultPermission == "" {
		return nil
	}
	return &RouteRule{Permission: rr.DefaultPermission, Path: "*", Method: "*"}
}

// MatchWithParams is like Match but also returns extracted path parameters.
func (rr *RouteRules) MatchWithParams(method, path string) (*RouteRule, map[string]string) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	for _, cr := range rr.compiled {
		if !matchMethod(cr.rule.Method, method) {
			continue
		}
		ok, params := cr.pattern.Match(path)
		if ok {
			return cr.rule, params
		}
	}
	return nil, nil
}

// AllRules returns a copy of the raw rules (for introspection/management API).
func (rr *RouteRules) AllRules() []RouteRule {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	out := make([]RouteRule, len(rr.Rules))
	copy(out, rr.Rules)
	return out
}

// Count returns the number of compiled rules.
func (rr *RouteRules) Count() int {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	return len(rr.compiled)
}

// matchMethod checks if the rule's method matches the request method.
func matchMethod(ruleMethod, reqMethod string) bool {
	if ruleMethod == "*" || ruleMethod == "" {
		return true
	}
	return strings.EqualFold(ruleMethod, reqMethod)
}

// ---- path pattern compiler ----

// literalPattern matches a fixed path exactly.
type literalPattern struct {
	path string
}

func (p *literalPattern) Match(path string) (bool, map[string]string) {
	return p.path == path, nil
}
func (p *literalPattern) Specificity() int { return 1000 + len(p.path) }

// wildcardPattern matches /api/v1/ca/* (single segment).
type wildcardPattern struct {
	prefix string // everything before the *
}

func (p *wildcardPattern) Match(path string) (bool, map[string]string) {
	if !strings.HasPrefix(path, p.prefix) {
		return false, nil
	}
	remainder := path[len(p.prefix):]
	// Single segment: no / allowed after prefix
	if remainder == "" || !strings.Contains(remainder, "/") {
		return true, nil
	}
	return false, nil
}
func (p *wildcardPattern) Specificity() int { return 500 + len(p.prefix) }

// doubleWildcardPattern matches /api/v1/cert/** (multiple segments).
type doubleWildcardPattern struct {
	prefix string
}

func (p *doubleWildcardPattern) Match(path string) (bool, map[string]string) {
	if !strings.HasPrefix(path, p.prefix) {
		return false, nil
	}
	return true, nil
}
func (p *doubleWildcardPattern) Specificity() int { return 400 + len(p.prefix) }

// paramPattern matches /api/v1/cert/{ca}/{serial} with named parameters.
type paramPattern struct {
	segments []patternSegment
}

type patternSegment struct {
	literal string // literal text (empty if parameter)
	param   string // parameter name (empty if literal)
}

func (p *paramPattern) Match(path string) (bool, map[string]string) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != len(p.segments) {
		return false, nil
	}
	params := make(map[string]string)
	for i, seg := range p.segments {
		if seg.param != "" {
			params[seg.param] = parts[i]
		} else if seg.literal != parts[i] {
			return false, nil
		}
	}
	return true, params
}

func (p *paramPattern) Specificity() int {
	// Param patterns are always more specific than wildcards.
	// Base 600 ensures param patterns outrank ** (400+) and * (500+).
	score := 600
	for _, seg := range p.segments {
		if seg.param != "" {
			score += 10
		} else {
			score += 50 + len(seg.literal)
		}
	}
	return score
}

// compilePath parses a path pattern into a pathPattern.
func compilePath(pattern string) (pathPattern, error) {
	// Handle trailing *
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "**")
		return &doubleWildcardPattern{prefix: prefix}, nil
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return &wildcardPattern{prefix: prefix}, nil
	}

	// Check for {param} segments
	if strings.Contains(pattern, "{") {
		return compileParamPattern(pattern)
	}

	// Literal match
	return &literalPattern{path: pattern}, nil
}

func compileParamPattern(pattern string) (*paramPattern, error) {
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	var segs []patternSegment
	for _, s := range segments {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			name := s[1 : len(s)-1]
			if name == "" {
				return nil, fmt.Errorf("empty parameter name in %q", pattern)
			}
			segs = append(segs, patternSegment{param: name})
		} else {
			segs = append(segs, patternSegment{literal: s})
		}
	}
	return &paramPattern{segments: segs}, nil
}

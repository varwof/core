package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	globalPolicy *Policy
	policyMu     sync.RWMutex
)

type Policy struct {
	Version           string                 `json:"version"`
	Roles             map[string]RoleDef     `json:"roles"`
	OUMapping         map[string]string      `json:"ou_mapping"`
	GatewayNamespaces map[string]GatewayNS   `json:"gateway_namespaces"`
	// CapabilityParameters is the parameter defaults map derived by gen-authz from capability.json,
	// keyed by "scheme:capability_id" (e.g. "varwof/core:cert:issue").
	// Used at runtime to validate whether AIC/PA declared parameters are within bounds.
	CapabilityParameters map[string]map[string]any `json:"capability_parameters,omitempty"`
}

type RoleDef struct {
	DisplayName string   `json:"display_name"`
	Profiles    []string `json:"profiles"`
	Grants      []string `json:"grants"`
	Scope       []string `json:"scope,omitempty"`
}

type GatewayNS struct {
	DisplayName string   `json:"display_name"`
	Prefix      string   `json:"prefix"`
	Grants      []string `json:"grants"`
}

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("auth: read policy: %w", err)
	}
	return LoadPolicyData(data)
}

func LoadPolicyData(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("auth: parse policy: %w", err)
	}
	if p.Version == "" {
		return nil, fmt.Errorf("auth: policy missing version")
	}
	if len(p.Roles) == 0 {
		return nil, fmt.Errorf("auth: policy has no roles")
	}
	return &p, nil
}

func SetPolicy(p *Policy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	globalPolicy = p
}

func GetPolicy() *Policy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return globalPolicy
}

func (p *Policy) HasGrant(role string, capability string) bool {
	roleDef, ok := p.Roles[role]
	if !ok {
		return false
	}
	for _, grant := range roleDef.Grants {
		if MatchCapability(capability, grant) {
			return true
		}
	}
	return false
}

func (p *Policy) RoleGrants(role string) []string {
	roleDef, ok := p.Roles[role]
	if !ok {
		return nil
	}
	return roleDef.Grants
}

// GrantCap represents a parsed permission grant (scheme_id + capability_id).
type GrantCap struct {
	Scheme       string
	CapabilityID string
}

// RoleGrantCaps returns the permission grants for a role, parsed from "scheme_id:capability_id" format.
// scheme_id may contain "/" (e.g. "varwof/demo-mysql-v1"), capability_id may contain ":" (e.g. "SELECT:*").
// Rule: find the first ":" from the right; left part is the scheme, right part is the capability_id.
func (p *Policy) RoleGrantCaps(role string) []GrantCap {
	grants := p.RoleGrants(role)
	out := make([]GrantCap, 0, len(grants))
	for _, g := range grants {
		scheme, capID := splitGrant(g)
		out = append(out, GrantCap{Scheme: scheme, CapabilityID: capID})
	}
	return out
}

// splitGrant splits "varwof/demo-mysql-v1:SELECT:*" into scheme="varwof/demo-mysql-v1" and capID="SELECT:*".
// The grant format is "scheme:capability_id"; capability_id may contain ":", so the last ":" is used as the delimiter.
func splitGrant(g string) (scheme, capID string) {
	if i := strings.LastIndex(g, ":"); i > 0 {
		return g[:i], g[i+1:]
	}
	return "generic", g
}

func (p *Policy) ProfileRoles(profile string) []string {
	var roles []string
	for name, def := range p.Roles {
		for _, prof := range def.Profiles {
			if prof == profile {
				roles = append(roles, name)
				break
			}
		}
	}
	return roles
}

func (p *Policy) RoleByOU(ou string) string {
	role, ok := p.OUMapping[ou]
	if !ok {
		return ""
	}
	return role
}

// RoleScope returns the scope list for a role, or nil if not defined.
func (p *Policy) RoleScope(role string) []string {
	roleDef, ok := p.Roles[role]
	if !ok {
		return nil
	}
	return roleDef.Scope
}

// ParamDefaults returns the parameter defaults for a given scheme:capability_id (derived by gen-authz).
// Returns nil if not found.
func (p *Policy) ParamDefaults(scheme, capID string) map[string]any {
	if p == nil || p.CapabilityParameters == nil {
		return nil
	}
	return p.CapabilityParameters[scheme+":"+capID]
}

// HasParamDefault checks whether a parameter has a default value (for bounds checking).
func (p *Policy) HasParamDefault(scheme, capID, param string) (any, bool) {
	params := p.ParamDefaults(scheme, capID)
	if params == nil {
		return nil, false
	}
	v, ok := params[param]
	return v, ok
}

func (p *Policy) MatchGrants(roles []string, capabilities []string) []string {
	if len(roles) == 0 || len(capabilities) == 0 {
		return nil
	}
	matchedSet := make(map[string]bool)
	var matched []string
	for _, role := range roles {
		roleDef, ok := p.Roles[role]
		if !ok {
			continue
		}
		for _, cap := range capabilities {
			if matchedSet[cap] {
				continue
			}
			for _, grant := range roleDef.Grants {
				if MatchCapability(cap, grant) {
					matchedSet[cap] = true
					matched = append(matched, cap)
					break
				}
			}
		}
	}
	return matched
}

func (p *Policy) IntersectGrants(roles []string, aicCapIds []string) []string {
	if len(roles) == 0 || len(aicCapIds) == 0 {
		return nil
	}
	grantSet := make(map[string]bool)
	for _, role := range roles {
		roleDef, ok := p.Roles[role]
		if !ok {
			continue
		}
		for _, grant := range roleDef.Grants {
			grantSet[grant] = true
		}
	}
	var result []string
	for _, capId := range aicCapIds {
		for grant := range grantSet {
			if MatchCapability(capId, grant) {
				result = append(result, capId)
				break
			}
		}
	}
	return result
}

func MatchCapability(id, pattern string) bool {
	if id == pattern {
		return true
	}
	if pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(pattern, id)
	if ok {
		return ok
	}
	if len(pattern) >= 2 && pattern[len(pattern)-1] == '*' && pattern[len(pattern)-2] == ':' {
		prefix := pattern[:len(pattern)-1]
		return len(id) >= len(prefix) && id[:len(prefix)] == prefix
	}
	return false
}

// ValidateOUS rejects OU values that would be interpreted as wildcard roles by
// HasRole/ExtractRoles (M24 fix). A certificate whose OU is "*" or "gateway:*"
// would match any role and is an elevation channel if the requester controls OU.
// Allowed OU values are non-empty, wildcard-free, and free of control characters.
func ValidateOUS(ous []string) error {
	for _, ou := range ous {
		trimmed := strings.TrimSpace(ou)
		if trimmed == "" {
			return fmt.Errorf("OU must not be empty")
		}
		if strings.ContainsAny(trimmed, "*?") {
			return fmt.Errorf("OU %q contains a wildcard; wildcard OUs are not allowed in issued certificates", ou)
		}
		if strings.Contains(trimmed, "\x00") || strings.ContainsAny(trimmed, "\r\n") {
			return fmt.Errorf("OU %q contains control characters", ou)
		}
	}
	return nil
}

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// UserIdentity is the unified person identity model resolved from an identity
// source (bridge-ldap lookup or bridge-oauth userinfo). Phase 2 of
// identity-source unification: core maps these attributes into a base
// identity certificate ("identity-user" profile) without manual subject entry.
type UserIdentity struct {
	Username string   `json:"username"`
	FullName string   `json:"full_name,omitempty"`
	Email    string   `json:"email,omitempty"`
	Dept     string   `json:"dept,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Source   string   `json:"source,omitempty"`
	Disabled bool     `json:"disabled"`
}

// IdentitySource resolves a person's identity attributes from a directory
// service (LDAP/AD via bridge-ldap, or OAuth/OIDC via bridge-oauth) for
// automated certificate issuance.
//
// Lookup resolves the identity for a username. The caller supplies the
// source_tag to route to a specific bridge backend; empty tries all backends
// in bridge configuration order.
type IdentitySource interface {
	Lookup(ctx context.Context, source, username string) (*UserIdentity, error)
}

// IdentitySourceType enumerates supported identity-source kinds.
type IdentitySourceType string

const (
	// IdentitySourceLDAP resolves persons via bridge-ldap's POST /api/v1/lookup.
	IdentitySourceLDAP IdentitySourceType = "ldap"
	// IdentitySourceOAuth resolves persons via bridge-oauth's password grant +
	// userinfo flow (service account). The configured username/password belong
	// to an automation account authorized in the IdP.
	IdentitySourceOAuth IdentitySourceType = "oauth"
)

// IdentitySourceConfig configures the remote identity source used for the
// identity-user profile. See docs/api.md for the full field reference.
type IdentitySourceConfig struct {
	// Type is the identity source kind: "ldap" (bridge-ldap) or "oauth" (bridge-oauth). Default "ldap".
	Type IdentitySourceType `json:"type,omitempty"`
	// SourceURL is the base URL of the identity bridge service, e.g. "http://127.0.0.1:8082".
	SourceURL string `json:"source_url,omitempty"`
	// Token is the bridge management API bearer token. Empty = no auth.
	Token string `json:"token,omitempty"`
	// Source is the default source_tag used when a request does not specify one.
	Source string `json:"source,omitempty"`
	// Username is the automation account username (oauth type only, resource-owner grant).
	Username string `json:"username,omitempty"`
	// Password is the automation account password (oauth type only, resource-owner grant).
	Password string `json:"password,omitempty"`
	// TimeoutSec bounds each upstream bridge request. Default 10.
	TimeoutSec int `json:"timeout_sec,omitempty"`
	// OUFromGroups maps identity-source groups to certificate OU values
	// (RBAC roles). Matching is exact OR case-insensitive suffix containment
	// of the OU-portion of an LDAP group DN. When no rule matches, DefaultOU
	// (or the source dept) is used.
	OUFromGroups map[string]string `json:"ou_from_groups,omitempty"`
	// DefaultOU is the OU written when no OUFromGroups rule matches and the
	// source carries no dept. Empty = omit OU.
	DefaultOU string `json:"default_ou,omitempty"`
	// DisabledOK allows issuing identity-user certs for disabled accounts.
	// Default false: disabled accounts are rejected (fail-closed).
	DisabledOK bool `json:"disabled_ok,omitempty"`
}

func (c *IdentitySourceConfig) effectiveType() IdentitySourceType {
	if c.Type == "" {
		return IdentitySourceLDAP
	}
	return c.Type
}

func (c *IdentitySourceConfig) timeout() time.Duration {
	if c.TimeoutSec <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSec) * time.Second
}

func (c *IdentitySourceConfig) defaultSource() string {
	return c.Source
}

// NewIdentitySource builds an IdentitySource from config. It returns an error
// for an unknown type or an empty bridge URL.
func NewIdentitySource(cfg *IdentitySourceConfig) (IdentitySource, error) {
	if cfg == nil {
		return nil, nil
	}
	if strings.TrimSpace(cfg.SourceURL) == "" {
		return nil, fmt.Errorf("identity source: source_url is required")
	}
	switch cfg.effectiveType() {
	case IdentitySourceLDAP:
		return &remoteIdentitySource{cfg: cfg, client: newIdentityHTTPClient(cfg)}, nil
	case IdentitySourceOAuth:
		return &oauthIdentitySource{cfg: cfg, client: newIdentityHTTPClient(cfg)}, nil
	default:
		return nil, fmt.Errorf("identity source: unknown type %q", cfg.Type)
	}
}

func newIdentityHTTPClient(cfg *IdentitySourceConfig) *http.Client {
	return &http.Client{Timeout: cfg.timeout()}
}

func identityBearerToken(cfg *IdentitySourceConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Token
}

// remoteIdentitySource implements IdentitySource via bridge-ldap's lookup API.
type remoteIdentitySource struct {
	cfg    *IdentitySourceConfig
	client *http.Client
}

func (s *remoteIdentitySource) Lookup(ctx context.Context, source, username string) (*UserIdentity, error) {
	if username == "" {
		return nil, fmt.Errorf("identity lookup: username required")
	}
	url := strings.TrimSuffix(s.cfg.SourceURL, "/") + "/api/v1/lookup"
	body, _ := json.Marshal(map[string]string{
		"source":   firstNonEmpty(source, s.cfg.defaultSource()),
		"username": username,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := identityBearerToken(s.cfg); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity lookup: %w", err)
	}
	defer resp.Body.Close()
	var raw struct {
		DN       string   `json:"dn"`
		StaffID  string   `json:"staff_id"`
		FullName string   `json:"full_name"`
		Dept     string   `json:"dept"`
		Email    string   `json:"email"`
		Source   string   `json:"source"`
		Disabled bool     `json:"disabled"`
		Groups   []string `json:"groups"`
		Error    string   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("identity lookup: decode: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("identity lookup: user %q not found", username)
	case http.StatusBadRequest:
		if raw.Error != "" {
			return nil, fmt.Errorf("identity lookup: %s", raw.Error)
		}
		return nil, fmt.Errorf("identity lookup: bad request (status %d)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("identity lookup: bridge status %d: %s", resp.StatusCode, raw.Error)
	}
	uid := raw.StaffID
	if uid == "" {
		uid = username
	}
	return &UserIdentity{
		Username: uid,
		FullName: raw.FullName,
		Email:    raw.Email,
		Dept:     raw.Dept,
		Groups:   raw.Groups,
		Source:   firstNonEmpty(raw.Source, source),
		Disabled: raw.Disabled,
	}, nil
}

// oauthIdentitySource implements IdentitySource via bridge-oauth's resource-owner
// grant: POST /api/v1/token (password grant) then POST /api/v1/userinfo.
type oauthIdentitySource struct {
	cfg    *IdentitySourceConfig
	client *http.Client
}

func (s *oauthIdentitySource) Lookup(ctx context.Context, source, username string) (*UserIdentity, error) {
	if username == "" {
		return nil, fmt.Errorf("identity lookup: username required")
	}
	if s.cfg.Username == "" || s.cfg.Password == "" {
		return nil, fmt.Errorf("identity lookup: oauth source requires username/password automation account")
	}
	base := strings.TrimSuffix(s.cfg.SourceURL, "/")
	src := firstNonEmpty(source, s.cfg.defaultSource())

	// 1. Obtain an access token via resource-owner password grant.
	tokURL := base + "/api/v1/token"
	tokBody, _ := json.Marshal(map[string]string{
		"source":   src,
		"username": s.cfg.Username,
		"password": s.cfg.Password,
	})
	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURL, bytes.NewReader(tokBody))
	if err != nil {
		return nil, err
	}
	tokReq.Header.Set("Content-Type", "application/json")
	if tok := identityBearerToken(s.cfg); tok != "" {
		tokReq.Header.Set("Authorization", "Bearer "+tok)
	}
	tokResp, err := s.client.Do(tokReq)
	if err != nil {
		return nil, fmt.Errorf("identity lookup: token: %w", err)
	}
	defer tokResp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("identity lookup: decode token: %w", err)
	}
	if tokResp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		if tok.Error != "" {
			return nil, fmt.Errorf("identity lookup: token: %s", tok.Error)
		}
		return nil, fmt.Errorf("identity lookup: token: status %d", tokResp.StatusCode)
	}

	// 2. Resolve the person via userinfo.
	infoURL := base + "/api/v1/userinfo"
	infoBody, _ := json.Marshal(map[string]string{
		"source": src,
		"token":  tok.AccessToken,
	})
	infoReq, err := http.NewRequestWithContext(ctx, http.MethodPost, infoURL, bytes.NewReader(infoBody))
	if err != nil {
		return nil, err
	}
	infoReq.Header.Set("Content-Type", "application/json")
	if tok := identityBearerToken(s.cfg); tok != "" {
		infoReq.Header.Set("Authorization", "Bearer "+tok)
	}
	infoResp, err := s.client.Do(infoReq)
	if err != nil {
		return nil, fmt.Errorf("identity lookup: userinfo: %w", err)
	}
	defer infoResp.Body.Close()
	var info struct {
		Sub      string   `json:"sub"`
		Username string   `json:"username"`
		FullName string   `json:"full_name"`
		Email    string   `json:"email"`
		Groups   []string `json:"groups"`
		Source   string   `json:"source"`
		Error    string   `json:"error"`
	}
	if err := json.NewDecoder(infoResp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("identity lookup: decode userinfo: %w", err)
	}
	switch infoResp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("identity lookup: user %q not found", username)
	default:
		if info.Error != "" {
			return nil, fmt.Errorf("identity lookup: userinfo: %s", info.Error)
		}
		return nil, fmt.Errorf("identity lookup: userinfo status %d", infoResp.StatusCode)
	}
	uid := firstNonEmpty(info.Username, info.Sub)
	if uid == "" {
		uid = username
	}
	return &UserIdentity{
		Username: uid,
		FullName: info.FullName,
		Email:    info.Email,
		Groups:   info.Groups,
		Source:   firstNonEmpty(info.Source, src),
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// CertificateOUS from identity attributes applies the OUFromGroups mapping,
// falling back to DefaultOU or the source dept. Returns the OU list to embed
// in the certificate subject.
func (c *IdentitySourceConfig) CertificateOUS(id *UserIdentity) []string {
	if id == nil {
		return nil
	}
	var ous []string
	if len(c.OUFromGroups) > 0 {
		for _, g := range id.Groups {
			if ou, ok := matchOUGroup(c.OUFromGroups, g); ok {
				ous = append(ous, ou)
			}
		}
		if len(ous) > 0 {
			return dedupStrings(ous)
		}
	}
	if c.DefaultOU != "" {
		return []string{c.DefaultOU}
	}
	if id.Dept != "" {
		return []string{id.Dept}
	}
	return nil
}

// matchOUGroup matches a source group against OUFromGroups rules.
// A group matches a rule by exact case-insensitive equality, or when the
// group is an LDAP DN whose CN/RDN portion equals the rule key.
func matchOUGroup(rules map[string]string, group string) (string, bool) {
	for k, ou := range rules {
		if strings.EqualFold(k, group) {
			return ou, true
		}
		// LDAP DN: "CN=医生,OU=Groups,DC=..." → compare against "医生" and the
		// RDN "CN=医生".
		if strings.Contains(group, "=") {
			for _, rdn := range strings.Split(group, ",") {
				if strings.EqualFold(strings.TrimSpace(rdn), k) {
					return ou, true
				}
			}
		}
	}
	return "", false
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

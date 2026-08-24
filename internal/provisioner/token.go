package provisioner

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// TokenName is the built-in token provisioner name.
const TokenName = "token"

// TokenProvisioner authenticates via X-Auth-Token or Authorization header.
// It delegates token validation to TokenResolver (set by Server).
type TokenProvisioner struct{}

func NewTokenProvisioner() *TokenProvisioner { return &TokenProvisioner{} }

func (p *TokenProvisioner) Name() string { return TokenName }
func (p *TokenProvisioner) Type() string { return "token" }

func (p *TokenProvisioner) Authenticate(r *http.Request) (*AuthResult, error) {
	token := extractToken(r)
	if token == "" {
		return nil, nil
	}

	resolver := getTokenResolver()
	if resolver == nil {
		return nil, nil
	}

	result, err := resolver(token)
	if err != nil {
		// M23 fix: do not silently swallow resolver errors — surface them so
		// brute-force attempts are observable in logs.
		return nil, err
	}
	return result, nil
}

func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return token
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if len(auth) >= 6 && strings.EqualFold(auth[:6], "Basic ") {
		// M23 fix: return only the base64 payload (no double prefix, no "Basic "
		// scheme token), and accept any casing of the scheme per RFC 7235.
		return "basic:" + strings.TrimSpace(auth[6:])
	}
	return ""
}

// TokenResolver resolves a token/credential to an AuthResult.
// Set by the Server.
var TokenResolver func(token string) (*AuthResult, error)

// tokenResolverAtomic holds the resolver in an atomic.Value to avoid the M23
// data race: cmd/pki writes the global on reload while handlers read it.
var tokenResolverAtomic atomic.Value // holds func(string) (*AuthResult, error)

// getTokenResolver returns the current resolver, preferring the atomic copy.
func getTokenResolver() func(string) (*AuthResult, error) {
	if v := tokenResolverAtomic.Load(); v != nil {
		return v.(func(string) (*AuthResult, error))
	}
	return TokenResolver
}

// SetTokenResolver atomically installs the resolver (M23 fix: hot-reload writes
// no longer race with concurrent handler reads of the plain global).
func SetTokenResolver(fn func(string) (*AuthResult, error)) {
	tokenResolverAtomic.Store(fn)
	TokenResolver = fn
}

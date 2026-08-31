// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// AICJWTName is the registry name of the AIC-JWT bearer provisioner.
const AICJWTName = "aic-jwt"

// AICJWTProvisioner authenticates requests via an AIC-JWT bearer token
// (draft-ietf-oauth-aic) issued by a local CA. Validation is delegated to
// the AICJWTResolver installed by the server, which anchors verification
// to the same trust root as X.509 (issuer keys are the configured CAs).
type AICJWTProvisioner struct{}

// NewAICJWTProvisioner returns a stateless AIC-JWT provisioner.
func NewAICJWTProvisioner() *AICJWTProvisioner { return &AICJWTProvisioner{} }

// Name returns the provisioner name ("aic-jwt").
func (p *AICJWTProvisioner) Name() string { return AICJWTName }

// Type returns the provisioner type.
func (p *AICJWTProvisioner) Type() string { return "aic-jwt" }

// AICJWTResolver resolves a bearer token to an AuthResult. It receives the
// request so strict dual-carrier binding (mTLS certificate vs cnf.jkt) can
// be enforced. Set by the Server.
var AICJWTResolver func(token string, r *http.Request) (*AuthResult, error)

// aicjwtResolverAtomic holds the resolver in an atomic.Value to avoid the M23
// data race: cmd/pki writes the global on reload while handlers read it.
var aicjwtResolverAtomic atomic.Value // holds func(string, *http.Request) (*AuthResult, error)

// getAICJWTResolver returns the current resolver, preferring the atomic copy.
func getAICJWTResolver() func(string, *http.Request) (*AuthResult, error) {
	if v := aicjwtResolverAtomic.Load(); v != nil {
		return v.(func(string, *http.Request) (*AuthResult, error))
	}
	return AICJWTResolver
}

// SetAICJWTResolver atomically installs the resolver (M23 fix: hot-reload
// writes no longer race with concurrent handler reads of the plain global).
func SetAICJWTResolver(fn func(string, *http.Request) (*AuthResult, error)) {
	aicjwtResolverAtomic.Store(fn)
	AICJWTResolver = fn
}

// Authenticate checks for a Bearer AIC-JWT and delegates to the resolver.
// Non-Bearer requests and requests without a resolver are left for other
// provisioners (nil, nil).
func (p *AICJWTProvisioner) Authenticate(r *http.Request) (*AuthResult, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" || !strings.Contains(token, ".") {
		return nil, nil
	}
	resolver := getAICJWTResolver()
	if resolver == nil {
		return nil, nil
	}
	return resolver(token, r)
}
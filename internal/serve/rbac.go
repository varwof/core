// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/engine/db"
)

type ctxKey string

const userCtxKey ctxKey = "auth_user"

// AuthUser represents an authenticated user.
type AuthUser struct {
	Username    string
	Role        string
	Permissions []Permission
	CAScopes    []string
	// CertIdentity records the client certificate identity bound to the current session.
	// nil means this authentication did not carry a certificate (e.g. token/Basic login),
	// and only the username can serve as an identity anchor.
	CertIdentity *provisioner.CertIdentity
}

// certIdentityFromCert extracts an identity snapshot from a client certificate
// (see provisioner.NewCertIdentityFromCert).
func certIdentityFromCert(cert *x509.Certificate) *provisioner.CertIdentity {
	return provisioner.NewCertIdentityFromCert(cert)
}

func (u *AuthUser) HasPerm(perm Permission) bool {
	for _, p := range u.Permissions {
		if auth.MatchCapability(string(perm), string(p)) {
			return true
		}
	}
	return false
}

// operatorCertScopes returns the effective CA scope for an account with a
// linked management certificate (operator-cert proxy). When
// user.OperatorCertPEM is set, the certificate's scope (SAN URI + OID) is the
// cryptographic source of truth: it must be a valid, unexpired, non-revoked
// management certificate issued by this PKI, otherwise authentication fails
// closed (the certificate lifecycle directly bounds the account's access).
// Without a linked certificate it returns the account's ca_scopes fallback.
func (s *Server) operatorCertScopes(user *db.RBACUser, fallback []string) ([]string, error) {
	if user.OperatorCertPEM == "" {
		return fallback, nil
	}
	return s.validateOperatorCertPEM([]byte(user.OperatorCertPEM))
}

// validateOperatorCertPEM fully validates a management certificate used to
// proxy an account's CA scope. It must be a valid, unexpired, non-revoked
// management certificate (DigitalSignature KU) whose OU maps to a real role,
// issued by this PKI. Returns the certificate's effective CA scope.
func (s *Server) validateOperatorCertPEM(pemBytes []byte) ([]string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("operator cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("operator cert: parse: %w", err)
	}
	// Must be a management certificate (entity cert, DigitalSignature KU)
	// whose OU maps to a real role.
	if err := ca.ValidateAdminCert(cert); err != nil {
		return nil, fmt.Errorf("operator cert: %w", err)
	}
	if ouToRole(cert.Subject.OrganizationalUnit) == "" {
		return nil, fmt.Errorf("operator cert OU %v maps to no role", cert.Subject.OrganizationalUnit)
	}
	// Must be inside its validity window.
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("operator cert expired (not_after %s)",
			cert.NotAfter.Format(time.RFC3339))
	}
	// Must be issued by this PKI and not revoked/expired.
	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	status, err := s.getCertStatusByIssuer(cert.Issuer.String(), serial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("operator cert not issued by this PKI (issuer=%s serial=%s)",
				cert.Issuer.CommonName, serial)
		}
		return nil, fmt.Errorf("operator cert: resolve status: %w", err)
	}
	if status.Status != "V" {
		return nil, fmt.Errorf("operator cert status %q (not valid)", status.Status)
	}
	return parseCAScopes(ca.ExtractAdminScope(cert)), nil
}

// requirePerm checks a specific permission, replacing the old requireRole + roleWeight.
// requirePermInline authenticates the request and checks the permission,
// writing the standard auth/forbidden error responses when it fails. It
// returns true when the request is authorized so callers can bail out early.
// Used by handlers that are not wrapped in requirePerm (e.g. AIC admin
// endpoints) so a future route wiring cannot expose them unauthenticated.
func (s *Server) requirePermInline(w http.ResponseWriter, r *http.Request, perm Permission) bool {
	if isWriteMethod(r.Method) && !isSameOrigin(r) {
		s.apiErr(w, r, http.StatusForbidden, "api.forbidden_cors", "")
		return false
	}
	user, err := s.authenticate(r)
	if err != nil || user == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="pki"`)
		s.apiErr(w, r, http.StatusUnauthorized, "api.unauthorized", "")
		return false
	}
	if !user.HasPerm(perm) {
		s.apiErr(w, r, http.StatusForbidden, "api.forbidden", "")
		return false
	}
	return true
}

func (s *Server) requirePerm(perm Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isWriteMethod(r.Method) && !isSameOrigin(r) {
			s.apiErr(w, r, http.StatusForbidden, "api.forbidden_cors", "")
			return
		}
		user, err := s.authenticate(r)
		if err != nil || user == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="pki"`)
			s.apiErr(w, r, http.StatusUnauthorized, "api.unauthorized", "")
			return
		}
		if !user.HasPerm(perm) {
			s.apiErr(w, r, http.StatusForbidden, "api.forbidden", "")
			return
		}
		// Enterprise mode: CA scope check
		if s.getConfig().RBAC.PermissionMode == "enterprise" {
			if !checkCAScope(user, r, perm, s.getConfig()) {
				s.apiErr(w, r, http.StatusForbidden, "api.ca_scope_denied", "permission denied for this CA")
				return
			}
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

func isWriteMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodDelete || method == http.MethodPatch
}

func isSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	// A "null" Origin comes from sandboxed contexts (opaque origins) and
	// must never be trusted as same-origin.
	if origin == "null" {
		return false
	}
	// Exact match on scheme + host. Parse instead of string prefix so that
	// https://host.evil.com cannot masquerade as https://host.
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if !strings.EqualFold(u.Scheme, scheme) || u.Host != host {
		return false
	}
	// url.Parse keeps the scheme; the Host comparison above is exact
	// (including port), so a trailing path in Referer is irrelevant.
	return true
}

func (s *Server) authenticate(r *http.Request) (*AuthUser, error) {
	// Delegate to provisioner registry if available.
	if s.provs != nil {
		result, name, _ := s.provs.Authenticate(r)
		if result != nil {
			auditProv := name
			if auditProv == "" {
				auditProv = "provisioner"
			}
			_ = auditProv // available for audit logging
			return s.authResultToUser(result)
		}
	}

	// Fallback: traditional hardcoded chain (kept for backward compat during migration)
	return s.authenticateLegacy(r)
}

func (s *Server) authenticateLegacy(r *http.Request) (*AuthUser, error) {
	// 1. mTLS (highest priority)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return s.authFromCert(r.TLS.PeerCertificates[0], r)
	}

	// 2. X-Auth-Token header
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return s.authByToken(token)
	}

	// 2b. HttpOnly session cookie (web console)
	if cookie, err := r.Cookie("pki_token"); err == nil && cookie.Value != "" {
		return s.authByToken(cookie.Value)
	}

	// 3. Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}
	if strings.HasPrefix(auth, "Bearer ") {
		return s.authByToken(strings.TrimPrefix(auth, "Bearer "))
	}
	if strings.HasPrefix(auth, "Basic ") {
		return s.authByBasic(r)
	}
	return nil, nil
}

// authResultToUser converts a provisioner AuthResult into an AuthUser,
// deriving the effective CA scope from the account's linked operator
// certificate (cryptographic binding) or its ca_scopes fallback. When the
// account HAS a bound operator certificate but that certificate fails
// validation (expired / revoked / foreign / malformed), authentication fails
// closed: the operator-cert proxy must never silently degrade a scoped
// account into an unscoped one (which would widen access in simple mode).
// authScopesCacheTTL bounds how long a derived CA-scope list stays cached.
// Every authenticated request previously re-read the user + operator-cert
// scopes from the DB (GetUserByUsername + operatorCertScopes). Under high
// concurrency these queries contend on SQLite's global page-cache mutex and
// collapse throughput (lock convoy at w32+). A short TTL keeps the stale
// account-state window (e.g. a revoked operator cert) small. Only the
// DB-derived scope list is cached; per-request permissions from the
// provisioner stay fresh.
var authScopesCacheTTL = 30 * time.Second

// authScopesCacheMaxEntries bounds the cache to avoid unbounded growth from
// many distinct usernames.
const authScopesCacheMaxEntries = 4096

var (
	authScopesMu    sync.Mutex
	authScopesCache map[string]authScopesEntry
)

type authScopesEntry struct {
	scopes []string
	exp    time.Time
}

func authScopesCached(username string) ([]string, bool) {
	authScopesMu.Lock()
	defer authScopesMu.Unlock()
	e, ok := authScopesCache[username]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.exp) {
		delete(authScopesCache, username)
		return nil, false
	}
	return e.scopes, true
}

func rememberAuthScopes(username string, scopes []string) {
	authScopesMu.Lock()
	defer authScopesMu.Unlock()
	if authScopesCache == nil {
		authScopesCache = make(map[string]authScopesEntry)
	}
	if len(authScopesCache) >= authScopesCacheMaxEntries {
		now := time.Now()
		for k, e := range authScopesCache {
			if now.After(e.exp) {
				delete(authScopesCache, k)
			}
		}
		if len(authScopesCache) >= authScopesCacheMaxEntries {
			return
		}
	}
	authScopesCache[username] = authScopesEntry{scopes: scopes, exp: time.Now().Add(authScopesCacheTTL)}
}

func (s *Server) authResultToUser(r *provisioner.AuthResult) (*AuthUser, error) {
	perms := make([]Permission, len(r.Permissions))
	for i, p := range r.Permissions {
		perms[i] = Permission(p)
	}
	au := &AuthUser{
		Username:     r.Username,
		Role:         r.Role,
		Permissions:  perms,
		CertIdentity: r.CertIdentity,
	}
	if r.Username == "" {
		return au, nil
	}
	if scopes, ok := authScopesCached(r.Username); ok {
		au.CAScopes = scopes
		return au, nil
	}
	user, err := s.getUserByUsername(r.Username)
	if err != nil {
		return au, nil
	}
	var caScopes []string
	if user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	scopes, err := s.operatorCertScopes(user, caScopes)
	if err != nil {
		return nil, err
	}
	au.CAScopes = scopes
	rememberAuthScopes(r.Username, scopes)
	return au, nil
}

// agentSessionAllowed enforces server-side limits on delegated-agent
// sessions. The X-Agent-TTL header must be present, parseable, in the
// future, and within Serve.AgentSessionMaxTTL of now. A missing TTL or a
// TTL window longer than the configured cap is rejected (fail-closed); a cap
// of zero rejects delegated sessions entirely.
func (s *Server) agentSessionAllowed(r *http.Request) bool {
	maxTTL := s.agentSessionMaxTTL()
	if maxTTL <= 0 {
		return false
	}
	ttlStr := r.Header.Get("X-Agent-TTL")
	if ttlStr == "" {
		return false
	}
	ttl, err := time.Parse(time.RFC3339, ttlStr)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.After(ttl) {
		return false
	}
	if ttl.Sub(now) > maxTTL {
		return false
	}
	return true
}

func (s *Server) agentSessionMaxTTL() time.Duration {
	cfg := s.getConfig()
	if cfg == nil || cfg.Serve.AgentSessionMaxTTL == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(cfg.Serve.AgentSessionMaxTTL)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// trustedGatewayOUs returns the configured OUs whose certs may assert
// delegated identities (X-Client-Cert-DER passthrough; legacy X-Agent-User
// username delegation also gated on this). An empty list rejects all
// gateway-asserted delegation entirely (fail-closed).
func (s *Server) trustedGatewayOUs() []string {
	cfg := s.getConfig()
	if cfg == nil {
		return nil
	}
	return cfg.Serve.TrustedGatewayOUs
}

// isTrustedGateway reports whether the peer cert carries an OU listed in
// serve.trusted_gateway_ous, i.e. it is a gateway service certificate trusted
// to assert delegated identities.
func (s *Server) isTrustedGateway(cert *x509.Certificate) bool {
	for _, want := range s.trustedGatewayOUs() {
		if hasOU(cert.Subject.OrganizationalUnit, want) {
			return true
		}
	}
	return false
}

// gatewayDelegatedUser resolves the identity asserted by a trusted gateway via
// the X-Agent-User username header (B1). Usernames are not cryptographically
// bound to a certificate, so this path carries no CertIdentity and is a
// degraded fallback: prefer B2 (X-Client-Cert-DER certificate passthrough)
// which lets the gateway forward the actual client certificate. The
// X-Agent-TTL must be present, in the future, and within the configured window
// (fail-closed); the principal is then looked up in the DB and its own
// role/permissions/CA scopes are used (least privilege, not the gateway's).
func (s *Server) gatewayDelegatedUser(r *http.Request) (*AuthUser, error) {
	if !s.agentSessionAllowed(r) {
		return nil, nil
	}
	username := r.Header.Get("X-Agent-User")
	if username == "" {
		return nil, nil
	}
	user, err := s.getUserByUsername(username)
	if err != nil || !user.Enabled {
		return nil, nil
	}
	var caScopes []string
	if user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	caScopes, err = s.operatorCertScopes(user, caScopes)
	if err != nil {
		return nil, err
	}
	return &AuthUser{
		Username:    user.Username,
		Role:        user.Role,
		Permissions: getRolePerms(user.Role),
		CAScopes:    caScopes,
	}, nil
}

// gatewayForwardedCertUser (B2) resolves the identity of a client certificate
// forwarded by a trusted gateway via the X-Client-Cert-DER header (base64 DER
// of the verified peer cert). The certificate is independently resolved
// against the local PKI database by (issuer DN, serial): it must exist, be
// valid (not revoked), and map to a real enabled user. This keeps identity
// cryptographically bound to a certificate and auditable, unlike the legacy
// X-Agent-User username path (B1). The X-Agent-TTL must still be present,
// in the future, and within the configured window (fail-closed).
func (s *Server) gatewayForwardedCertUser(r *http.Request) (*AuthUser, error) {
	if !s.agentSessionAllowed(r) {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Client-Cert-DER"))
	if err != nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil
	}
	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	status, principalUid, err := s.getDB().GetPrincipalByCert(cert.Issuer.String(), serial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // certificate not issued by this PKI
		}
		return nil, fmt.Errorf("resolve forwarded cert: %w", err)
	}
	if status != "V" {
		return nil, nil // revoked, expired, or otherwise not valid
	}
	username := principalUid
	if username == "" {
		username = cert.Subject.CommonName
	}
	if username == "" {
		return nil, nil
	}
	user, err := s.getUserByUsername(username)
	if err != nil || !user.Enabled {
		return nil, nil
	}
	var caScopes []string
	if user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	caScopes, err = s.operatorCertScopes(user, caScopes)
	if err != nil {
		return nil, err
	}
	return &AuthUser{
		Username:     user.Username,
		Role:         user.Role,
		Permissions:  getRolePerms(user.Role),
		CAScopes:     caScopes,
		CertIdentity: certIdentityFromCert(cert),
	}, nil
}

func (s *Server) authByToken(token string) (*AuthUser, error) {
	info, err := s.getToken(token)
	if err != nil {
		return nil, nil
	}
	// Load user CA scopes from database
	user, err := s.getUserByUsername(info.Username)
	var caScopes []string
	if err == nil && user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	if err == nil {
		caScopes, err = s.operatorCertScopes(user, caScopes)
		if err != nil {
			return nil, err
		}
	}
	// Cert-first: non-certificate authentication (token/basic/cookie) is always assigned
	// the "operator" role, ignoring DB user role permission claims — permissions come
	// only from the certificate's PA grants.
	return &AuthUser{
		Username:    info.Username,
		Role:        "operator",
		Permissions: getRolePerms("operator"),
		CAScopes:    caScopes,
	}, nil
}

func (s *Server) authByBasic(r *http.Request) (*AuthUser, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	if s.loginThrottled(username) {
		return nil, nil
	}
	user, err := s.getUserByUsername(username)
	if err != nil || !user.Enabled {
		return nil, nil
	}

	// Argon2id verification is intentionally expensive (~64MB, tens of ms per
	// call). Cache only the verification outcome keyed on the stored credential
	// so a password change invalidates the entry automatically; account state
	// below is re-loaded from the DB on every request.
	cacheKey := BasicAuthCacheKey(username, user.Salt, user.PasswordHash)
	if !BasicAuthVerified(cacheKey) {
		hash := db.HashPassword(password, user.Salt)
		if subtle.ConstantTimeCompare([]byte(hash), []byte(user.PasswordHash)) != 1 {
			s.recordLoginFailure(username)
			return nil, nil
		}
		RememberBasicAuth(cacheKey)
	}
	s.resetLoginThrottle(username)

	var caScopes []string
	if user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	caScopes, err = s.operatorCertScopes(user, caScopes)
	if err != nil {
		return nil, err
	}
	// Cert-first: non-certificate authentication (token/basic/cookie) is always assigned
	// the "operator" role, ignoring DB user role permission claims — permissions come
	// only from the certificate's PA grants.
	return &AuthUser{
		Username:    user.Username,
		Role:        "operator",
		Permissions: getRolePerms("operator"),
		CAScopes:    caScopes,
	}, nil
}

// basicAuthCacheTTL bounds how long a successful Argon2id password verification
// stays cached. A short TTL keeps the window for stale account state (e.g. a
// role change or password reset) small while eliminating the ~tens-of-ms hash
// cost from every request. Only the verification OUTCOME is cached, keyed on
// the stored credential (username+salt+hash); account state is re-read from
// the DB on every request by the callers.
var basicAuthCacheTTL = 5 * time.Minute

// basicAuthCacheMaxEntries bounds the cache to avoid unbounded growth from
// many distinct (user, salt, hash) combinations.
const basicAuthCacheMaxEntries = 4096

var (
	basicAuthMu    sync.Mutex
	basicAuthCache map[string]time.Time
)

// BasicAuthCacheKey builds the cache key for a credential verification.
// Embedding the stored password hash means any password change invalidates the
// entry automatically. Exported so the provisioner path (cmd/pki TokenResolver)
// shares the same cache as the legacy authByBasic fallback.
func BasicAuthCacheKey(username, salt, passwordHash string) string {
	return username + "\x00" + salt + "\x00" + passwordHash
}

// BasicAuthVerified reports whether the credential encoded in cacheKey was
// successfully verified within basicAuthCacheTTL.
func BasicAuthVerified(cacheKey string) bool {
	basicAuthMu.Lock()
	defer basicAuthMu.Unlock()
	exp, ok := basicAuthCache[cacheKey]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(basicAuthCache, cacheKey)
		return false
	}
	return true
}

// RememberBasicAuth records that the credential encoded in cacheKey passed
// Argon2id verification. Expired entries are dropped opportunistically when the
// cache reaches basicAuthCacheMaxEntries; live entries are never evicted early.
func RememberBasicAuth(cacheKey string) {
	basicAuthMu.Lock()
	defer basicAuthMu.Unlock()
	if basicAuthCache == nil {
		basicAuthCache = make(map[string]time.Time)
	}
	if len(basicAuthCache) >= basicAuthCacheMaxEntries {
		now := time.Now()
		for k, exp := range basicAuthCache {
			if now.After(exp) {
				delete(basicAuthCache, k)
			}
		}
		if len(basicAuthCache) >= basicAuthCacheMaxEntries {
			return
		}
	}
	basicAuthCache[cacheKey] = time.Now().Add(basicAuthCacheTTL)
}

// authFromCert resolves identity from an mTLS certificate.
// Prefers AIC extension (permissions = PA grants ∩ AIC capabilities), falls back to
// m-* management certificates (permissions = PA grants, no PA → fail-closed).
func (s *Server) authFromCert(cert *x509.Certificate, r *http.Request) (*AuthUser, error) {
	aic, err := ca.ParseAIC(cert)
	if err == nil && aic != nil {
		pa, paErr := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
		if paErr != nil {
			return nil, nil
		}
		user, err := s.authFromAIC(aic, pa)
		if err != nil || user == nil {
			return user, err
		}
		user.CertIdentity = certIdentityFromCert(cert)
		return user, nil
	}

	// Trusted-gateway delegation. Prefer B2 (X-Client-Cert-DER certificate
	// passthrough): the forwarded certificate is resolved against the DB for
	// its principal, revocation, and permissions. B1 (X-Agent-User username)
	// is a degraded fallback: it carries no certificate, so CertIdentity is
	// nil and only the username anchors identity.
	if s.isTrustedGateway(cert) && r.Header.Get("X-Client-Cert-DER") != "" {
		return s.gatewayForwardedCertUser(r)
	}
	if s.isTrustedGateway(cert) && r.Header.Get("X-Agent-User") != "" {
		return s.gatewayDelegatedUser(r)
	}

	role := ouToRole(cert.Subject.OrganizationalUnit)
	if role == "" {
		return nil, nil
	}
	// Delegated-Agent certificates no longer trust client-supplied identity
	// (X-Agent-User): the operator must come from the certificate itself,
	// either the AIC PrincipalUid (handled above) or the certificate CN.
	username := cert.Subject.CommonName
	if hasOU(cert.Subject.OrganizationalUnit, "Delegated-Agent") {
		// The delegated session must carry a server-verifiable expiry that is
		// both in the future and within the configured window. Missing,
		// unparseable, expired, or over-long TTLs are rejected (fail-closed).
		if !s.agentSessionAllowed(r) {
			return nil, nil
		}
	}

	// Cert-first authorization: the certificate's PrincipalAuthorization
	// grants are the authoritative permission source. Without a PA extension
	// the certificate is rejected (fail-closed) — it cannot silently inherit
	// the DB role's full permissions.
	pa, err := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
	if err != nil {
		return nil, nil
	}
	if pa == nil || len(pa.Grants) == 0 {
		return nil, nil
	}
	var paPerms []Permission
	for _, g := range pa.Grants {
		paPerms = append(paPerms, Permission(g.FullID()))
	}

	// Extract CA scopes from the admin certificate: SAN URIs
	// (urn:pki:ca:<scope>) plus the OID 1.3.6.1.4.1.66257.1.5.1 scope
	// extension, merged and de-duplicated by ExtractAdminScope.
	caScopes := parseCAScopes(ca.ExtractAdminScope(cert))

	return &AuthUser{
		Username:     username,
		Role:         role,
		Permissions:  paPerms,
		CAScopes:     caScopes,
		CertIdentity: certIdentityFromCert(cert),
	}, nil
}

// authFromAIC derives permissions from the AIC extension.
// Permissions = PA grants ∩ AIC capabilities (Cert-first secure intersection mode).
// PrincipalAuthorization is the authoritative permission source; AIC capabilities are
// the agent's declared capabilities — anything outside the intersection is rejected.
// No PA extension → fail-closed rejection (permissions come only from the certificate).
func (s *Server) authFromAIC(aic *ca.AIC, pa *ca.PrincipalAuthorization) (*AuthUser, error) {
	user, err := s.getUserByUsername(aic.PrincipalUid.String())
	if err != nil || !user.Enabled {
		return nil, nil
	}

	var caScopes []string
	if user.CAScopes != "" {
		caScopes = parseCAScopes(user.CAScopes)
	}
	caScopes, err = s.operatorCertScopes(user, caScopes)
	if err != nil {
		return nil, err
	}

	username := aic.PrincipalUid.String()
	roleName := user.Role + "(agent)"

	// Cert-first fail-closed: PA extension missing or empty → reject. Permissions come only
	// from the certificate, never falling back to DB user roles (otherwise the certificate
	// becomes merely an identity tag while permissions are still controlled by the DB).
	if pa == nil || len(pa.Grants) == 0 {
		return nil, nil
	}

	// Secure intersection fail-closed: AIC declares no capabilities → grant empty permissions.
	// Must never fall back to inheriting all PA permissions — otherwise an AIC with empty
	// capabilities becomes a full-power proxy for the bound principal (unlimited damage
	// surface when an AI agent goes rogue).
	if len(aic.Capabilities) == 0 {
		return &AuthUser{
			Username:    username,
			Role:        roleName,
			Permissions: nil,
			CAScopes:    caScopes,
		}, nil
	}

	// PA grants (authoritative) serve as matching templates, AIC capabilities (agent declarations)
	// as candidates. Result = AIC capabilities covered by PA grants (full ID intersection,
	// wildcard supported). Matching is uniformly based on FullID (schemeId:capabilityId),
	// consistent with the types specification.
	var paIds []string
	for _, g := range pa.Grants {
		paIds = append(paIds, g.FullID())
	}
	var finalPerms []Permission
	for _, cap := range aic.Capabilities {
		if cap.CapabilityId == "" {
			continue
		}
		fullID := cap.FullID()
		if grantCovered(fullID, paIds) {
			finalPerms = append(finalPerms, Permission(fullID))
		}
	}
	return &AuthUser{
		Username:    username,
		Role:        roleName,
		Permissions: finalPerms,
		CAScopes:    caScopes,
	}, nil
}

// grantCovered reports whether capabilityID is covered by any grant template in allowed (wildcard supported).
func grantCovered(capID string, allowed []string) bool {
	for _, a := range allowed {
		if auth.MatchCapability(capID, a) {
			return true
		}
	}
	return false
}

// getRolePerms returns role permissions, preferring Policy reads, falling back to hardcoded RolePermissions.
func getRolePerms(role string) []Permission {
	if p := auth.GetPolicy(); p != nil {
		grants := p.RoleGrants(role)
		perms := make([]Permission, len(grants))
		for i, g := range grants {
			perms[i] = Permission(g)
		}
		return perms
	}
	return RolePermissions[role]
}

// parseCAScopes parses CA scopes from a comma-separated string.
func parseCAScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var scopes []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			scopes = append(scopes, p)
		}
	}
	return scopes
}

func ouToRole(ous []string) string {
	if p := auth.GetPolicy(); p != nil {
		for _, ou := range ous {
			if role := p.RoleByOU(ou); role != "" {
				return role
			}
		}
		return ""
	}
	for _, ou := range ous {
		switch ou {
		case "SuperAdmin":
			return "superadmin"
		case "admin", "Admin":
			return "admin"
		case "Operator", "operator":
			return "operator"
		case "Auditor", "auditor":
			return "auditor"
		case "Revoker", "revoker":
			return "revoker"
		case "ReadOnly", "readonly":
			return "readonly"
		case "Console", "console":
			return "console"
		case "AutoRenew", "auto-renew":
			return "auto-renew"
		case "Reporter", "reporter":
			return "reporter"
		}
	}
	return ""
}

func hasOU(ous []string, target string) bool {
	for _, ou := range ous {
		if ou == target {
			return true
		}
	}
	return false
}

// checkCAScope checks whether a user has permission to operate on a specific CA in enterprise mode.
// This function is not called in simple mode.
//
// Rules:
//  1. Framework operations (ca:create / ca:delete) → only superadmin has permission, no scope check
//  2. Read-only roles (auditor / readonly / reporter) → ALLOW
//  3. Fixed-scope roles (revoker / auto-renew, scope=*) → ALLOW
//  4. No scope defined → DENY (enterprise default secure)
//  5. scope contains * → ALLOW
//  6. Extract CA name from request → exact string match against scope list
//  7. Config file fallback match
//  8. No match → DENY
func checkCAScope(user *AuthUser, r *http.Request, perm Permission, cfg *internal.Config) bool {
	permStr := string(perm)

	// 1. Framework operation exemption: ca:create / ca:delete — only superadmin reaches here
	//    (requirePerm already checked permissions; only superadmin has ca:create/delete)
	if permStr == "ca:create" || permStr == "ca:delete" {
		return true
	}

	// 2. Read-only roles: auditor / readonly / reporter → allow all read operations
	switch user.Role {
	case "auditor", "readonly", "reporter":
		return true
	}

	// 3. Fixed-scope roles: revoker / auto-renew (policy defines scope=*)
	if p := auth.GetPolicy(); p != nil {
		if scopes := p.RoleScope(user.Role); len(scopes) == 1 && scopes[0] == "*" {
			return true
		}
	}

	// 4. No scope defined → preserve original mode semantics: simple mode allows
	//    (lightweight deployments never configured scopes, backward compatible);
	//    enterprise mode denies (default secure). Once a scope is bound (account
	//    ca_scopes or operator-cert), it is enforced in all permission_mode settings
	//    (steps 5-8).
	if len(user.CAScopes) == 0 {
		if cfg == nil {
			return false
		}
		return cfg.RBAC.PermissionMode == "simple"
	}

	// 5. scope contains * → allow
	for _, scope := range user.CAScopes {
		if scope == "*" {
			return true
		}
	}

	// 6. Extract CA name from request
	caName := extractCANameFromRequest(r)
	if caName == "" {
		// Cannot determine CA → reject
		return false
	}

	// 7. Exact string match against scope list
	for _, scope := range user.CAScopes {
		if scope == caName {
			return true
		}
		// Compare comma-separated multi-scopes item by item
		for _, s := range strings.Split(scope, ",") {
			if strings.TrimSpace(s) == caName {
				return true
			}
		}
	}

	// 8. Config file fallback
	if cfg.RBAC.CAScopes != nil {
		if roleScopes, ok := cfg.RBAC.CAScopes[user.Role]; ok {
			for _, scope := range roleScopes {
				if scope == caName || scope == "*" {
					return true
				}
			}
		}
	}
	return false
}

// extractCANameFromRequest extracts the CA name from the request path, query parameters, or POST body.
func extractCANameFromRequest(r *http.Request) string {
	// Try path parameter
	caName := extractCANameFromPath(r.URL.Path)
	if caName != "" {
		return caName
	}
	// Try query parameter
	caName = r.URL.Query().Get("ca")
	if caName != "" {
		return caName
	}
	// Try POST body (JSON) — peek only, do not consume; body is read by subsequent handlers
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if r.Body == nil {
			return ""
		}
		// Read only the first 64KB to prevent abuse
		buf, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			return ""
		}
		// Restore body for subsequent handlers
		r.Body = io.NopCloser(bytes.NewReader(buf))
		var m struct {
			CA string `json:"ca"`
		}
		if json.Unmarshal(buf, &m) != nil {
			return ""
		}
		return strings.TrimSpace(m.CA)
	}
	return ""
}

// extractCANameFromPath extracts the CA name from the API path.
func extractCANameFromPath(path string) string {
	// POST /api/v1/cert/<ca>/<serial>/revoke
	// POST /api/v1/crl/<ca>/generate
	// GET  /api/v1/certs?ca=<ca>
	// POST /api/v1/certs (body contains ca field — not extractable from path)
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		if p == "cert" && i+1 < len(parts) {
			return parts[i+1]
		}
		if p == "crl" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// scopeMatch checks whether scope matches caName (exact string match).
func scopeMatch(scope, caName string) bool {
	return scope == "*" || scope == caName
}

// extractPolicyCAFromChain extracts the policy sub-CA name from the mTLS client certificate chain.
// The policy sub-CA is the first intermediate CA under the Root CA (self-signed).
func extractPolicyCAFromChain(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return ""
	}
	// VerifiedChains[0] = [leaf, intermediate..., root]
	chain := r.TLS.VerifiedChains[0]
	if len(chain) < 3 {
		return "" // Not enough layers (leaf + subCA + root)
	}
	// root is the last one, policy sub-CA is the second-to-last
	policyCA := chain[len(chain)-2]
	// Return the policy sub-CA's CN as the scope identifier
	return policyCA.Subject.CommonName
}

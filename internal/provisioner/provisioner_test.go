// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal/ca"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatal("expected empty registry")
	}

	mtls := NewMTLSProvisioner()
	if err := r.Register(mtls); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatal("expected 1 provisioner")
	}

	found, err := r.Find(MTLSName)
	if err != nil {
		t.Fatal(err)
	}
	if found.Name() != MTLSName {
		t.Fatal("wrong name")
	}

	// Duplicate register should fail
	if err := r.Register(mtls); err == nil {
		t.Fatal("expected duplicate error")
	}

	// Find nonexistent
	if _, err := r.Find("nonexistent"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestMTLSProvisioner_NoCert(t *testing.T) {
	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil result for no cert")
	}
}

func TestMTLSProvisioner_OUFallback(t *testing.T) {
	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "testuser",
			OrganizationalUnit: []string{"admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		Extensions:   []pkix.Extension{testPAExt(t, "cert:list", "cert:issue")},
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Username != "testuser" {
		t.Fatalf("expected testuser, got %s", result.Username)
	}
}

func TestMTLSProvisioner_OUFallbackNoPA(t *testing.T) {
	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "testuser",
			OrganizationalUnit: []string{"admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	// Cert-first fail-closed: OU matches a role but no PA extension → reject.
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected nil result for OU cert without PA, got %+v", result)
	}
}

func TestMTLSProvisioner_OUFallbackPermissions(t *testing.T) {
	prevPolicy := auth.GetPolicy()
	prevResolver := UserResolver
	defer func() {
		auth.SetPolicy(prevPolicy)
		UserResolver = prevResolver
	}()
	// No policy (ouToRole uses built-in mapping), no UserResolver.
	auth.SetPolicy(nil)
	UserResolver = nil

	p := NewMTLSProvisioner()

	// managementPAGrants encoding: SchemeId + CapabilityId(action) stored separately.
	// Full permission = "scheme:action", used by HasPerm/MatchCapability matching.
	grants := []ca.Capability{
		{SchemeId: "ca", CapabilityId: "list"},
		{SchemeId: "cert", CapabilityId: "issue"},
	}
	paExt, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "admin-user",
			OrganizationalUnit: []string{"admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		Extensions:   []pkix.Extension{paExt},
	}
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	want := []string{"ca:list", "cert:issue"}
	if len(result.Permissions) != len(want) {
		t.Fatalf("expected %d perms, got %v", len(want), result.Permissions)
	}
	for i, w := range want {
		if result.Permissions[i] != w {
			t.Fatalf("perm[%d] = %q, want %q (all=%v)", i, result.Permissions[i], w, result.Permissions)
		}
	}
}

func TestGrantID(t *testing.T) {
	cases := []struct {
		g    ca.Capability
		want string
	}{
		{ca.Capability{SchemeId: "ca", CapabilityId: "list"}, "ca:list"},
		{ca.Capability{SchemeId: "", CapabilityId: "plain"}, "plain"},
		{ca.Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}, "varwof/demo-mysql-v1:SELECT:*"},
	}
	for _, c := range cases {
		if got := grantID(c.g); got != c.want {
			t.Fatalf("grantID(%+v) = %q, want %q", c.g, got, c.want)
		}
	}
}

func TestMTLSProvisioner_TrustedGatewayDelegation(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevResolver := UserResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		UserResolver = prevResolver
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	UserResolver = func(username string) (string, []string, error) {
		if username == "varwof:delegatee:" {
			return "admin", []string{"ca:list"}, nil
		}
		return "", nil, nil
	}

	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-User", "varwof:delegatee:")
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Username != "varwof:delegatee:" {
		t.Fatalf("expected delegated principal, got %s", result.Username)
	}
	if result.Role != "admin" {
		t.Fatalf("expected delegated principal's own role, got %s", result.Role)
	}
}

func TestMTLSProvisioner_TrustedGatewayNoTTL(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevResolver := UserResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		UserResolver = prevResolver
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	UserResolver = func(username string) (string, []string, error) {
		return "admin", nil, nil
	}

	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-User", "varwof:delegatee:")

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil result when X-Agent-TTL is missing")
	}
}

func TestMTLSProvisioner_NonGatewayUserHeaderIgnored(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	defer func() { TrustedGatewayOUs = prevOUs }()
	TrustedGatewayOUs = []string{"gateway:admin"}

	p := NewMTLSProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-User", "varwof:someone-else:")
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "testuser",
			OrganizationalUnit: []string{"admin"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		Extensions:   []pkix.Extension{testPAExt(t, "cert:list")},
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Username != "testuser" {
		t.Fatalf("expected testuser (CN), got %s", result.Username)
	}
}

// testPAExt builds a PrincipalAuthorization extension granting the given
// capability IDs. IDs are "scheme:action" strings; each is split so the PA
// encodes SchemeId and CapabilityId(action) separately, matching the
// managementPAGrants encoding convention in ca/sign.go.
func testPAExt(t *testing.T, capIDs ...string) pkix.Extension {
	t.Helper()
	var grants []ca.Capability
	for _, id := range capIDs {
		scheme, action := id, id
		if i := strings.Index(id, ":"); i > 0 {
			scheme, action = id[:i], id[i+1:]
		}
		grants = append(grants, ca.Capability{SchemeId: scheme, CapabilityId: action})
	}
	ext, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

// makeForwardedCert builds a self-signed cert whose Issuer DN and serial match
// what gatewayForwardedCertUser passes to CertResolver.
func makeForwardedCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         "agent-42",
			OrganizationalUnit: []string{"Delegated-Agent"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestMTLSProvisioner_ForwardedCertValid(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevUser := UserResolver
	prevCert := CertResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		UserResolver = prevUser
		CertResolver = prevCert
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	UserResolver = func(username string) (string, []string, error) {
		if username == "varwof:forwarded-user:" {
			return "admin", []string{"ca:list"}, nil
		}
		return "", nil, nil
	}
	CertResolver = func(issuerDN, serial string) (string, string, error) {
		return "V", "varwof:forwarded-user:", nil
	}

	cert := makeForwardedCert(t, 42)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	// The peer cert presented to the provisioner is the gateway service cert.
	gwKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gwTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	gwDer, _ := x509.CreateCertificate(rand.Reader, gwTmpl, gwTmpl, &gwKey.PublicKey, gwKey)
	gwCert, _ := x509.ParseCertificate(gwDer)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{gwCert}}

	p := NewMTLSProvisioner()
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Username != "varwof:forwarded-user:" {
		t.Fatalf("expected forwarded principal, got %s", result.Username)
	}
	if result.Role != "admin" {
		t.Fatalf("expected admin, got %s", result.Role)
	}
}

func TestMTLSProvisioner_ForwardedCertRevoked(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevUser := UserResolver
	prevCert := CertResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		UserResolver = prevUser
		CertResolver = prevCert
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	UserResolver = func(username string) (string, []string, error) {
		return "admin", nil, nil
	}
	CertResolver = func(issuerDN, serial string) (string, string, error) {
		return "R", "varwof:revoked-user:", nil
	}

	cert := makeForwardedCert(t, 43)
	gwKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gwTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	gwDer, _ := x509.CreateCertificate(rand.Reader, gwTmpl, gwTmpl, &gwKey.PublicKey, gwKey)
	gwCert, _ := x509.ParseCertificate(gwDer)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{gwCert}}

	p := NewMTLSProvisioner()
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil result for revoked forwarded cert")
	}
}

func TestTokenProvisioner_NoHeader(t *testing.T) {
	p := NewTokenProvisioner()
	req, _ := http.NewRequest("GET", "/", nil)
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
}

func TestSignOption(t *testing.T) {
	opt := &ProfileOption{Profile: "tls-server"}
	sc := &ca.SignConfig{}
	if err := opt.Apply(sc); err != nil {
		t.Fatal(err)
	}
	if string(sc.Profile) != "tls-server" {
		t.Fatalf("expected tls-server, got %s", sc.Profile)
	}
}

func TestCompositeOption(t *testing.T) {
	comp := &CompositeOption{
		Options: []SignOption{
			&ProfileOption{Profile: "tls-client"},
			&KeyTypeOption{KeyType: "ecdsa-p256"},
		},
	}
	sc := &ca.SignConfig{}
	if err := comp.Apply(sc); err != nil {
		t.Fatal(err)
	}
	if string(sc.Profile) != "tls-client" {
		t.Fatal("wrong profile")
	}
	if sc.KeyType != "ecdsa-p256" {
		t.Fatal("wrong key type")
	}
}

func TestOIDCProvisioner_NoAuthHeader(t *testing.T) {
	p := NewOIDCProvisioner(OIDCConfig{IssuerURL: "https://example.com"})
	req, _ := http.NewRequest("GET", "/", nil)
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil result for no auth header")
	}
}

func TestOIDCProvisioner_JWKSFetchFailure(t *testing.T) {
	p := NewOIDCProvisioner(OIDCConfig{
		IssuerURL:    "https://example.invalid",
		ClientID:     "test-client",
		RoleOverride: "operator",
	})

	// Fail closed: JWKS fetch failure must NOT authenticate an unverified JWT.
	jwt := createTestJWT("https://example.invalid")
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	result, _ := p.Authenticate(req)
	if result != nil {
		t.Fatal("expected nil result when JWKS fetch fails (fail-closed)")
	}
}

func TestOIDCProvisioner_NoMatchingKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jwksResponse{
			Keys: []jwkKey{{
				Kid: "other-key",
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.X.Bytes(), 32)),
				Y:   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.Y.Bytes(), 32)),
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksSrv.Close()

	p := NewOIDCProvisioner(OIDCConfig{
		IssuerURL:    "https://test.issuer",
		ClientID:     "test-client",
		JWKSEndpoint: jwksSrv.URL,
	})

	// Token signed with a key whose kid is not in the JWKS → must be rejected.
	jwt := signTestJWTWithKid(key, "test-key", map[string]interface{}{
		"sub":   "testuser",
		"email": "user@example.com",
		"iss":   "https://test.issuer",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	result, _ := p.Authenticate(req)
	if result != nil {
		t.Fatal("expected nil result when no JWK matches kid (fail-closed)")
	}
}

func TestOIDCProvisioner_JWKSVerified(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// JWKS server
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xBytes := key.PublicKey.X.Bytes()
		yBytes := key.PublicKey.Y.Bytes()
		// P-256 keys are 32 bytes
		xEnc := base64.RawURLEncoding.EncodeToString(padBytes(xBytes, 32))
		yEnc := base64.RawURLEncoding.EncodeToString(padBytes(yBytes, 32))
		resp := jwksResponse{
			Keys: []jwkKey{{
				Kid: "test-key",
				Kty: "EC",
				Crv: "P-256",
				X:   xEnc,
				Y:   yEnc,
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksSrv.Close()

	p := NewOIDCProvisioner(OIDCConfig{
		IssuerURL:    "https://test.issuer",
		ClientID:     "test-client",
		JWKSEndpoint: jwksSrv.URL,
	})

	// Create signed JWT
	jwt := signTestJWT(key, map[string]interface{}{
		"sub":   "testuser",
		"email": "user@example.com",
		"iss":   "https://test.issuer",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	result, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result from OIDC")
	}
	if result.Username != "user@example.com" {
		t.Fatalf("expected user@example.com, got %s", result.Username)
	}
}

// TestOIDCProvisioner_NotYetValid rejects tokens whose nbf is in the future
// (with leeway), while accepting a slightly-in-the-past nbf.
func TestOIDCProvisioner_NotYetValid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jwksResponse{
			Keys: []jwkKey{{
				Kid: "test-key",
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.X.Bytes(), 32)),
				Y:   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.Y.Bytes(), 32)),
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksSrv.Close()

	p := NewOIDCProvisioner(OIDCConfig{
		IssuerURL:    "https://test.issuer",
		ClientID:     "test-client",
		JWKSEndpoint: jwksSrv.URL,
	})

	base := map[string]interface{}{
		"sub":   "testuser",
		"email": "user@example.com",
		"iss":   "https://test.issuer",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}

	doAuth := func(claims map[string]interface{}) *AuthResult {
		jwt := signTestJWT(key, claims)
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		res, _ := p.Authenticate(req)
		return res
	}

	// nbf far in the future → rejected (fail-closed).
	if res := doAuth(mergeClaims(base, "nbf", time.Now().Add(2*time.Hour).Unix())); res != nil {
		t.Fatal("expected rejection when nbf is far in the future")
	}
	// nbf slightly in the past → accepted (within leeway).
	if res := doAuth(mergeClaims(base, "nbf", time.Now().Add(-1*time.Minute).Unix())); res == nil {
		t.Fatal("expected acceptance when nbf is slightly in the past")
	}
	// no nbf → accepted.
	if res := doAuth(base); res == nil {
		t.Fatal("expected acceptance without nbf")
	}
}

func mergeClaims(base map[string]interface{}, k string, v interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(base)+1)
	for kk, vv := range base {
		m[kk] = vv
	}
	m[k] = v
	return m
}

// TestOIDCProvisioner_JWKSHTTPStatus rejects a JWKS endpoint returning a
// non-200 status even when the body would otherwise decode.
func TestOIDCProvisioner_JWKSHTTPStatus(t *testing.T) {
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksSrv.Close()

	p := NewOIDCProvisioner(OIDCConfig{
		IssuerURL:    "https://test.issuer",
		ClientID:     "test-client",
		JWKSEndpoint: jwksSrv.URL,
	})
	// Force a cache miss by using a fresh provisioner (no prior fetch).
	if _, err := p.jwksCache.get(p.httpClient); err == nil {
		t.Fatal("expected error when JWKS returns non-200")
	}
}

// ---- JWT test helpers ----

func createTestJWT(issuer string) string {
	header := `{"alg":"RS256","kid":"test-key","typ":"JWT"}`
	payload := `{"sub":"testuser","email":"user@test.com","iss":"` + issuer + `","exp":` + fmt.Sprintf("%d", time.Now().Add(1*time.Hour).Unix()) + `}`
	hEnc := base64.RawURLEncoding.EncodeToString([]byte(header))
	pEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return hEnc + "." + pEnc + ".fake-signature"
}

func signTestJWT(key *ecdsa.PrivateKey, claims map[string]interface{}) string {
	return signTestJWTWithKid(key, "test-key", claims)
}

func signTestJWTWithKid(key *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	header := map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(claims)
	hEnc := base64.RawURLEncoding.EncodeToString(hBytes)
	pEnc := base64.RawURLEncoding.EncodeToString(pBytes)
	signingInput := hEnc + "." + pEnc
	hash := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, key, hash[:])
	sigBytes := append(r.Bytes(), s.Bytes()...)
	sigEnc := base64.RawURLEncoding.EncodeToString(sigBytes)
	return hEnc + "." + pEnc + "." + sigEnc
}

func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// Use import from standard library
var _ = strings.TrimSpace

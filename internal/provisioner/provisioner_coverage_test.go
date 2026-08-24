// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal/ca"
)

// ---- SignOption coverage ----

func TestValidityOption(t *testing.T) {
	sc := &ca.SignConfig{}
	if err := (&ValidityOption{Validity: 0}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if sc.Validity != 0 {
		t.Fatalf("zero validity should not change config, got %v", sc.Validity)
	}
	if err := (&ValidityOption{Validity: 48}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if sc.Validity != 48*time.Hour {
		t.Fatalf("expected 48h, got %v", sc.Validity)
	}
}

func TestSANOption(t *testing.T) {
	sc := &ca.SignConfig{}
	o := &SANOption{
		DNSNames: []string{"a.example.com"},
		IPs:      []string{"10.0.0.1"},
		URIs:     []string{"spiffe://realm/agent"},
		Emails:   []string{"u@example.com"},
	}
	if err := o.Apply(sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.SANs) != 4 {
		t.Fatalf("expected 4 SANs, got %v", sc.SANs)
	}
	// Empty list: should not append
	if err := (&SANOption{}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.SANs) != 4 {
		t.Fatalf("empty option should not append, got %d", len(sc.SANs))
	}
}

func TestAICOption(t *testing.T) {
	cfg := ca.AICConfig{AgentId: "a1"}
	sc := &ca.SignConfig{}
	if err := (&AICOption{Config: cfg}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if sc.AIC == nil || sc.AIC.AgentId != "a1" {
		t.Fatalf("AIC not applied: %+v", sc.AIC)
	}
}

func TestPrincipalAuthOption(t *testing.T) {
	cfg := ca.PrincipalAuthorizationConfig{}
	sc := &ca.SignConfig{}
	if err := (&PrincipalAuthOption{Config: cfg}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if sc.PrincipalAuthorization == nil {
		t.Fatal("PrincipalAuthorization not applied")
	}
}

func TestKeyTypeOption(t *testing.T) {
	sc := &ca.SignConfig{}
	if err := (&KeyTypeOption{KeyType: "rsa-2048"}).Apply(sc); err != nil {
		t.Fatal(err)
	}
	if sc.KeyType != "rsa-2048" {
		t.Fatalf("key type: %s", sc.KeyType)
	}
}

func TestCompositeOption_ErrorPropagation(t *testing.T) {
	boom := errors.New("boom")
	comp := &CompositeOption{Options: []SignOption{
		&ProfileOption{Profile: "tls-server"},
		SignOptionFromFunc(func(sc *ca.SignConfig) error { return boom }),
	}}
	sc := &ca.SignConfig{}
	if err := comp.Apply(sc); err == nil {
		t.Fatal("expected propagated error")
	}
	// Empty option list
	empty := &CompositeOption{}
	if err := empty.Apply(sc); err != nil {
		t.Fatalf("empty composite: %v", err)
	}
}

func TestSignOptionFuncAdapter(t *testing.T) {
	called := false
	opt := SignOptionFromFunc(func(sc *ca.SignConfig) error {
		called = true
		sc.CommonName = "via-func"
		return nil
	})
	sc := &ca.SignConfig{}
	if err := opt.Apply(sc); err != nil {
		t.Fatal(err)
	}
	if !called || sc.CommonName != "via-func" {
		t.Fatal("SignOptionFunc adapter did not invoke function")
	}
}

// ---- Registry coverage ----

type fakeProv struct{ name string }

func (f *fakeProv) Name() string { return f.name }
func (f *fakeProv) Type() string { return "fake" }
func (f *fakeProv) Authenticate(r *http.Request) (*AuthResult, error) {
	return &AuthResult{Username: "from-" + f.name}, nil
}

type errProv struct{}

func (e *errProv) Name() string { return "err" }
func (e *errProv) Type() string { return "err" }
func (e *errProv) Authenticate(r *http.Request) (*AuthResult, error) {
	return nil, errors.New("reject")
}

func TestRegistry_NamesAndAuthenticate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&fakeProv{name: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(&errProv{}); err != nil {
		t.Fatal(err)
	}
	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %v", names)
	}
	// Empty registry: Authenticate returns nil,nil
	empty := NewRegistry()
	res, name, err := empty.Authenticate(&http.Request{})
	if err != nil || res != nil || name != "" {
		t.Fatalf("empty registry: %v %v %v", res, name, err)
	}
	// Has a match
	res, name, err = r.Authenticate(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || name == "" {
		t.Fatalf("expected auth result from fake prov, got %v %q", res, name)
	}
}

func TestProvisionerError(t *testing.T) {
	var e error = provisionerError("custom")
	if e.Error() != "custom" {
		t.Fatalf("Error(): %s", e.Error())
	}
	if ErrNotFound.Error() == "" {
		t.Fatal("ErrNotFound must have message")
	}
}

func TestPEMToCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pem-test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := PEMToCert(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "pem-test" {
		t.Fatalf("CN: %s", cert.Subject.CommonName)
	}
	if _, err := PEMToCert([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage PEM")
	}
}

func TestCertSpkiHash(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{1, 2, 3}}
	h := CertSpkiHash(cert)
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

// ---- NewCertIdentityFromCert coverage ----

func TestNewCertIdentityFromCert_AICBranch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pu, err := ca.ParsePrincipalUid("varwof:user@example.com:MTIzNDU2Nzg5MA")
	if err != nil {
		t.Fatal(err)
	}
	pu.KeyHash = make([]byte, 32)
	ext, err := ca.BuildAIC(ca.AICConfig{
		AgentId:      "agent-7",
		PrincipalUid: pu,
		Capabilities: []ca.Capability{{SchemeId: "mysql-v1", CapabilityId: "mysql-exec"}},
		DelegationAuthorization: &ca.DelegationAuthorization{
			Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "key rotation"},
			SignatureValue:     []byte{0xde, 0xad, 0xbe, 0xef},
			SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(99),
		Subject:         pkix.Name{CommonName: "agent-7"},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	id := NewCertIdentityFromCert(cert)
	if id == nil {
		t.Fatal("nil identity")
	}
	if id.PrincipalUid != pu.String() {
		t.Fatalf("principal_uid: %q, want %q", id.PrincipalUid, pu.String())
	}
	if id.AgentId != "agent-7" {
		t.Fatalf("agent_id: %q", id.AgentId)
	}
	if id.CN != "agent-7" {
		t.Fatalf("CN: %q", id.CN)
	}
	if id.Serial == "" || id.Issuer == "" || id.SpkiHash == "" {
		t.Fatal("identity fields not populated")
	}
}

// ---- Token provisioner coverage ----

func TestTokenProvisioner_NameType(t *testing.T) {
	p := NewTokenProvisioner()
	if p.Name() != "token" || p.Type() != "token" {
		t.Fatalf("name/type: %s/%s", p.Name(), p.Type())
	}
}

func TestTokenProvisioner_Headers(t *testing.T) {
	prev := TokenResolver
	defer func() { TokenResolver = prev }()
	TokenResolver = func(token string) (*AuthResult, error) {
		switch token {
		case "basic:secret":
			return &AuthResult{Username: "basic-user", Role: "operator"}, nil
		default:
			return &AuthResult{Username: token, Role: "operator"}, nil
		}
	}
	p := NewTokenProvisioner()

	// X-Auth-Token
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "tok-1")
	res, err := p.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Username != "tok-1" {
		t.Fatalf("x-auth-token: %+v", res)
	}

	// Bearer
	req2, _ := http.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer tok-2")
	if res, _ := p.Authenticate(req2); res == nil {
		t.Fatal("bearer should resolve")
	}

	// Basic → prefixed base64 payload (M23 fix: no double prefix, no scheme token)
	req3, _ := http.NewRequest("GET", "/", nil)
	req3.Header.Set("Authorization", "Basic secret")
	res3, err := p.Authenticate(req3)
	if err != nil {
		t.Fatal(err)
	}
	if res3 == nil || res3.Username != "basic-user" {
		t.Fatalf("basic: %+v", res3)
	}

	// Basic scheme is case-insensitive per RFC 7235 (M23 fix).
	req3b, _ := http.NewRequest("GET", "/", nil)
	req3b.Header.Set("Authorization", "bAsIc secret")
	res3b, err := p.Authenticate(req3b)
	if err != nil {
		t.Fatal(err)
	}
	if res3b == nil || res3b.Username != "basic-user" {
		t.Fatalf("basic lowercase scheme: %+v", res3b)
	}

	// Unknown scheme → no token
	req4, _ := http.NewRequest("GET", "/", nil)
	req4.Header.Set("Authorization", "Digest xyz")
	if res, _ := p.Authenticate(req4); res != nil {
		t.Fatal("unknown scheme should produce nil")
	}
}

func TestTokenProvisioner_ResolverNilOrMissing(t *testing.T) {
	prev := TokenResolver
	defer func() { TokenResolver = prev }()

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "t")

	// Resolver not set → nil
	TokenResolver = nil
	if res, _ := NewTokenProvisioner().Authenticate(req); res != nil {
		t.Fatal("nil resolver should return nil result")
	}

	// No header → nil
	noHeader, _ := http.NewRequest("GET", "/", nil)
	if res, _ := NewTokenProvisioner().Authenticate(noHeader); res != nil {
		t.Fatal("no header should return nil")
	}

	// Resolver returns nil result
	TokenResolver = func(string) (*AuthResult, error) { return nil, nil }
	if res, _ := NewTokenProvisioner().Authenticate(req); res != nil {
		t.Fatal("nil result should be ignored")
	}
}

// ---- MTLS coverage ----

func TestMTLSProvisioner_NameType(t *testing.T) {
	p := NewMTLSProvisioner()
	if p.Name() != "mtls" || p.Type() != "mtls" {
		t.Fatalf("name/type: %s/%s", p.Name(), p.Type())
	}
}

func TestDelegatedSessionAllowed(t *testing.T) {
	prev := AgentSessionMaxTTL
	defer func() { AgentSessionMaxTTL = prev }()

	// Zero TTL → reject
	AgentSessionMaxTTL = 0
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	if delegatedSessionAllowed(req) {
		t.Fatal("zero TTL must reject")
	}

	AgentSessionMaxTTL = 24 * time.Hour

	// Missing header → reject
	req2, _ := http.NewRequest("GET", "/", nil)
	if delegatedSessionAllowed(req2) {
		t.Fatal("missing TTL must reject")
	}

	// Invalid format → reject
	req3, _ := http.NewRequest("GET", "/", nil)
	req3.Header.Set("X-Agent-TTL", "not-a-time")
	if delegatedSessionAllowed(req3) {
		t.Fatal("invalid TTL must reject")
	}

	// Expired → reject
	req4, _ := http.NewRequest("GET", "/", nil)
	req4.Header.Set("X-Agent-TTL", time.Now().Add(-time.Hour).Format(time.RFC3339))
	if delegatedSessionAllowed(req4) {
		t.Fatal("expired TTL must reject")
	}

	// Exceeds window → reject
	req5, _ := http.NewRequest("GET", "/", nil)
	req5.Header.Set("X-Agent-TTL", time.Now().Add(48*time.Hour).Format(time.RFC3339))
	if delegatedSessionAllowed(req5) {
		t.Fatal("over-window TTL must reject")
	}

	// Valid → pass
	req6, _ := http.NewRequest("GET", "/", nil)
	req6.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	if !delegatedSessionAllowed(req6) {
		t.Fatal("valid TTL must pass")
	}
}

func TestGatewayForwardedCertUser_ErrorPaths(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevCert := CertResolver
	prevUser := UserResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		CertResolver = prevCert
		UserResolver = prevUser
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	UserResolver = func(string) (string, []string, error) { return "admin", nil, nil }

	gwCert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "gw", OrganizationalUnit: []string{"gateway:admin"}},
		SerialNumber: big.NewInt(1),
	}
	req := func() *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.TLS = tlsConn(gwCert)
		r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
		return r
	}

	// Base64 decode failure
	CertResolver = func(issuerDN, serial string) (string, string, error) { return "V", "u", nil }
	r := req()
	r.Header.Set("X-Client-Cert-DER", "###not-base64###")
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("bad base64 must be nil")
	}

	// Parse failure
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString([]byte("garbage")))
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("bad DER must be nil")
	}

	// CertResolver not set
	CertResolver = nil
	cert := makeForwardedCert(t, 5)
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("nil CertResolver must be nil")
	}

	// ErrNoRows
	CertResolver = func(issuerDN, serial string) (string, string, error) {
		return "", "", errors.New("sql: no rows")
	}
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("no rows must be nil")
	}

	// Other resolver error
	CertResolver = func(issuerDN, serial string) (string, string, error) {
		return "", "", errors.New("db down")
	}
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	if _, err := gatewayForwardedCertUser(r); err == nil {
		t.Fatal("db error should propagate")
	}

	// Status not V
	CertResolver = func(issuerDN, serial string) (string, string, error) { return "E", "u", nil }
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("non-V status must be nil")
	}

	// Username empty → fallback to CN (CN="agent-42", non-empty → use CN)
	CertResolver = func(issuerDN, serial string) (string, string, error) { return "V", "", nil }
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	res, _ := gatewayForwardedCertUser(r)
	if res == nil || res.Username != "agent-42" {
		t.Fatalf("CN fallback expected agent-42, got %+v", res)
	}

	// UserResolver not set → nil
	UserResolver = nil
	CertResolver = func(issuerDN, serial string) (string, string, error) { return "V", "u", nil }
	cert2 := makeForwardedCert(t, 6)
	r = req()
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert2.Raw))
	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("nil UserResolver must be nil")
	}
}

func TestGatewayForwardedCertUser_UserResolverFail(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevCert := CertResolver
	prevUser := UserResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		CertResolver = prevCert
		UserResolver = prevUser
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}
	CertResolver = func(issuerDN, serial string) (string, string, error) { return "V", "varwof:user:", nil }
	UserResolver = func(string) (string, []string, error) { return "", nil, nil }

	cert := makeForwardedCert(t, 7)
	gwCert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "gw", OrganizationalUnit: []string{"gateway:admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.TLS = tlsConn(gwCert)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	if res, _ := gatewayForwardedCertUser(r); res != nil {
		t.Fatal("empty role must be nil")
	}
}

func TestGatewayDelegatedUser(t *testing.T) {
	prevOUs := TrustedGatewayOUs
	prevUser := UserResolver
	defer func() {
		TrustedGatewayOUs = prevOUs
		UserResolver = prevUser
	}()
	TrustedGatewayOUs = []string{"gateway:admin"}

	gwCert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "gw", OrganizationalUnit: []string{"gateway:admin"}},
	}
	reqWithTTL := func() *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.TLS = tlsConn(gwCert)
		r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
		return r
	}

	// Missing X-Agent-User → nil
	UserResolver = func(string) (string, []string, error) { return "admin", nil, nil }
	if res, _ := gatewayDelegatedUser(reqWithTTL()); res != nil {
		t.Fatal("missing username must be nil")
	}

	// UserResolver not set → nil
	r := reqWithTTL()
	r.Header.Set("X-Agent-User", "varwof:delegatee:")
	UserResolver = nil
	if res, _ := gatewayDelegatedUser(r); res != nil {
		t.Fatal("nil resolver must be nil")
	}

	// No TTL → nil
	UserResolver = func(string) (string, []string, error) { return "admin", nil, nil }
	r2, _ := http.NewRequest("GET", "/", nil)
	r2.TLS = tlsConn(gwCert)
	r2.Header.Set("X-Agent-User", "varwof:delegatee:")
	if res, _ := gatewayDelegatedUser(r2); res != nil {
		t.Fatal("missing TTL must be nil")
	}

	// Success path
	r3 := reqWithTTL()
	r3.Header.Set("X-Agent-User", "varwof:delegatee:")
	res, err := gatewayDelegatedUser(r3)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Username != "varwof:delegatee:" || res.Role != "admin" {
		t.Fatalf("delegated user: %+v", res)
	}
}

func TestAuthFromAIC(t *testing.T) {
	prev := UserResolver
	defer func() { UserResolver = prev }()
	p := NewMTLSProvisioner()

	pu, _ := ca.ParsePrincipalUid("varwof:user@x.com:YWJjZA")
	cap := ca.Capability{SchemeId: "mysql-v1", CapabilityId: "exec"}
	pa := &ca.PrincipalAuthorization{Grants: []ca.Capability{cap}}

	// No PA → fail-closed (permissions come only from cert PA)
	aic := &ca.AIC{PrincipalUid: pu, Capabilities: []ca.Capability{cap}}
	if res, _ := p.authFromAIC(aic, nil); res != nil {
		t.Fatalf("nil PA must be rejected, got %+v", res)
	}
	if res, _ := p.authFromAIC(aic, &ca.PrincipalAuthorization{}); res != nil {
		t.Fatalf("empty PA must be rejected, got %+v", res)
	}

	// No resolver → basic agent identity (empty permissions, PA already included)
	UserResolver = nil
	res, err := p.authFromAIC(aic, pa)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Role != "agent" || res.Username != "varwof:user@x.com:YWJjZA" {
		t.Fatalf("no-resolver: %+v", res)
	}
	if len(res.Permissions) != 0 {
		t.Fatalf("no-resolver must yield empty permissions, got %v", res.Permissions)
	}

	// Resolver rejects
	UserResolver = func(string) (string, []string, error) { return "", nil, nil }
	if res, _ := p.authFromAIC(aic, pa); res != nil {
		t.Fatal("rejected resolver must be nil")
	}

	// No capabilities → empty permissions (fail-closed, does not fall back to inheriting PA)
	UserResolver = func(string) (string, []string, error) { return "admin", []string{"ca:list"}, nil }
	res, err = p.authFromAIC(&ca.AIC{PrincipalUid: pu}, pa)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Role != "admin(agent)" || len(res.Permissions) != 0 {
		t.Fatalf("no-cap: %+v", res)
	}

	// PA covers capabilities → intersection = AIC capabilities
	res, err = p.authFromAIC(aic, pa)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Permissions) != 1 || res.Permissions[0] != "mysql-v1:exec" {
		t.Fatalf("pa-intersect: %+v", res)
	}

	// PA does not cover capabilities → empty permissions (fail-closed)
	otherPA := &ca.PrincipalAuthorization{Grants: []ca.Capability{
		{SchemeId: "core", CapabilityId: "cert-issue"},
	}}
	res, err = p.authFromAIC(aic, otherPA)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Permissions) != 0 {
		t.Fatalf("uncovered PA must yield empty perms, got %+v", res)
	}

	// PA wildcard covers capabilities
	wildPA := &ca.PrincipalAuthorization{Grants: []ca.Capability{
		{SchemeId: "mysql-v1", CapabilityId: "*"},
	}}
	res, err = p.authFromAIC(aic, wildPA)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Permissions) != 1 || res.Permissions[0] != "mysql-v1:exec" {
		t.Fatalf("wildcard PA: %+v", res)
	}
}

func TestOuToRole_NoPolicy(t *testing.T) {
	prev := auth.GetPolicy()
	defer auth.SetPolicy(prev)
	auth.SetPolicy(nil)

	cases := map[string]string{
		"SuperAdmin": "superadmin",
		"admin":      "admin",
		"Admin":      "admin",
		"Operator":   "operator",
		"Auditor":    "auditor",
		"Revoker":    "revoker",
		"ReadOnly":   "readonly",
		"Console":    "console",
		"AutoRenew":  "auto-renew",
		"Reporter":   "reporter",
	}
	for ou, want := range cases {
		if got := ouToRole([]string{ou}); got != want {
			t.Errorf("ouToRole(%q) = %q, want %q", ou, got, want)
		}
	}
	if got := ouToRole([]string{"unknown", "also-unknown"}); got != "" {
		t.Errorf("unknown OU: %q", got)
	}
	if got := ouToRole(nil); got != "" {
		t.Errorf("nil OUs: %q", got)
	}
}

func TestRolePerms_NoPolicy(t *testing.T) {
	prev := auth.GetPolicy()
	defer auth.SetPolicy(prev)
	auth.SetPolicy(nil)

	perms := rolePerms("admin")
	if len(perms) == 0 {
		t.Fatal("admin should have fallback perms")
	}
	// Undefined role → empty (len(RolePermissions[role])==0 → empty slice)
	if got := rolePerms("nonexistent"); len(got) != 0 {
		t.Fatalf("nonexistent perms: %v", got)
	}
}

func TestHasOU(t *testing.T) {
	if !hasOU([]string{"a", "target"}, "target") {
		t.Fatal("should find target")
	}
	if hasOU([]string{"a", "b"}, "target") {
		t.Fatal("should not find target")
	}
}

// tlsConn constructs a fake TLS connection state to avoid repeated inlining.
func tlsConn(peer *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
}

var _ = tlsConn // keep reference (suppress unused warning noise)

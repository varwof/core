// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/engine/db"
)

func TestAuthFromAIC_UserNotFound(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "nonexistent"},
	}
	user, err := s.authFromAIC(aic, &ca.PrincipalAuthorization{Grants: []ca.Capability{{CapabilityId: "cert:list"}}})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestAuthFromAIC_UserDisabled(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:disabled-user:", db.HashPassword("pwd", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE rbac_users SET enabled = 0 WHERE username = ?", "varwof:disabled-user:"); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "disabled-user"},
	}
	user, err := s.authFromAIC(aic, &ca.PrincipalAuthorization{Grants: []ca.Capability{{CapabilityId: "cert:list"}}})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user for disabled account, got %+v", user)
	}
}

func TestAuthFromAIC_NoPAFailsClosed(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:alice:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice"},
		Capabilities: []ca.Capability{{CapabilityId: string(PermCertIssue)}},
	}
	// Cert-first fail-closed: no PA extension → reject (permissions only come from cert PA).
	if user, _ := s.authFromAIC(aic, nil); user != nil {
		t.Fatalf("expected nil user for missing PA, got %+v", user)
	}
	if user, _ := s.authFromAIC(aic, &ca.PrincipalAuthorization{}); user != nil {
		t.Fatalf("expected nil user for empty PA, got %+v", user)
	}
}

func TestAuthFromAIC_EmptyCapabilitiesFailsClosed(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:alice:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice"},
	}
	pa := &ca.PrincipalAuthorization{Grants: []ca.Capability{{CapabilityId: string(PermCertIssue)}}}
	user, err := s.authFromAIC(aic, pa)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "varwof:alice:" {
		t.Fatalf("expected varwof:alice:, got %s", user.Username)
	}
	if user.Role != "admin(agent)" {
		t.Fatalf("expected admin(agent), got %s", user.Role)
	}
	// Fail-closed: an AIC without declared capabilities must NOT inherit the
	// user's full permissions — that would make it a full-power proxy.
	if len(user.Permissions) != 0 {
		t.Fatalf("expected empty permissions for empty-capabilities AIC (fail-closed), got %v", user.Permissions)
	}
}

func TestAuthFromAIC_Intersection(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:bob:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-2",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "bob"},
		Capabilities: []ca.Capability{
			{SchemeId: "cert", CapabilityId: "issue"},
			{SchemeId: "cert", CapabilityId: "list"},
		},
	}
	pa := &ca.PrincipalAuthorization{Grants: []ca.Capability{
		{SchemeId: "cert", CapabilityId: "issue"},
		{SchemeId: "cert", CapabilityId: "list"},
	}}
	user, err := s.authFromAIC(aic, pa)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "varwof:bob:" {
		t.Fatalf("expected varwof:bob:, got %s", user.Username)
	}
	if len(user.Permissions) == 0 {
		t.Fatal("expected non-empty permissions (intersection)")
	}
	// Should only have the intersected perms
	for _, p := range user.Permissions {
		if p != PermCertIssue && p != PermCertList {
			t.Fatalf("unexpected permission in intersection: %s", p)
		}
	}
}

func TestAuthFromAIC_EmptyIntersection(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:carol:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)

	aic := &ca.AIC{
		AgentId:      "agent-3",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "carol"},
		Capabilities: []ca.Capability{
			{SchemeId: "test", CapabilityId: "nonexistent-perm"},
		},
	}
	pa := &ca.PrincipalAuthorization{Grants: []ca.Capability{
		{SchemeId: "test", CapabilityId: string(PermCertIssue)},
	}}
	user, err := s.authFromAIC(aic, pa)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if len(user.Permissions) != 0 {
		t.Fatalf("expected empty permissions for no-match intersection, got %v", user.Permissions)
	}
}

func TestAuthFromCert_DelegatedAgentWithHeader(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gateway-bot",
			OrganizationalUnit: []string{"Delegated-Agent", "admin"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{authCertPAExt(t, "ca:list")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	// X-Agent-User must be ignored (A05): identity comes from the cert.
	r.Header.Set("X-Agent-User", "human-admin")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "gateway-bot" {
		t.Fatalf("expected gateway-bot from certificate CN, got %s", user.Username)
	}
}

func TestAuthFromCert_DelegatedAgentNoTTL(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gateway-bot",
			OrganizationalUnit: []string{"Delegated-Agent", "admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// No X-Agent-TTL → fail-closed (was previously unlimited).
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user when X-Agent-TTL is missing")
	}
}

func TestAuthFromCert_DelegatedAgentTTLTooLong(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gateway-bot",
			OrganizationalUnit: []string{"Delegated-Agent", "admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// TTL window beyond the configured 24h cap → rejected.
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-TTL", time.Now().Add(48*time.Hour).Format(time.RFC3339))
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user when X-Agent-TTL exceeds the cap")
	}

	// AgentSessionMaxTTL = "0" rejects delegated sessions entirely.
	cfg.Serve.AgentSessionMaxTTL = "0"
	r2, _ := http.NewRequest("GET", "/api/cas", nil)
	r2.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	if user, _ := s.authFromCert(cert, r2); user != nil {
		t.Fatal("expected nil user when agent sessions are disabled")
	}
}

func TestAuthFromCert_TrustedGatewayDelegation(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:delegatee:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// A trusted gateway may assert the delegated principal (server-side).
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "varwof:delegatee:")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "varwof:delegatee:" {
		t.Fatalf("expected delegated principal username, got %q", user.Username)
	}
	if user.Role != "admin" {
		t.Fatalf("expected delegated principal's own role (admin), got %q", user.Role)
	}
}

func TestAuthFromCert_TrustedGatewayNoTTL(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// X-Agent-TTL missing → fail-closed even for a trusted gateway.
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "varwof:delegatee:")
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user when X-Agent-TTL is missing")
	}
}

func TestAuthFromCert_TrustedGatewayUnknownUser(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "gw-service",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// Principal asserted by a trusted gateway must exist in the DB.
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "varwof:no-such-user:")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for unknown delegated principal")
	}
}

func TestAuthFromCert_NonGatewayUserHeaderIgnored(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "regular-user",
			OrganizationalUnit: []string{"admin"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{authCertPAExt(t, "ca:list")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// A direct client (no gateway OU) cannot spoof X-Agent-User.
	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "varwof:someone-else:")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "regular-user" {
		t.Fatalf("expected regular-user (CN), got %s", user.Username)
	}
}

// makeForwardedAgentCert builds a self-signed cert whose Issuer DN matches the
// DB issuer_dn used in B2 lookups, and returns both the cert and the DB record.
func makeForwardedAgentCert(t *testing.T, serial int64, ou []string) (*x509.Certificate, *db.CertRecord) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         "agent-42",
			OrganizationalUnit: ou,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	rec := db.CertRecord{
		SerialNumber: fmt.Sprintf("%040X", big.NewInt(serial)),
		CAName:       "issuing",
		Status:       "V",
		IssuerDN:     cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		CertDER:      der,
		PrincipalUid: "varwof:forwarded-user:",
		AgentId:      "agent-42",
	}
	return cert, &rec
}

func TestAuthFromCert_ForwardedCertValid(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("varwof:forwarded-user:", db.HashPassword("pwd", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}
	cert, rec := makeForwardedAgentCert(t, 42, []string{"gateway:admin"})
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "varwof:forwarded-user:" {
		t.Fatalf("expected forwarded principal, got %q", user.Username)
	}
	if user.Role != "admin" {
		t.Fatalf("expected admin, got %q", user.Role)
	}
}

func TestAuthFromCert_ForwardedCertRevoked(t *testing.T) {
	d := newTestDB(t)
	cert, rec := makeForwardedAgentCert(t, 43, []string{"gateway:admin"})
	rec.PrincipalUid = "varwof:revoked-user:"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeCert("issuing", fmt.Sprintf("%040X", big.NewInt(43)), 1); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for revoked forwarded cert")
	}
}

func TestAuthFromCert_ForwardedCertUnknown(t *testing.T) {
	d := newTestDB(t)
	cert, _ := makeForwardedAgentCert(t, 44, []string{"gateway:admin"})

	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	// Cert not issued by this PKI → no DB record → rejected.
	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for unknown forwarded cert")
	}
}

func TestAuthFromCert_ForwardedCertBadDER(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	cert, _ := makeForwardedAgentCert(t, 45, []string{"gateway:admin"})

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", "not-valid-base64!!!")
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user for malformed X-Client-Cert-DER")
	}
}

func TestAuthFromCert_ForwardedCertNoTTL(t *testing.T) {
	d := newTestDB(t)
	cert, rec := makeForwardedAgentCert(t, 46, []string{"gateway:admin"})
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(cert.Raw))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatal("expected nil user when X-Agent-TTL is missing")
	}
}

func TestAuthFromCert_ForwardedCertNonGatewayIgnored(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	cfg.Serve.TrustedGatewayOUs = []string{"gateway:admin"}
	s.cfgPtr.Store(&cfg)

	// Direct client cert (no gateway OU) sending X-Client-Cert-DER.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "regular-user",
			OrganizationalUnit: []string{"admin"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{authCertPAExt(t, "ca:list")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(der))
	r.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "regular-user" {
		t.Fatalf("expected regular-user (CN), got %s", user.Username)
	}
}

func TestAuthFromCert_NoDelegatedAgent(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "regular-user",
			OrganizationalUnit: []string{"admin"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{authCertPAExt(t, "ca:list")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "should-be-ignored")

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "regular-user" {
		t.Fatalf("expected regular-user (CN), got %s", user.Username)
	}
}

func TestAuthFromCert_UnknownOU(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "stranger",
			OrganizationalUnit: []string{"unknown-role"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r, _ := http.NewRequest("GET", "/api/cas", nil)

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user for unknown OU, got %+v", user)
	}
}

func TestAuthFromCert_AICPreferred(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	const keyFP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := d.CreateUser("varwof:aic-user:"+keyFP, db.HashPassword("pwd", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	s.dbPtr.Store(d)

	aicVal, _ := ca.BuildAIC(ca.AICConfig{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "aic-user", KeyHash: make([]byte, 32)},
		Capabilities: []ca.Capability{{SchemeId: "varwof", CapabilityId: "cert:list"}},
		DelegationAuthorization: &ca.DelegationAuthorization{
			Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "test AIC delegation"},
			SignatureValue:     []byte{0xde, 0xad, 0xbe, 0xef},
			SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
		},
	})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "agent-cert",
			OrganizationalUnit: []string{"Delegated-Agent"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{aicVal, authCertPAExt(t, "cert:list")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r, _ := http.NewRequest("GET", "/api/cas", nil)
	r.Header.Set("X-Agent-User", "header-user")

	user, err := s.authFromCert(cert, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "varwof:aic-user:"+keyFP {
		t.Fatalf("expected varwof:aic-user:%s from AIC PrincipalUid, got %s", keyFP, user.Username)
	}
}

func TestCAScopeCheck(t *testing.T) {
	// simple mode — no scope check, should pass
	user := &AuthUser{
		Username:    "admin",
		Role:        "admin",
		Permissions: RolePermissions["admin"],
		CAScopes:    []string{"*"},
	}

	r, _ := http.NewRequest("GET", "/api/ca/test-ca", nil)
	cfg := internal.DefaultConfig()
	cfg.RBAC.PermissionMode = "simple"

	if !checkCAScope(user, r, PermCAInfo, &cfg) {
		t.Fatal("expected scope check to pass in simple mode (should not be called)")
	}
}

func TestExtractCANameFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/cert/issuing/ABCD/revoke", "issuing"},
		{"/api/v1/crl/issuing/generate", "issuing"},
		{"/api/v1/certs", ""},
		{"/api/v1/cert/", ""},
		{"/", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractCANameFromPath(tc.path)
		if got != tc.want {
			t.Errorf("extractCANameFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestHasOU(t *testing.T) {
	if !hasOU([]string{"Delegated-Agent", "ops"}, "Delegated-Agent") {
		t.Fatal("expected to find Delegated-Agent OU")
	}
	if hasOU([]string{"admin", "ops"}, "Delegated-Agent") {
		t.Fatal("expected not to find Delegated-Agent OU")
	}
	if hasOU(nil, "anything") {
		t.Fatal("expected false for nil OUs")
	}
}

func newLoginServer(t *testing.T) *Server {
	t.Helper()
	d := newTestDB(t)
	seedAdmin(t, d)
	s := &Server{}
	s.dbPtr.Store(d)
	s.bundle = i18n.NewBundle()
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)
	return s
}

func doLogin(t *testing.T, s *Server, username, password string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiLogin(rec, req)
	return rec.Code
}

func TestLoginThrottle(t *testing.T) {
	origMax, origDur := maxLoginFailures, lockoutDuration
	maxLoginFailures, lockoutDuration = 5, 5*time.Minute
	defer func() { maxLoginFailures, lockoutDuration = origMax, origDur }()

	s := newLoginServer(t)
	// Failed attempts before the threshold → 401.
	for i := 0; i < 4; i++ {
		if code := doLogin(t, s, "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, code)
		}
	}
	// 5th failure locks the account.
	if code := doLogin(t, s, "admin", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("5th failure: expected 401, got %d", code)
	}
	// Subsequent attempts (even with correct password) → 429.
	for i := 0; i < 3; i++ {
		if code := doLogin(t, s, "admin", "admin"); code != http.StatusTooManyRequests {
			t.Fatalf("locked attempt %d: expected 429, got %d", i+1, code)
		}
	}
}

func TestLoginThrottleReset(t *testing.T) {
	origMax, origDur := maxLoginFailures, lockoutDuration
	maxLoginFailures, lockoutDuration = 5, 5*time.Minute
	defer func() { maxLoginFailures, lockoutDuration = origMax, origDur }()

	s := newLoginServer(t)
	for i := 0; i < 2; i++ {
		doLogin(t, s, "admin", "wrong")
	}
	// Successful login clears the counter.
	if code := doLogin(t, s, "admin", "admin"); code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", code)
	}
	// Two more failures should NOT lock yet.
	for i := 0; i < 2; i++ {
		if code := doLogin(t, s, "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("after reset attempt %d: expected 401, got %d", i+1, code)
		}
	}
	if code := doLogin(t, s, "admin", "admin"); code != http.StatusOK {
		t.Fatalf("login after reset: expected 200, got %d", code)
	}
}

func TestLoginThrottleExpiry(t *testing.T) {
	origMax, origDur := maxLoginFailures, lockoutDuration
	maxLoginFailures, lockoutDuration = 5, 5*time.Minute
	defer func() { maxLoginFailures, lockoutDuration = origMax, origDur }()

	s := newLoginServer(t)
	for i := 0; i < 5; i++ {
		doLogin(t, s, "admin", "wrong")
	}
	if code := doLogin(t, s, "admin", "admin"); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while locked, got %d", code)
	}
	// Simulate lockout expiry.
	s.loginMu.Lock()
	at := s.loginAttempts["admin"]
	at.lockedUntil = time.Now().Add(-time.Second)
	s.loginAttempts["admin"] = at
	s.loginMu.Unlock()

	if code := doLogin(t, s, "admin", "admin"); code != http.StatusOK {
		t.Fatalf("expected 200 after expiry, got %d", code)
	}
}

func TestBasicAuthThrottle(t *testing.T) {
	origMax, origDur := maxLoginFailures, lockoutDuration
	maxLoginFailures, lockoutDuration = 5, 5*time.Minute
	defer func() { maxLoginFailures, lockoutDuration = origMax, origDur }()

	s := newLoginServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	for i := 0; i < 5; i++ {
		u, _ := s.authByBasic(req)
		if u != nil {
			t.Fatalf("attempt %d: expected auth failure", i+1)
		}
	}
	// Locked: even correct credentials are rejected.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.SetBasicAuth("admin", "admin")
	if u, _ := s.authByBasic(req2); u != nil {
		t.Fatal("expected Basic auth to be blocked while locked")
	}
}

func TestTokenHashedAtRest(t *testing.T) {
	d := newTestDB(t)
	salt, _ := db.GenerateSalt()
	if err := d.CreateUser("tokhash", db.HashPassword("p", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}
	u, _ := d.GetUserByUsername("tokhash")

	tok, err := d.CreateAPIToken(u.ID, "plaintext-check", "")
	if err != nil {
		t.Fatal(err)
	}

	// Plaintext must never be stored; the column holds the SHA-256 hash.
	var stored string
	if err := d.QueryRow("SELECT token FROM rbac_api_tokens WHERE id = ?", tok.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == tok.Token {
		t.Fatal("plaintext token found in database")
	}
	if stored != db.TokenHash(tok.Token) {
		t.Fatalf("expected stored token hash, got %q", stored)
	}

	// Token still authenticates.
	if info, err := d.GetToken(tok.Token); err != nil || info == nil {
		t.Fatalf("GetToken with plaintext failed: %v", err)
	}

	// ListTokens must not expose the plaintext.
	list, _ := d.ListTokens(u.ID)
	if len(list) != 1 {
		t.Fatalf("expected 1 token, got %d", len(list))
	}
	if list[0].Token == tok.Token {
		t.Fatal("ListTokens leaked plaintext token")
	}
	if strings.Contains(list[0].Token, tok.Token) {
		t.Fatal("ListTokens leaked a substring of the token")
	}
}

func TestAPISession_CertIdentity(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	paExt, _ := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{
		Grants: []ca.Capability{{SchemeId: "core", CapabilityId: "cert:list"}},
	})
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:         "user-cert",
			OrganizationalUnit: []string{"admin"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{paExt},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	r := httptest.NewRequest("GET", "/api/v1/session", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()

	s.apiSession(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		CertIdentity  *struct {
			Serial   string `json:"serial"`
			SpkiHash string `json:"spki_hash"`
			CN       string `json:"cn"`
		} `json:"cert_identity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Authenticated {
		t.Fatal("expected authenticated=true")
	}
	if body.CertIdentity == nil {
		t.Fatal("expected cert_identity for mTLS session")
	}
	if body.CertIdentity.Serial != fmt.Sprintf("%040X", big.NewInt(42)) {
		t.Fatalf("unexpected serial: %s", body.CertIdentity.Serial)
	}
	if body.CertIdentity.SpkiHash == "" {
		t.Fatal("expected spki_hash")
	}
	if body.CertIdentity.CN != "user-cert" {
		t.Fatalf("unexpected cn: %s", body.CertIdentity.CN)
	}
}

func TestAPISession_TokenNoCert(t *testing.T) {
	d := newTestDB(t)
	s := &Server{}
	s.dbPtr.Store(d)
	cfg := internal.DefaultConfig()
	s.cfgPtr.Store(&cfg)

	// No client cert, no token → 401.
	r := httptest.NewRequest("GET", "/api/v1/session", nil)
	w := httptest.NewRecorder()
	s.apiSession(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated session, got %d", w.Code)
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/routing"
	"github.com/varwof/engine/db"
)

var scopeOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1}

var mgmtCertSerial int64

// signManagementCert signs an entity management certificate (OU → operator,
// DigitalSignature KU, scope via SAN URI + OID) under the given CA.
func signManagementCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer,
	cn, ou, scope string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	id := atomic.AddInt64(&mgmtCertSerial, 1)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scopeExt := pkix.Extension{Id: scopeOID, Value: []byte(scope)}
	uri, _ := url.Parse("urn:pki:ca:" + scope)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(id),
		Subject:         pkix.Name{CommonName: cn, OrganizationalUnit: []string{ou}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{scopeExt},
		URIs:            []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// registerCert inserts a certificate record with the given status so that
// GetCertStatusByIssuer can resolve it.
func registerCert(t *testing.T, d *db.DB, caCert *x509.Certificate, cert *x509.Certificate, status string) {
	t.Helper()
	notAfter := cert.NotAfter
	rec := &db.CertRecord{
		SerialNumber: fmt.Sprintf("%040X", cert.SerialNumber),
		CAName:       caCert.Subject.CommonName,
		Status:       status,
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      cert.Raw,
		Fingerprint:  db.Fingerprint(cert.Raw),
		IssuerDN:     caCert.Subject.String(),
		Profile:      "m-operator",
	}
	if status == "R" {
		revoked := notAfter.Add(-time.Hour)
		rec.RevokedAt = &revoked
		reason := 1
		rec.RevokeReason = &reason
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorCertScopes_ValidCert(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "VPC Client CA",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "V")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, err := srv.getDB().GetUserByUsername("op")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.getDB().UpdateUserOperatorCert(user.ID,
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))); err != nil {
		t.Fatal(err)
	}
	user, _ = srv.getDB().GetUserByUsername("op")

	scopes, err := srv.operatorCertScopes(user, []string{"CA-A"})
	if err != nil {
		t.Fatalf("operatorCertScopes: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "VPC Client CA" {
		t.Fatalf("expected scope [VPC Client CA], got %v", scopes)
	}
}

func TestOperatorCertScopes_FallbackWhenUnbound(t *testing.T) {
	srv, _ := newTestServerWithDB(t)

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")
	if err := srv.getDB().UpdateUserOperatorCert(user.ID, ""); err != nil {
		t.Fatal(err)
	}
	user, _ = srv.getDB().GetUserByUsername("op")

	scopes, err := srv.operatorCertScopes(user, []string{"CA-A"})
	if err != nil {
		t.Fatalf("operatorCertScopes: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "CA-A" {
		t.Fatalf("expected fallback [CA-A], got %v", scopes)
	}
}

func TestOperatorCertScopes_FailClosed(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")

	// 1. Expired cert
	expired := signManagementCert(t, caCert, caKey, "expired", "Operator", "CA-X",
		time.Now().Add(-time.Hour))
	registerCert(t, srv.getDB(), caCert, expired, "V")
	setOpCert(t, srv, user, expired)
	if _, err := srv.operatorCertScopes(user, nil); err == nil {
		t.Fatal("expected error for expired cert")
	}

	// 2. Revoked cert
	revoked := signManagementCert(t, caCert, caKey, "revoked", "Operator", "CA-Y",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, revoked, "R")
	setOpCert(t, srv, user, revoked)
	if _, err := srv.operatorCertScopes(user, nil); err == nil {
		t.Fatal("expected error for revoked cert")
	}

	// 3. Not issued by this PKI (no DB record)
	foreignCA, foreignKey := newTestCA(t, "foreign-ca")
	foreign := signManagementCert(t, foreignCA, foreignKey, "foreign", "Operator", "CA-Z",
		time.Now().Add(24*time.Hour))
	setOpCert(t, srv, user, foreign)
	if _, err := srv.operatorCertScopes(user, nil); err == nil {
		t.Fatal("expected error for foreign cert")
	}

	// 4. Invalid PEM
	if err := srv.getDB().UpdateUserOperatorCert(user.ID, "not a pem"); err != nil {
		t.Fatal(err)
	}
	user, _ = srv.getDB().GetUserByUsername("op")
	if _, err := srv.operatorCertScopes(user, nil); err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func setOpCert(t *testing.T, srv *Server, user *db.RBACUser, cert *x509.Certificate) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := srv.getDB().UpdateUserOperatorCert(user.ID, string(pemBytes)); err != nil {
		t.Fatal(err)
	}
	user.OperatorCertPEM = string(pemBytes)
}

func TestOperatorCertProxy_AuthBasicDerivesScope(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "VPC Client CA",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "V")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")
	setOpCert(t, srv, user, cert)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/users/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("op", "secret")
	au, err := srv.authByBasic(req)
	if err != nil {
		t.Fatalf("authByBasic: %v", err)
	}
	if au == nil {
		t.Fatal("no auth user")
	}
	if len(au.CAScopes) != 1 || au.CAScopes[0] != "VPC Client CA" {
		t.Fatalf("expected scope [VPC Client CA], got %v", au.CAScopes)
	}
}

func TestRequireRouteAuth_ScopeEnforcedInSimpleMode(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	// operator-cert bound with scope matching "test-ca"
	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "test-ca",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "V")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")
	setOpCert(t, srv, user, cert)

	// Control user without operator-cert
	salt2, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("noscope", db.HashPassword("secret", salt2), salt2, "operator"); err != nil {
		t.Fatal(err)
	}

	// Default permission_mode = simple, but ca_scope rules must be enforced in all modes
	rule := &routing.RouteRule{Method: "*", Path: "/api/v1/cert/{ca}/{serial}/revoke",
		Permission: "cert:revoke", CAScope: true}

	call := func(username, path string) int {
		req, _ := http.NewRequest(http.MethodPost, path, nil)
		req.SetBasicAuth(username, "secret")
		rec := httptest.NewRecorder()
		h := srv.requireRouteAuth(rule, nil, func(w http.ResponseWriter, r *http.Request) {
			apiOK(w, map[string]string{"ok": "1"})
		})
		h(rec, req)
		return rec.Code
	}

	// Matching scope → allow
	if code := call("op", "/api/v1/cert/test-ca/ABCD/revoke"); code != http.StatusOK {
		t.Fatalf("expected 200 for matching scope, got %d", code)
	}
	// Non-matching scope → 403
	if code := call("op", "/api/v1/cert/other-ca/ABCD/revoke"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-matching scope, got %d", code)
	}
	// No-scope user → simple mode preserves original behavior (allow)
	if code := call("noscope", "/api/v1/cert/test-ca/ABCD/revoke"); code != http.StatusOK {
		t.Fatalf("expected 200 for no-scope user in simple mode, got %d", code)
	}
}

func TestAPIUserOperatorCert_BindUnbind(t *testing.T) {
	srv, h := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "VPC Client CA",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "V")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")

	// user:manage (operator-cert bind/unbind) requires the superadmin
	// management certificate under the strict default route table.
	fx := newMTLSSuperAdminFixture(t, h, "user:manage")

	post := func(path string, body []byte) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, fx.Server.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := fx.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		rr := httptest.NewRecorder()
		rr.Code = resp.StatusCode
		rr.Body = bytes.NewBuffer(raw)
		return rr
	}

	// Bind: valid cert → bound + scope
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	rec := post(fmt.Sprintf("/api/v1/users/%d/operator-cert", user.ID),
		[]byte(fmt.Sprintf(`{"cert_pem":%q}`, string(pemBytes))))
	if rec.Code != http.StatusOK {
		t.Fatalf("bind: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Auth path should derive cert scope
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/users/info", nil)
	req.SetBasicAuth("op", "secret")
	au, err := srv.authByBasic(req)
	if err != nil {
		t.Fatalf("authByBasic: %v", err)
	}
	if len(au.CAScopes) != 1 || au.CAScopes[0] != "VPC Client CA" {
		t.Fatalf("expected scope [VPC Client CA], got %v", au.CAScopes)
	}

	// Bind invalid cert → 400
	rec = post(fmt.Sprintf("/api/v1/users/%d/operator-cert", user.ID),
		[]byte(`{"cert_pem":"garbage"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bind invalid: expected 400, got %d", rec.Code)
	}

	// Unbind
	dreq, _ := http.NewRequest(http.MethodDelete,
		fx.Server.URL+fmt.Sprintf("/api/v1/users/%d/operator-cert", user.ID), nil)
	dresp, err := fx.Client.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dresp.Body)
		t.Fatalf("unbind: expected 200, got %d: %s", dresp.StatusCode, string(b))
	}

	// After unbind, fallback to account ca_scopes (none → nil)
	req, _ = http.NewRequest(http.MethodGet, "/api/v1/users/info", nil)
	req.SetBasicAuth("op", "secret")
	au, err = srv.authByBasic(req)
	if err != nil {
		t.Fatalf("authByBasic: %v", err)
	}
	if len(au.CAScopes) != 0 {
		t.Fatalf("expected no scopes after unbind, got %v", au.CAScopes)
	}
}

// TestAuthResultToUser_OperatorCertScopes verifies the provisioner registry auth
// path also derives operator-cert scope (a critical path beyond the legacy chain).
func TestAuthResultToUser_OperatorCertScopes(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "VPC Client CA",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "V")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")
	setOpCert(t, srv, user, cert)

	au, err := srv.authResultToUser(&provisioner.AuthResult{
		Username:    "op",
		Role:        "operator",
		Permissions: []string{"cert:issue"},
	})
	if err != nil {
		t.Fatalf("authResultToUser: %v", err)
	}
	if au == nil {
		t.Fatal("no auth user")
	}
	if len(au.CAScopes) != 1 || au.CAScopes[0] != "VPC Client CA" {
		t.Fatalf("expected scope [VPC Client CA], got %v", au.CAScopes)
	}
}

// TestAuthResultToUser_OperatorCertRevoked verifies that after cert revocation the
// provisioner path fails-closed (auth returns error) instead of silently degrading
// to no scope.
func TestAuthResultToUser_OperatorCertRevoked(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	cert := signManagementCert(t, caCert, caKey, "op-cert", "Operator", "VPC Client CA",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, cert, "R")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")
	setOpCert(t, srv, user, cert)

	_, err := srv.authResultToUser(&provisioner.AuthResult{
		Username:    "op",
		Role:        "operator",
		Permissions: []string{"cert:issue"},
	})
	if err == nil {
		t.Fatal("expected error for revoked operator cert (fail-closed)")
	}
}

func TestRequireRouteAuth_AgentBlockedByAllowAIC(t *testing.T) {
	srv, _ := newTestServerWithDB(t)

	// Bind a real user (agent's PrincipalUid mapping)
	salt, _ := db.GenerateSalt()
	const keyFP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := srv.getDB().CreateUser("varwof:aic-user:"+keyFP, db.HashPassword("secret", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}

	// Construct mTLS cert with AIC extension (including capabilities)
	aicVal, err := ca.BuildAIC(ca.AICConfig{
		AgentId:      "agent-1",
		PrincipalUid: ca.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "aic-user", KeyHash: make([]byte, 32)},
		Capabilities: []ca.Capability{
			{SchemeId: "cert", CapabilityId: "revoke"},
			{SchemeId: "cert", CapabilityId: "list"},
		},
		DelegationAuthorization: &ca.DelegationAuthorization{
			Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "test AIC delegation"},
			SignatureValue:     []byte{0xde, 0xad, 0xbe, 0xef},
			SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	paVal, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{
		Grants: []ca.Capability{
			{SchemeId: "cert", CapabilityId: "revoke"},
			{SchemeId: "cert", CapabilityId: "list"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "agent-cert",
			OrganizationalUnit: []string{"Delegated-Agent"},
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{aicVal, paVal},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	agentCert, _ := x509.ParseCertificate(der)

	// Destructive endpoint rule: revoke with allow_aic: false
	rule := &routing.RouteRule{
		Method: "POST", Path: "/api/v1/cert/{ca}/{serial}/revoke",
		Permission: "cert:revoke", CAScope: true, AllowAIC: boolPtr(false),
	}

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/cert/test-ca/ABCD/revoke", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{agentCert}}
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	rec := httptest.NewRecorder()
	h := srv.requireRouteAuth(rule, nil, func(w http.ResponseWriter, r *http.Request) {
		apiOK(w, map[string]string{"ok": "1"})
	})
	h(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent on allow_aic:false endpoint, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Control: same cert accessing allow_aic unset (nil=true) endpoint → allow
	rule2 := &routing.RouteRule{
		Method: "GET", Path: "/api/v1/certs", Permission: "cert:list",
	}
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/certs", nil)
	req2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{agentCert}}
	req2.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).Format(time.RFC3339))
	rec2 := httptest.NewRecorder()
	h2 := srv.requireRouteAuth(rule2, nil, func(w http.ResponseWriter, r *http.Request) {
		apiOK(w, map[string]string{"ok": "1"})
	})
	h2(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for agent on default-open endpoint, got %d (%s)", rec2.Code, rec2.Body.String())
	}
}

func boolPtr(b bool) *bool { return &b }

// TestAPIUserOperatorCert_NegativePaths drives the remaining apiUserOperatorCert
// error branches through the HTTP layer: bad id, malformed JSON, missing cert_pem,
// a non-management certificate whose OU maps to no role, and an unsupported method.
func TestAPIUserOperatorCert_NegativePaths(t *testing.T) {
	srv, h := newTestServerWithDB(t)
	caCert, caKey := newTestCA(t, "test-ca")

	salt, _ := db.GenerateSalt()
	if err := srv.getDB().CreateUser("op", db.HashPassword("secret", salt), salt, "operator"); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.getDB().GetUserByUsername("op")

	fx := newMTLSSuperAdminFixture(t, h, "user:manage")

	send := func(method, suffix, body string) *httptest.ResponseRecorder {
		t.Helper()
		req, _ := http.NewRequest(method, fx.Server.URL+suffix, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := fx.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		rr := httptest.NewRecorder()
		rr.Code = resp.StatusCode
		rr.Body = bytes.NewBuffer(raw)

		return rr
	}

	path := fmt.Sprintf("/api/v1/users/%d/operator-cert", user.ID)

	// Non-management certificate (OU maps to no role), registered and valid.
	engineerCert := signManagementCert(t, caCert, caKey, "eng", "Engineer", "CA-E",
		time.Now().Add(24*time.Hour))
	registerCert(t, srv.getDB(), caCert, engineerCert, "V")
	engineerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: engineerCert.Raw})

	tests := []struct {
		name     string
		method   string
		suffix   string
		body     string
		wantCode int
		wantErr  string
	}{
		{
			name:     "invalid user id",
			method:   http.MethodPost,
			suffix:   "/api/v1/users/abc/operator-cert",
			body:     `{"cert_pem":"x"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid user id",
		},
		{
			name:     "malformed json",
			method:   http.MethodPost,
			suffix:   path,
			body:     `{not json`,
			wantCode: http.StatusBadRequest,
			wantErr:  "Invalid JSON",
		},
		{
			name:     "missing cert_pem",
			method:   http.MethodPost,
			suffix:   path,
			body:     `{}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "cert_pem is required",
		},
		{
			name:     "certificate OU maps to no role",
			method:   http.MethodPost,
			suffix:   path,
			body:     fmt.Sprintf(`{"cert_pem":%q}`, string(engineerPEM)),
			wantCode: http.StatusBadRequest,
			wantErr:  "operator cert rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := send(tt.method, tt.suffix, tt.body)
			if rec.Code != tt.wantCode {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantErr) {
				t.Fatalf("missing error code %q in body=%s", tt.wantErr, rec.Body.String())
			}
		})
	}
}

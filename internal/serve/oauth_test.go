// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/types/aicjwt"
)

// oauthTestAICCert issues an AIC certificate under the test CA and returns
// its PEM plus the subject private key.
func oauthTestAICCert(t *testing.T, srv *Server, caCert *x509.Certificate, caKey crypto.Signer) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := ca.SPKIHash(&key.PublicKey)
	sc := &ca.SignConfig{
		DB:             srv.getDB(),
		CAKey:          caKey,
		CACert:         caCert,
		CAName:         "test-ca",
		SubjectPubKey:  &key.PublicKey,
		CommonName:     "agent-oauth",
		Subject:        &pkix.Name{CommonName: "agent-oauth", OrganizationalUnit: []string{"gateway:agent"}},
		Validity:       24 * time.Hour,
		DefaultCountry: "CN",
		DefaultOrg:     "Test Org",
		Profile:        ca.ProfileAgentProxy,
		AIC: &ca.AICConfig{
			AgentId:        "agent-oauth",
			PrincipalUid:   ca.PrincipalUid{Version: 1, Realm: "r", Identifier: "oauth-user", KeyHash: keyHash},
			DelegationMode: ca.DelegationAuthorized,
			Capabilities:   []ca.Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
			DelegationAuthorization: &ca.DelegationAuthorization{
				Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "oauth test"},
				Nonce:              make([]byte, 32),
				Timestamp:          time.Now().Add(-time.Minute),
				RequestedLifetime:  3600,
				SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
			},
		},
	}
	res, err := ca.Sign(sc)
	if err != nil {
		t.Fatalf("sign AIC cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.CertDER})), key
}

func oauthFormPost(t *testing.T, srv http.Handler, m map[string]string, clientCert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	for k, v := range m {
		form.Set(k, v)
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientCert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestOAuthTokenX509Exchange(t *testing.T) {
	srv, handler, caCert, caKey := newTestServerWithCA(t)
	certPEM, key := oauthTestAICCert(t, srv, caCert, caKey)

	w := oauthFormPost(t, handler, map[string]string{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token":      certPEM,
		"subject_token_type": oauthTokenTypeX509Cert,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}
	var resp oauthTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" || resp.TokenType != TokenTypeBearer {
		t.Fatalf("bad token response: %+v", resp)
	}

	// The exchanged token must validate against the same CA trust root and
	// bind the same subject key (cnf.jkt).
	dec, err := aicjwt.Validate(resp.AccessToken, aicjwt.VerifyOptions{
		Now:              time.Now(),
		ExpectedIssuer:   oauthIssuerID,
		ExpectedAudience: []string{oauthIssuerID},
		IssuerKeys:       map[string]crypto.PublicKey{ca.SPKISHA256(caCert): caKey.Public()},
	})
	if err != nil {
		t.Fatalf("validate exchanged token: %v", err)
	}
	if len(dec.Capabilities) != 1 || dec.Capabilities[0].ID != "SELECT:*" {
		t.Fatalf("capabilities = %+v", dec.Capabilities)
	}
	// cnf.jkt must equal the certificate subject key thumbprint.
	_, pb, _, err := aicjwt.ParseCompact(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	var outer aicjwt.OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		t.Fatal(err)
	}
	if outer.Cnf == nil || outer.Cnf.Jkt == "" {
		t.Fatal("exchanged token missing cnf.jkt")
	}
	wantJkt, err := aicjwt.KeyHashOf(&key.PublicKey, "jkt")
	if err != nil {
		t.Fatal(err)
	}
	if outer.Cnf.Jkt != wantJkt {
		t.Fatalf("cnf.jkt = %q, want %q", outer.Cnf.Jkt, wantJkt)
	}
}

func TestOAuthTokenX509Exchange_WrongCA(t *testing.T) {
	srv, handler, caCert, caKey := newTestServerWithCA(t)
	certPEM, _ := oauthTestAICCert(t, srv, caCert, caKey)

	// Break the issuer/cert match by minting the subject under a different CA.
	otherCert, otherKey := newTestCA(t, "other-ca")
	_ = otherKey
	_ = certPEM

	// A cert from the "other" CA must be rejected.
	otherPEM, _ := oauthTestAICCert(t, srv, otherCert, otherKey)
	w := oauthFormPost(t, handler, map[string]string{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token":      otherPEM,
		"subject_token_type": oauthTokenTypeX509Cert,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign CA subject, got %d", w.Code)
	}
}

func TestOAuthTokenJWTBearer(t *testing.T) {
	_, handler, caCert, caKey := newTestServerWithCA(t)

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := ca.SPKIHash(&agentKey.PublicKey)
	da := &ca.DelegationAuthorization{
		Reason:            ca.Reason{ReasonCode: "ROTATION", Description: "oauth jwt-bearer"},
		Nonce:             make([]byte, 32),
		Timestamp:         time.Now().Add(-time.Minute),
		RequestedLifetime: 3600,
	}
	res, err := ca.SignJWT(&ca.SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: &agentKey.PublicKey, Validity: time.Hour,
		AIC: &ca.AICConfig{
			AgentId:                 "agent-oauth",
			PrincipalUid:            ca.PrincipalUid{Version: 1, Realm: "r", Identifier: "oauth-user", KeyHash: keyHash},
			DelegationMode:          ca.DelegationAuthorized,
			Capabilities:            []ca.Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
			DelegationAuthorization: da,
		},
	}, ca.JWTSignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Client authenticates with the AIC-JWT as client_assertion (RFC 7523)
	// and proves possession of the same key via mTLS.
	clientCert := leafCertForTest(t, agentKey)
	w := oauthFormPost(t, handler, map[string]string{
		"grant_type":            GrantTypeJWTBearer,
		"client_assertion_type": AssertionTypeJWT,
		"client_assertion":      res.Token,
	}, clientCert)
	if w.Code != http.StatusOK {
		t.Fatalf("jwt-bearer: %d %s", w.Code, w.Body.String())
	}
	var resp oauthTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" {
		t.Fatal("no access token issued")
	}
}

func TestOAuthTokenRequiresPoP(t *testing.T) {
	_, handler, caCert, caKey := newTestServerWithCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := ca.SPKIHash(&agentKey.PublicKey)
	res, err := ca.SignJWT(&ca.SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: &agentKey.PublicKey, Validity: time.Hour,
		AIC: &ca.AICConfig{
			AgentId:        "agent-oauth",
			PrincipalUid:   ca.PrincipalUid{Version: 1, Realm: "r", Identifier: "oauth-user", KeyHash: keyHash},
			DelegationMode: ca.DelegationAuthorized,
			Capabilities:   []ca.Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
			DelegationAuthorization: &ca.DelegationAuthorization{
				Reason:            ca.Reason{ReasonCode: "ROTATION", Description: "pop test"},
				Nonce:             make([]byte, 32),
				Timestamp:         time.Now().Add(-time.Minute),
				RequestedLifetime: 3600,
			},
		},
	}, ca.JWTSignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// No mTLS, no DPoP → cnf cannot be bound → reject.
	w := oauthFormPost(t, handler, map[string]string{
		"grant_type":            GrantTypeJWTBearer,
		"client_assertion_type": AssertionTypeJWT,
		"client_assertion":      res.Token,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (missing PoP), got %d", w.Code)
	}
}

// leafCertForTest creates a self-signed leaf bound to key (for mTLS PoP only).
func leafCertForTest(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "agent-oauth"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOAuthTokenMethodNotAllowed(t *testing.T) {
	srv, handler, _, _ := newTestServerWithCA(t)
	_ = srv
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/token", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

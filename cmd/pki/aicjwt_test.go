// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

func selfSignedECCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "aic-jwt-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func caConfigForTest(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey, caName string) *internal.Config {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600)
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)

	cfg := internal.DefaultConfig()
	cfg.Defaults.CA = caName
	cfg.CAs = map[string]internal.CAConfig{
		caName: {Cert: certPath, Key: keyPath},
	}
	return &cfg
}

func signTestToken(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, subjectKey *ecdsa.PublicKey) string {
	t.Helper()
	keyHash := ca.SPKIHash(subjectKey)
	res, err := ca.SignJWT(&ca.SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: subjectKey, Validity: time.Hour,
		AIC: &ca.AICConfig{
			AgentId:        "agent-jwt",
			PrincipalUid:   ca.PrincipalUid{Version: 1, Realm: "r", Identifier: "principal-a", KeyHash: keyHash},
			Capabilities:   []ca.Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
			DelegationMode: ca.DelegationAuthorized,
			DelegationAuthorization: &ca.DelegationAuthorization{
				Reason:         ca.Reason{ReasonCode: "ROTATION", Description: "test"},
				Nonce:          make([]byte, 32),
				Timestamp:      time.Now().Add(-time.Minute),
				RequestedLifetime: 3600,
			},
		},
	}, ca.JWTSignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

func TestBuildAICJWTResolver_AuthorizedMode(t *testing.T) {
	caCert, caKey := selfSignedECCA(t)
	cfg := caConfigForTest(t, caCert, caKey, "test-ca")

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := signTestToken(t, caCert, caKey, &agentKey.PublicKey)

	// Build an agent certificate matching the subject key to exercise the
	// dual-carrier coherence path.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "agent-jwt"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &agentKey.PublicKey, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	resolver := buildAICJWTResolver(cfg)

	// No mTLS → token alone authenticates.
	req := &http.Request{}
	result, err := resolver(token, req)
	if err != nil {
		t.Fatalf("resolver(token): %v", err)
	}
	if result.AICJWT == nil {
		t.Fatal("AICJWT identity missing")
	}
	if result.AICJWT.Principal.Realm != "r" || result.AICJWT.Principal.ID != "principal-a" {
		t.Fatalf("principal = %+v", result.AICJWT.Principal)
	}
	if len(result.AICJWT.Capabilities) != 1 || result.AICJWT.Capabilities[0] != "std/database-v1:SELECT:*" {
		t.Fatalf("capabilities = %v", result.AICJWT.Capabilities)
	}
	if result.AICJWT.Issuer != aicJWTIssuer {
		t.Fatalf("issuer = %q", result.AICJWT.Issuer)
	}

	// Matching mTLS certificate → passes.
	reqTLS := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{agentCert}}}
	if _, err := resolver(token, reqTLS); err != nil {
		t.Fatalf("resolver(token + matching cert): %v", err)
	}

	// Mismatched mTLS certificate → rejected (dual-carrier coherence).
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "other"}, NotAfter: time.Now().Add(time.Hour)}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherCert, _ := x509.ParseCertificate(otherDER)
	reqMismatch := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherCert}}}
	if _, err := resolver(token, reqMismatch); err == nil {
		t.Fatal("expected error for mTLS key mismatch")
	}
}

func TestBuildAICJWTResolver_GarbageToken(t *testing.T) {
	caCert, caKey := selfSignedECCA(t)
	cfg := caConfigForTest(t, caCert, caKey, "test-ca")
	resolver := buildAICJWTResolver(cfg)

	if _, err := resolver("not.a.jwt", &http.Request{}); err == nil {
		t.Fatal("garbage token must fail validation")
	}
	if _, err := resolver("", &http.Request{}); err == nil {
		t.Fatal("empty token must fail validation")
	}
}

func TestBuildAICJWTResolver_IssuerKeysFromAllCAs(t *testing.T) {
	caCert, caKey := selfSignedECCA(t)
	cfg := caConfigForTest(t, caCert, caKey, "test-ca")
	keys := caJWTIssuerKeys(cfg)
	if len(keys) != 1 {
		t.Fatalf("issuer keys = %d, want 1", len(keys))
	}
	if kid := ca.SPKISHA256(caCert); kid == "" {
		t.Fatal("empty kid")
	}
}
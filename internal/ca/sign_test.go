// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func newTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestGenerateKey(t *testing.T) {
	for _, kt := range []string{"ecdsa-p256", "ecdsa-p384"} {
		key, err := GenerateKey(kt)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if key == nil {
			t.Fatalf("%s: nil key", kt)
		}
	}
}

func TestSignTLSServer(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "test.example.com",
		SANs:       []string{"DNS:test.example.com", "DNS:www.example.com"},
		CRLBaseURL: "http://crl.test/pki",
		OCSPURL:    "http://ocsp.test:9080",
		Validity:   365 * 24 * time.Hour,
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	if result.SerialHex == "" {
		t.Fatal("empty serial")
	}
	if result.Cert.Subject.CommonName != "test.example.com" {
		t.Fatalf("expected test.example.com, got %q", result.Cert.Subject.CommonName)
	}
	if result.Cert.IsCA {
		t.Fatal("server cert should not be CA")
	}
	if len(result.Cert.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %d", len(result.Cert.DNSNames))
	}
}

// TestSignRequireTLSServerSAN verifies F11.1: when RequireTLSServerSAN is set,
// a TLS-server certificate with no subjectAltName is rejected (RFC 6125);
// otherwise it warn-and-continues (backward compatible). A SAN-bearing cert
// always passes.
func TestSignRequireTLSServerSAN(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	base := func() *SignConfig {
		return &SignConfig{
			DB:         d,
			CAKey:      caKey,
			CACert:     caCert,
			Profile:    ProfileTLSServer,
			CommonName: "nosan.example.com",
			Validity:   24 * time.Hour,
		}
	}

	// Default off: CN-only succeeds (warn-and-continue).
	if _, err := Sign(base()); err != nil {
		t.Fatalf("default (RequireTLSServerSAN=false): CN-only should warn-and-continue, got %v", err)
	}

	// Enforced: CN-only must fail.
	sc := base()
	sc.RequireTLSServerSAN = true
	if _, err := Sign(sc); err == nil {
		t.Fatal("RequireTLSServerSAN=true with no SAN should fail")
	}

	// Enforced + DNS SAN: succeeds.
	sc = base()
	sc.RequireTLSServerSAN = true
	sc.SANs = []string{"DNS:nosan.example.com"}
	if _, err := Sign(sc); err != nil {
		t.Fatalf("RequireTLSServerSAN with DNS SAN should succeed, got %v", err)
	}

	// Enforced + IP SAN (raw-IP service): succeeds.
	sc = base()
	sc.RequireTLSServerSAN = true
	sc.SANs = []string{"IP:10.0.0.1"}
	if _, err := Sign(sc); err != nil {
		t.Fatalf("RequireTLSServerSAN with IP SAN should succeed, got %v", err)
	}
}

func TestSignOCSPSigner(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileOCSPSigner,
		CommonName: "ocsp.test",
		Validity:   365 * 24 * time.Hour,
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	if result.SerialHex == "" {
		t.Fatal("empty serial")
	}
}

func TestParseCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr.test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "csr.test" {
		t.Fatalf("expected csr.test, got %q", csr.Subject.CommonName)
	}
}

// A CSR whose self-signature does not verify must be rejected by ParseCSR.
func TestParseCSRRejectsBadSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr.test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	mut := append([]byte(nil), csrDER...)
	mut[len(mut)-5] ^= 0x01
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: mut})

	if _, err := ParseCSR(csrPEM); err == nil {
		t.Fatal("expected ParseCSR to reject a CSR with a bad signature")
	}
}

func TestLoadSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	caCert, _ := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0644)

	loadedCert, loadedKey, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedCert == nil || loadedKey == nil {
		t.Fatal("nil cert or key")
	}
}

func TestCertToPEM(t *testing.T) {
	der := []byte("fake-der")
	pem := CertToPEM(der)
	if len(pem) == 0 {
		t.Fatal("empty PEM")
	}
}

func TestSignAgentProxy(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileAgentProxy,
		CommonName: "agent-1",
		Subject: &pkix.Name{
			CommonName:         "agent-1",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		OCSPURL:  "http://ocsp.test:9080",
		Validity: 365 * 24 * time.Hour,
		AIC: &AICConfig{
			AgentId:                 "agent-1",
			PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "admin@varwof.com", KeyHash: testAICKeyHash()},
			Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"}},
			DelegationAuthorization: testAICDelegation(),
		},
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign agent-proxy: %v", err)
	}

	// Verify AIC extension in the resulting cert
	aic, err := ParseAIC(result.Cert)
	if err != nil {
		t.Fatalf("ParseAIC: %v", err)
	}
	if aic == nil {
		t.Fatal("expected AIC extension in agent-proxy cert")
	}
	if aic.AgentId != "agent-1" {
		t.Fatalf("AgentId: expected agent-1, got %s", aic.AgentId)
	}
	if aic.PrincipalUid.Identifier != "admin@varwof.com" {
		t.Fatalf("PrincipalUid.Identifier: expected admin@varwof.com, got %s", aic.PrincipalUid.Identifier)
	}
	if len(aic.Capabilities) != 1 || aic.Capabilities[0].CapabilityId != "gateway:admin" {
		t.Fatalf("Capabilities: expected [gateway:admin], got %v", aic.Capabilities)
	}

	// Verify short-lived enforcement (max 1 hour)
	maxExpected := time.Hour
	actualValidity := result.Cert.NotAfter.Sub(result.Cert.NotBefore)
	if actualValidity > maxExpected+time.Minute {
		t.Fatalf("agent-proxy validity %v exceeds max %v", actualValidity, maxExpected)
	}

	// Verify OU and EKU
	if len(result.Cert.Subject.OrganizationalUnit) == 0 || result.Cert.Subject.OrganizationalUnit[0] != "gateway:admin" {
		t.Fatalf("OU: expected [gateway:admin], got %v", result.Cert.Subject.OrganizationalUnit)
	}
	hasClientAuth := false
	for _, eku := range result.Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Fatal("expected ExtKeyUsageClientAuth in agent-proxy cert")
	}
}

// TestSignAgentProxyMaxValidity verifies that agent-proxy validity cap is configurable
// (spec P1-B-09/25, P2-A-04: authorized mode ≤24h, default 1h).
func TestSignAgentProxyMaxValidity(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	base := func() *SignConfig {
		return &SignConfig{
			DB:         d,
			CAKey:      caKey,
			CACert:     caCert,
			Profile:    ProfileAgentProxy,
			CommonName: "agent-1",
			Subject: &pkix.Name{
				CommonName:         "agent-1",
				OrganizationalUnit: []string{"gateway:admin"},
			},
			OCSPURL:  "http://ocsp.test:9080",
			Validity: 365 * 24 * time.Hour,
			AIC: &AICConfig{
				AgentId:                 "agent-1",
				PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "admin@varwof.com", KeyHash: testAICKeyHash()},
				Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"}},
				DelegationAuthorization: testAICDelegation(),
			},
		}
	}

	t.Run("default 1h cap", func(t *testing.T) {
		sc := base()
		result, err := Sign(sc)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		got := result.Cert.NotAfter.Sub(result.Cert.NotBefore)
		if got > time.Hour+time.Minute {
			t.Fatalf("default validity %v exceeds 1h", got)
		}
	})

	t.Run("configured 6h cap", func(t *testing.T) {
		sc := base()
		sc.MaxAgentProxyValidity = 6 * time.Hour
		result, err := Sign(sc)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		got := result.Cert.NotAfter.Sub(result.Cert.NotBefore)
		if got > 6*time.Hour+time.Minute {
			t.Fatalf("configured validity %v exceeds 6h", got)
		}
		// And the requested 365d is capped to 6h (proving the limit works).
		if got < 5*time.Hour {
			t.Fatalf("expected validity near 6h cap, got %v", got)
		}
	})

	t.Run("MaxAgentProxyValidityLimit helper", func(t *testing.T) {
		var nilSC *SignConfig
		if got := nilSC.MaxAgentProxyValidityLimit(); got != DefaultAgentProxyMaxValidity {
			t.Fatalf("nil: want %v, got %v", DefaultAgentProxyMaxValidity, got)
		}
		if got := (&SignConfig{}).MaxAgentProxyValidityLimit(); got != DefaultAgentProxyMaxValidity {
			t.Fatalf("zero: want %v, got %v", DefaultAgentProxyMaxValidity, got)
		}
		sc := &SignConfig{MaxAgentProxyValidity: 24 * time.Hour}
		if got := sc.MaxAgentProxyValidityLimit(); got != 24*time.Hour {
			t.Fatalf("want 24h, got %v", got)
		}
	})
}

func TestSignAgentProxyWithPrincipalAuthorization(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileAgentProxy,
		CommonName: "agent-2",
		Subject: &pkix.Name{
			CommonName:         "agent-2",
			OrganizationalUnit: []string{"gateway:ops"},
		},
		Validity: 30 * 24 * time.Hour,
		AIC: &AICConfig{
			AgentId:                 "agent-2",
			PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "ops@varwof.com", KeyHash: testAICKeyHash()},
			Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:ops"}},
			DelegationAuthorization: testAICDelegation(),
		},
		PrincipalAuthorization: &PrincipalAuthorizationConfig{
			Grants: []Capability{
				{SchemeId: "gateway", CapabilityId: "gateway:ops"},
			},
		},
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign agent-proxy with principal authorization: %v", err)
	}

	// Verify PrincipalAuthorization extension
	pa, err := ParsePrincipalAuthorizationExtension(result.Cert.Extensions)
	if err != nil {
		t.Fatalf("ParsePrincipalAuthorizationExtension: %v", err)
	}
	if pa == nil {
		t.Fatal("expected PrincipalAuthorization extension in agent-proxy cert")
	}
	if len(pa.Grants) != 1 || pa.Grants[0].CapabilityId != "gateway:ops" {
		t.Fatalf("PrincipalAuthorization.Grants: expected [gateway:ops], got %v", pa.Grants)
	}
}

func TestSignAgentProxyMissingOU(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileAgentProxy,
		CommonName: "no-ou",
		Validity:   time.Hour,
	}

	_, err := Sign(sc)
	if err == nil {
		t.Fatal("expected error for missing OU in agent-proxy profile")
	}
}

func TestKeyToPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := KeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(pem) == 0 {
		t.Fatal("empty PEM")
	}
}

func TestSignCodeSigning(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileCodeSigning,
		CommonName: "codesign.test",
		Validity:   365 * 24 * time.Hour,
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	if result.SerialHex == "" {
		t.Fatal("empty serial")
	}
}

func TestSignWithSANs(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "multi.test",
		SANs:       []string{"DNS:a.test", "DNS:b.test", "IP:192.168.1.1"},
		Validity:   365 * 24 * time.Hour,
	}

	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Cert.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %d", len(result.Cert.DNSNames))
	}
	if len(result.Cert.IPAddresses) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(result.Cert.IPAddresses))
	}
}

func TestAddMustStaple(t *testing.T) {
	tmpl := &x509.Certificate{}
	addMustStaple(tmpl)
	if len(tmpl.ExtraExtensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(tmpl.ExtraExtensions))
	}
	ext := tmpl.ExtraExtensions[0]
	if !ext.Id.Equal(oidTLSFeature) {
		t.Errorf("expected OID %v, got %v", oidTLSFeature, ext.Id)
	}
	if !bytes.Contains(ext.Value, []byte{5}) {
		t.Errorf("extension value should contain status_request (5)")
	}
}

func TestParseOID(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"1.2.3.4", "1.2.3.4", false},
		{"1.2", "1.2", false},
		{"", "", true},
		{"abc", "", true},
	}
	for _, tt := range tests {
		got, err := parseOID(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("expected error for %q", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error for %q: %v", tt.input, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("parseOID(%q) = %s, want %s", tt.input, got.String(), tt.want)
		}
	}
}

func TestBuildGeneralName(t *testing.T) {
	tests := []struct {
		tag  int
		data []byte
		want byte
	}{
		{1, []byte("a@b.com"), 0x81},
		{2, []byte("example.com"), 0x82},
		{4, []byte("der-bytes"), 0xA4},
		{6, []byte("https://x"), 0x86},
	}
	for _, tt := range tests {
		got := buildGeneralName(tt.tag, tt.data)
		if len(got) == 0 || got[0] != tt.want {
			t.Errorf("buildGeneralName(%d, %q) = 0x%02x..., want 0x%02x", tt.tag, string(tt.data), got[0], tt.want)
		}
	}
}

func TestAsn1DERSequence(t *testing.T) {
	// short content (< 128 bytes)
	short := []byte{0x01}
	result := asn1DERSequence(short)
	if result[0] != 0x30 || result[1] != 1 {
		t.Errorf("short: expected 0x30 0x01, got 0x%02x 0x%02x", result[0], result[1])
	}

	// empty content → 0x30 0x00
	empty := []byte{}
	result = asn1DERSequence(empty)
	if result[0] != 0x30 || result[1] != 0x00 {
		t.Errorf("empty: expected 0x30 0x00, got 0x%02x 0x%02x", result[0], result[1])
	}

	// exactly 127 bytes → short form length
	content127 := make([]byte, 127)
	result = asn1DERSequence(content127)
	if result[0] != 0x30 || result[1] != 0x7f {
		t.Errorf("127 bytes: expected 0x30 0x7f, got 0x%02x 0x%02x", result[0], result[1])
	}

	// 128 bytes → long form length 0x30 0x81 0x80
	content128 := make([]byte, 128)
	result = asn1DERSequence(content128)
	if result[0] != 0x30 || result[1] != 0x81 || result[2] != 0x80 {
		t.Errorf("128 bytes: expected 0x30 0x81 0x80, got 0x%02x 0x%02x 0x%02x", result[0], result[1], result[2])
	}
}

func TestSign_Rule1_AIC_MustBeEndEntity(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	// Rule 1: AIC certificate MUST be an end entity
	// agent-proxy profile should not produce IsCA=true
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            testDB,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: key.Public(),
		Profile:       ProfileAgentProxy,
		CommonName:    "test-agent",
		Subject:       &pkix.Name{CommonName: "test-agent", OrganizationalUnit: []string{"gateway:admin"}},
		Validity:      1 * time.Hour,
		AIC: &AICConfig{
			AgentId:                 "agent-1",
			PrincipalUid:            PrincipalUid{Version: 1, Realm: "r", Identifier: "i", KeyHash: testAICKeyHash()},
			Capabilities:            []Capability{{SchemeId: "s", CapabilityId: "c"}},
			DelegationAuthorization: testAICDelegation(),
		},
	}
	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if result.Cert.IsCA {
		t.Fatal("Rule 1 violated: agent certificate has IsCA=true")
	}
}

func TestSign_Rule2_PrincipalAuthValidation(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	// Rule 2: PrincipalAuthorization grants must cover AIC capabilities
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            testDB,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: key.Public(),
		Profile:       ProfileAgentProxy,
		CommonName:    "test-agent",
		Subject:       &pkix.Name{CommonName: "test-agent", OrganizationalUnit: []string{"gateway:admin"}},
		Validity:      1 * time.Hour,
		AIC: &AICConfig{
			AgentId:      "agent-1",
			PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i", KeyHash: testAICKeyHash()},
			Capabilities: []Capability{
				{SchemeId: "http", CapabilityId: "http:read"},
				{SchemeId: "http", CapabilityId: "http:write"},
			},
			DelegationAuthorization: testAICDelegation(),
		},
		PrincipalAuthorization: &PrincipalAuthorizationConfig{
			Grants: []Capability{
				{SchemeId: "http", CapabilityId: "http:read"},
			},
		},
	}
	_, err := Sign(sc)
	if err == nil {
		t.Fatal("Rule 2 violated: should reject when grants don't cover all capabilities")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not covered by principal authorization grants")) {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now add the missing grant — should succeed
	sc.PrincipalAuthorization.Grants = append(sc.PrincipalAuthorization.Grants,
		Capability{SchemeId: "http", CapabilityId: "http:write"})
	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign with complete grants failed: %v", err)
	}
	if result.Cert == nil {
		t.Fatal("expected non-nil cert")
	}
}

func TestSign_Rule3_AKI_MatchesIssuerSKI(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result, err := Sign(&SignConfig{
		DB:            testDB,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: key.Public(),
		Profile:       ProfileTLSClient,
		CommonName:    "test-client",
		Validity:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	// Rule 3: AKI should match issuer SKI
	if len(result.Cert.AuthorityKeyId) == 0 {
		t.Fatal("expected non-empty AKI")
	}
	if len(caCert.SubjectKeyId) == 0 {
		t.Fatal("CA has no SKI")
	}
	if !bytesEqual(result.Cert.AuthorityKeyId, caCert.SubjectKeyId) {
		t.Fatalf("Rule 3 violated: AKI %x does not match issuer SKI %x",
			result.Cert.AuthorityKeyId, caCert.SubjectKeyId)
	}
}

func TestSignVPNProfiles(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	cases := []struct {
		name    string
		profile Profile
		wantEKS []x509.ExtKeyUsage
	}{
		{"vpn-client", ProfileVPNClient, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"vpn-server", ProfileVPNServer, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			result, err := Sign(&SignConfig{
				DB:            testDB,
				CAKey:         caKey,
				CACert:        caCert,
				CAName:        "test-ca",
				SubjectPubKey: key.Public(),
				Profile:       tc.profile,
				CommonName:    "vpn-test",
				Validity:      24 * time.Hour,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			got := map[x509.ExtKeyUsage]bool{}
			for _, e := range result.Cert.ExtKeyUsage {
				got[e] = true
			}
			for _, want := range tc.wantEKS {
				if !got[want] {
					t.Errorf("profile %s: missing EKU %v (got %v)", tc.profile, want, result.Cert.ExtKeyUsage)
				}
			}
		})
	}
}

func TestSignManagementScopeOID(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)
	scopeOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1}

	// OID scope must be written for every management profile carrying a scope,
	// matching the SAN URI dual-write (unified for m-superadmin and m-admin).
	for _, profile := range []Profile{ProfileMSuperAdmin, ProfileMAdmin, ProfileMOperator} {
		profile := profile
		t.Run(string(profile), func(t *testing.T) {
			result, err := Sign(&SignConfig{
				DB:         d,
				CAKey:      caKey,
				CACert:     caCert,
				Profile:    profile,
				CommonName: "scope-admin",
				Scope:      "Client CA",
				CAScope:    []string{"Client CA"},
				Validity:   180 * 24 * time.Hour,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			var oidVal []byte
			for _, ext := range result.Cert.Extensions {
				if ext.Id.Equal(scopeOID) {
					oidVal = ext.Value
					break
				}
			}
			if string(oidVal) != "Client CA" {
				t.Errorf("profile %s: OID scope = %q, want %q", profile, oidVal, "Client CA")
			}
			uriFound := false
			for _, u := range result.Cert.URIs {
				if u.Scheme == "urn" && u.Opaque == "pki:ca:Client CA" {
					uriFound = true
				}
			}
			if !uriFound {
				t.Errorf("profile %s: missing SAN URI scope urn:pki:ca:Client CA", profile)
			}
			if got := ExtractAdminScope(result.Cert); got != "Client CA" {
				t.Errorf("profile %s: ExtractAdminScope = %q, want %q", profile, got, "Client CA")
			}
		})
	}

	// No scope -> no OID extension
	result, err := Sign(&SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileMAdmin,
		CommonName: "plain-admin",
		Validity:   180 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	for _, ext := range result.Cert.Extensions {
		if ext.Id.Equal(scopeOID) {
			t.Fatalf("unexpected OID scope extension on unscoped admin cert")
		}
	}
}

func TestSignSkipDB(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "skipdb.example.com",
		Validity:   24 * time.Hour,
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	n, err := d.CountCertsByCA("Test CA", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 cert written, got %d", n)
	}

	sc2 := &SignConfig{
		DB:         d,
		SkipDB:     true,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "skipdb2.example.com",
		Validity:   24 * time.Hour,
	}
	res, err := Sign(sc2)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := d.CountCertsByCA("Test CA", "")
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 1 {
		t.Fatalf("SkipDB should not write to DB, got %d certs", n2)
	}
	if res.Record == nil {
		t.Fatal("SkipDB result must carry the CertRecord for buffered persistence")
	}
	if res.Record.SerialNumber != res.SerialHex {
		t.Fatalf("record serial %q != result serial %q", res.Record.SerialNumber, res.SerialHex)
	}
	if res.Record.CommonName != "skipdb2.example.com" {
		t.Fatalf("record CN mismatch: %q", res.Record.CommonName)
	}
	if res.Record.Status != "V" {
		t.Fatalf("record status = %q, want V", res.Record.Status)
	}
}

func TestSignRequirePolicyFailClosed(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	// Without RequirePolicy: warn-and-continue (backward compatible).
	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "nopolicy.example.com",
		Validity:   24 * time.Hour,
	}
	if _, err := Sign(sc); err != nil {
		t.Fatalf("without RequirePolicy Sign should succeed, got %v", err)
	}

	// M4 fix: with RequirePolicy and no policy loaded → hard error.
	sc.RequirePolicy = true
	if _, err := Sign(sc); err == nil {
		t.Fatal("RequirePolicy=true with no policy should fail closed")
	}
}

func TestSignRequirePolicyWithPolicyOK(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	// M4: RequirePolicy=true with a loaded policy passes.
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		Profile:       ProfileTLSServer,
		CommonName:    "ok.example.com",
		Validity:      24 * time.Hour,
		RequirePolicy: true,
		Policy: &Policy{Rules: []PolicyRule{{
			AllowedCNs: []string{"*.example.com"},
		}}},
	}
	if _, err := Sign(sc); err != nil {
		t.Fatalf("RequirePolicy with policy should succeed, got %v", err)
	}

	// A CN outside the policy is still rejected.
	sc.CommonName = "evil.com"
	if _, err := Sign(sc); err == nil {
		t.Fatal("policy should reject CN outside allowed list")
	}
}

func TestSignIdentityUserProfile(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := &pkix.Name{CommonName: "张三"}
	result, err := Sign(&SignConfig{
		DB:            testDB,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: key.Public(),
		Profile:       ProfileIdentityUser,
		CommonName:    "张三",
		Subject:       subj,
		Validity:      365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	cert := result.Cert
	if cert.Subject.CommonName != "张三" {
		t.Fatalf("CN = %q, want 张三", cert.Subject.CommonName)
	}
	eku := map[x509.ExtKeyUsage]bool{}
	for _, e := range cert.ExtKeyUsage {
		eku[e] = true
	}
	if !eku[x509.ExtKeyUsageEmailProtection] || !eku[x509.ExtKeyUsageClientAuth] {
		t.Fatalf("identity-user missing EmailProtection/ClientAuth EKU: %v", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Fatal("identity-user must not be a CA cert")
	}
}

func TestSignIdentityUserWithPrincipalAuth(t *testing.T) {
	caCert, caKey := newTestCA(t)
	testDB := newTestDB(t)
	defer testDB.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := &pkix.Name{CommonName: "张三"}
	pa := &PrincipalAuthorizationConfig{Grants: []Capability{
		{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"},
	}}
	result, err := Sign(&SignConfig{
		DB:                     testDB,
		CAKey:                  caKey,
		CACert:                 caCert,
		CAName:                 "test-ca",
		SubjectPubKey:          key.Public(),
		Profile:                ProfileIdentityUser,
		CommonName:             "张三",
		Subject:                subj,
		Validity:               365 * 24 * time.Hour,
		PrincipalAuthorization: pa,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	ext, err := ParsePrincipalAuthorizationExtension(result.Cert.Extensions)
	if err != nil {
		t.Fatalf("ParsePrincipalAuthorizationExtension: %v", err)
	}
	if ext == nil {
		t.Fatal("expected PA extension on identity-user cert")
	}
	if len(ext.Grants) != 1 || ext.Grants[0].FullID() != "varwof-gateway-v1:gateway:read" {
		t.Fatalf("unexpected PA grants: %+v", ext.Grants)
	}
}

// TestSignEd25519CAKey verifies that Sign() works with an Ed25519 CA key:
// the SignatureAlgorithm must be PureEd25519 (not forced to ECDSAWithSHA256).
func TestSignEd25519CAKey(t *testing.T) {
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ed25519 Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	d := newTestDB(t)
	result, err := Sign(&SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "ed25519.example.com",
		SANs:       []string{"DNS:ed25519.example.com"},
		Validity:   24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign with ed25519 CA key: %v", err)
	}
	if result.Cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatalf("expected PureEd25519, got %v", result.Cert.SignatureAlgorithm)
	}
	if err := result.Cert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("ed25519 signature check: %v", err)
	}
}

// TestSignDoesNotMutateConfig verifies Sign() operates on a copy: a caller
// reusing the same *SignConfig must not observe lazy Policy / PrincipalAuthorization
// mutation (cross-goroutine race + non-idempotence).
func TestSignDoesNotMutateConfig(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)
	// A policy file forces the lazy `sc.Policy = p` load inside Sign(); without
	// the local copy this would mutate the caller's struct.
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "rules": [
    {"allowed_cns": ["*.example.com"]}
  ]
}`), 0600); err != nil {
		t.Fatal(err)
	}
	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "test.example.com",
		SANs:       []string{"DNS:test.example.com"},
		Validity:   24 * time.Hour,
		PolicyFile: policyPath,
	}
	if _, err := Sign(sc); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sc.Policy != nil {
		t.Fatal("Sign mutated caller's SignConfig.Policy")
	}
	if sc.PrincipalAuthorization != nil {
		t.Fatal("Sign mutated caller's SignConfig.PrincipalAuthorization")
	}
}

// TestSignCAScopeSurvivesDirNameSAN verifies the CAScope URI SANs are not lost
// when a DirName SAN forces the manual SAN extension path (parseSANs clears
// tmpl.URIs).
func TestSignCAScopeSurvivesDirNameSAN(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)
	sc := &SignConfig{
		DB:         d,
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileRootCA,
		CommonName: "scoped",
		Validity:   24 * time.Hour,
		CAScope:    []string{"scope-a", "scope-b"},
		SANs:       []string{"DirName:CN=intermediate,O=Varwof", "DNS:extra.example.com"},
	}
	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var foundScope int
	for _, u := range result.Cert.URIs {
		switch u.Opaque {
		case "pki:ca:scope-a", "pki:ca:scope-b":
			foundScope++
		}
	}
	if foundScope != 2 {
		t.Fatalf("expected both CAScope URIs on cert, got %d (URIs=%v)", foundScope, result.Cert.URIs)
	}
	// The manual SAN extension (DirName + DNS) must still be present and valid.
	var hasDirName bool
	for _, e := range result.Cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			hasDirName = true
		}
	}
	if !hasDirName {
		t.Fatal("expected a SAN extension on the cert")
	}
}

// L17: even in SkipDB mode (no DB, so no ErrDuplicateSerial retry), the
// in-process guard must keep serials unique across a burst of concurrent
// issuers. Previously SkipDB mode had no uniqueness enforcement at all.
func TestSignSkipDBSerialUniquenessL17(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	const n = 200
	serials := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sc := &SignConfig{
				DB:         d,
				SkipDB:     true,
				CAKey:      caKey,
				CACert:     caCert,
				Profile:    ProfileTLSServer,
				CommonName: fmt.Sprintf("skipdb-%d", i),
				Validity:   24 * time.Hour,
			}
			res, err := Sign(sc)
			if err != nil {
				t.Errorf("Sign(SkipDB): %v", err)
				return
			}
			serials <- res.SerialHex
		}(i)
	}
	wg.Wait()
	close(serials)

	seen := make(map[string]struct{}, n)
	for s := range serials {
		if s == "" {
			t.Fatal("empty serial from SkipDB sign")
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate serial %q issued in SkipDB mode (L17 guard failed)", s)
		}
		seen[s] = struct{}{}
	}
}

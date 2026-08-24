package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ─── ParsePrincipalUid ────────────────────────────────────────────

func TestParsePrincipalUid_Valid(t *testing.T) {
	keyHash := make([]byte, 32)
	for i := range keyHash {
		keyHash[i] = byte(i)
	}
	b64 := base64.RawURLEncoding.EncodeToString(keyHash)
	s := "varwof:alice@" + "example.com:" + b64

	uid, err := ParsePrincipalUid(s)
	if err != nil {
		t.Fatalf("ParsePrincipalUid: %v", err)
	}
	if uid.Realm != "varwof" {
		t.Fatalf("expected realm varwof, got %s", uid.Realm)
	}
	if uid.Identifier != "alice@"+"example.com" {
		t.Fatalf("expected identifier alice@example.com, got %s", uid.Identifier)
	}
	if len(uid.KeyHash) != 32 {
		t.Fatalf("expected 32-byte keyHash, got %d", len(uid.KeyHash))
	}
}

func TestParsePrincipalUid_RoundTrip(t *testing.T) {
	orig := PrincipalUid{
		Version:    1,
		Realm:      "test",
		Identifier: "user@test.com",
		KeyHash:    make([]byte, 32),
	}
	s := orig.String()
	parsed, err := ParsePrincipalUid(s)
	if err != nil {
		t.Fatalf("ParsePrincipalUid: %v", err)
	}
	if parsed.Realm != orig.Realm || parsed.Identifier != orig.Identifier {
		t.Fatalf("mismatch: %+v vs %+v", orig, parsed)
	}
}

func TestParsePrincipalUid_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"only-one-part",
		"two:parts",
		":::",
	}
	for _, s := range cases {
		_, err := ParsePrincipalUid(s)
		if err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestParsePrincipalUid_InvalidBase64(t *testing.T) {
	_, err := ParsePrincipalUid("realm:id:!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParsePrincipalUid_WrongKeyHashLength(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString(make([]byte, 65)) // > 64 bytes
	_, err := ParsePrincipalUid("realm:id:" + b64)
	if err == nil {
		t.Fatal("expected error for 65-byte keyHash")
	}
	// 16 bytes is now valid at parse level (SIZE(1..64), algo-dependent).
	b64b := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := ParsePrincipalUid("realm:id:" + b64b); err != nil {
		t.Fatalf("unexpected error for 16-byte keyHash: %v", err)
	}
}

func TestParsePrincipalUid_RealmIdentifierBounds(t *testing.T) {
	fp := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cases := []string{
		":id:" + fp,
		strings.Repeat("r", 129) + ":id:" + fp,
		"realm::" + fp,
		"realm:" + strings.Repeat("i", 257) + ":" + fp,
	}
	for _, s := range cases {
		_, err := ParsePrincipalUid(s)
		if err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

// ─── MakePrincipalUidFromCert ─────────────────────────────────────

func TestMakePrincipalUidFromCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	uid := MakePrincipalUidFromCert("prod", "agent-1", cert)
	if uid.Version != 1 {
		t.Fatalf("expected version 1, got %d", uid.Version)
	}
	if uid.Realm != "prod" {
		t.Fatalf("expected realm prod, got %s", uid.Realm)
	}
	if uid.Identifier != "agent-1" {
		t.Fatalf("expected identifier agent-1, got %s", uid.Identifier)
	}

	// KeyHash should be SPKI SHA-256, not certificate DER SHA-256
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	expected := sha256.Sum256(pubBytes)
	if len(uid.KeyHash) != 32 {
		t.Fatalf("expected 32-byte keyHash")
	}
	for i := range uid.KeyHash {
		if uid.KeyHash[i] != expected[i] {
			t.Fatalf("keyHash mismatch at byte %d", i)
		}
	}
}

func TestMakePrincipalUidFromCert_String(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	uid := MakePrincipalUidFromCert("r", "i", cert)
	s := uid.String()
	if s == ":" {
		t.Fatal("expected non-empty string")
	}
	// Should be parseable
	parsed, err := ParsePrincipalUid(s)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if parsed.Realm != "r" {
		t.Fatalf("expected realm r, got %s", parsed.Realm)
	}
}

// ─── ValidateConstraints ──────────────────────────────────────────

func TestValidateConstraints_WrongNewKeyHashLength(t *testing.T) {
	token := &RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1, 2, 3},
		NewKeyHash:     make([]byte, 16), // wrong length
		Timestamp:      time.Now(),
		Nonce:          make([]byte, 16),
		ValidityPeriod: 300,
	}
	err := token.ValidateConstraints()
	if err == nil {
		t.Fatal("expected error for 16-byte newKeyHash")
	}
}

func TestValidateConstraints_WrongNonceLength(t *testing.T) {
	token := &RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1, 2, 3},
		NewKeyHash:     make([]byte, 32),
		Timestamp:      time.Now(),
		Nonce:          make([]byte, 8), // wrong length
		ValidityPeriod: 300,
	}
	err := token.ValidateConstraints()
	if err == nil {
		t.Fatal("expected error for 8-byte nonce")
	}
}

// ─── CheckPermission ──────────────────────────────────────────────

func TestCheckPermission_ExactMatch(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "tcp-proxy"},
		},
	}
	ok, err := aic.CheckPermission("tcp-proxy")
	if err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}
}

func TestCheckPermission_NoMatch(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "tcp-proxy"},
		},
	}
	ok, err := aic.CheckPermission("http-proxy")
	if err != nil || ok {
		t.Fatalf("expected no match, got ok=%v err=%v", ok, err)
	}
}

// ─── HasProtocol ──────────────────────────────────────────────────

func TestHasProtocol_Found(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1"},
		},
	}
	if !aic.HasProtocol("varwof-gateway-v1") {
		t.Fatal("expected true")
	}
}

func TestHasProtocol_NotFound(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{},
	}
	if aic.HasProtocol("varwof-gateway-v1") {
		t.Fatal("expected false")
	}
}

// ─── Principal ────────────────────────────────────────────────────

func TestPrincipal(t *testing.T) {
	aic := &AIC{
		PrincipalUid: PrincipalUid{
			Realm:      "r",
			Identifier: "i",
			KeyHash:    make([]byte, 32),
		},
	}
	p := aic.Principal()
	if p == "" || p == ":" {
		t.Fatalf("expected non-empty principal, got %s", p)
	}
	// String() returns "realm:identifier:keyFingerprint"
	if !strings.HasPrefix(p, "r:i:") {
		t.Fatalf("expected prefix 'r:i:', got %s", p)
	}
}

func TestPrincipal_Empty(t *testing.T) {
	aic := &AIC{}
	p := aic.Principal()
	// PrincipalUid.String() on zero-value returns "::" (empty key hash)
	if p != "::" {
		t.Fatalf("expected '::', got %q", p)
	}
}

// ─── ParseRevokeReason ────────────────────────────────────────────

func TestParseRevokeReason_Valid(t *testing.T) {
	reasons := map[string]int{
		"unspecified":  0,
		"keyCompromise": 1,
		"cACompromise": 2,
		"superseded":   4,
	}
	for name, expected := range reasons {
		r, err := ParseRevokeReason(name)
		if err != nil {
			t.Fatalf("ParseRevokeReason(%q): %v", name, err)
		}
		if r != expected {
			t.Fatalf("expected %d, got %d", expected, r)
		}
	}
}

func TestParseRevokeReason_Empty(t *testing.T) {
	r, err := ParseRevokeReason("")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if r != 0 {
		t.Fatalf("expected 0, got %d", r)
	}
}

func TestParseRevokeReason_Invalid(t *testing.T) {
	_, err := ParseRevokeReason("not-a-reason")
	if err == nil {
		t.Fatal("expected error")
	}
}

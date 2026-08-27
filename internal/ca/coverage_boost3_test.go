// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// ─── policy.go: globMatch ────────────────────────────────────────

func TestGlobMatch_Star(t *testing.T) {
	if !globMatch("anything", "*") {
		t.Fatal("* should match everything")
	}
}

func TestGlobMatch_Exact(t *testing.T) {
	if !globMatch("foo.example.com", "foo.example.com") {
		t.Fatal("exact match should work")
	}
	if globMatch("bar.example.com", "foo.example.com") {
		t.Fatal("non-match should fail")
	}
}

func TestGlobMatch_PrefixSuffix(t *testing.T) {
	if !globMatch("foo.example.com", "foo*.com") {
		t.Fatal("prefix*suffix should match")
	}
	if globMatch("bar.example.org", "foo*.com") {
		t.Fatal("wrong suffix should not match")
	}
	if globMatch("bar.example.com", "foo*.com") {
		t.Fatal("wrong prefix should not match")
	}
}

func TestGlobMatch_NoWildcard(t *testing.T) {
	if globMatch("anything", "no-wildcard") {
		t.Fatal("non-wildcard pattern should only match exact")
	}
}

func TestGlobMatch_MultipleParts(t *testing.T) {
	// M13 fix: multi-wildcard patterns now match correctly.
	if !globMatch("a*b*c", "a*b*c") {
		t.Fatal("multi-wildcard should match literal '*'-containing value")
	}
	if !globMatch("a1b2c", "a*b*c") {
		t.Fatal("multi-wildcard should match segments")
	}
	if globMatch("a1b2", "a*b*c") {
		t.Fatal("missing last segment should not match")
	}
}

func TestGlobMatch_CaseInsensitive(t *testing.T) {
	// M13 fix: DNS names are case-insensitive — deny rules must catch variants.
	if !globMatch("ATTACKER.EXAMPLE.COM", "*.example.com") {
		t.Fatal("uppercase hostname must match lowercase wildcard deny rule")
	}
	if !globMatch("Sub.Example.com", "*.example.com") {
		t.Fatal("mixed-case hostname must match wildcard")
	}
}

// ─── policy.go: matchGlobList ────────────────────────────────────

func TestMatchGlobList_EmptyAllowed(t *testing.T) {
	if !matchGlobList("foo", nil, nil) {
		t.Fatal("empty allowed list should match everything")
	}
}

func TestMatchGlobList_Allowed(t *testing.T) {
	if !matchGlobList("foo.example.com", []string{"foo*.com"}, nil) {
		t.Fatal("should match allowed pattern")
	}
	if matchGlobList("bar.example.com", []string{"foo*.com"}, nil) {
		t.Fatal("should not match non-matching pattern")
	}
}

func TestMatchGlobList_Denied(t *testing.T) {
	if matchGlobList("foo.example.com", nil, []string{"foo*"}) {
		t.Fatal("should be denied")
	}
	if !matchGlobList("bar.example.com", nil, []string{"foo*"}) {
		t.Fatal("should not be denied by non-matching pattern")
	}
}

func TestMatchGlobList_AllowedAndDenied(t *testing.T) {
	allowed := []string{"*.example.com"}
	denied := []string{"evil.example.com"}
	if !matchGlobList("good.example.com", allowed, denied) {
		t.Fatal("should match allowed and not be denied")
	}
	if matchGlobList("evil.example.com", allowed, denied) {
		t.Fatal("should be denied")
	}
}

// ─── policy.go: matchRule ────────────────────────────────────────

func TestMatchRule_Basic(t *testing.T) {
	sc := &SignConfig{CommonName: "test.example.com", Profile: ProfileTLSServer}
	rule := PolicyRule{AllowedCNs: []string{"test.example.com"}}
	if !matchRule(sc, rule) {
		t.Fatal("should match")
	}
}

func TestMatchRule_ProfileMismatch(t *testing.T) {
	sc := &SignConfig{CommonName: "test.example.com", Profile: ProfileTLSServer}
	rule := PolicyRule{AllowedProfiles: []string{"client"}}
	if matchRule(sc, rule) {
		t.Fatal("should not match profile mismatch")
	}
}

func TestMatchRule_KeyTypeMismatch(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, KeyType: "ecdsa-p256"}
	rule := PolicyRule{AllowedKeyTypes: []string{"rsa-2048"}}
	if matchRule(sc, rule) {
		t.Fatal("should not match key type mismatch")
	}
}

func TestMatchRule_KeyTypeDefault(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer} // KeyType empty
	rule := PolicyRule{AllowedKeyTypes: []string{"ecdsa-p256"}}
	if !matchRule(sc, rule) {
		t.Fatal("default key type should be ecdsa-p256")
	}
}

func TestMatchRule_CAMismatch(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, CAName: "ca-a"}
	rule := PolicyRule{AllowedCAs: []string{"ca-b"}}
	if matchRule(sc, rule) {
		t.Fatal("should not match CA mismatch")
	}
}

func TestMatchRule_MaxValidityExceeded(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, Validity: 400 * 24 * time.Hour}
	rule := PolicyRule{MaxValidityDays: 365}
	if matchRule(sc, rule) {
		t.Fatal("should not match validity exceeded")
	}
}

func TestMatchRule_MaxValidityOK(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, Validity: 30 * 24 * time.Hour}
	rule := PolicyRule{MaxValidityDays: 365}
	if !matchRule(sc, rule) {
		t.Fatal("should match validity within limit")
	}
}

func TestMatchRule_SANMismatch(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, SANs: []string{"bad.example.com"}}
	rule := PolicyRule{AllowedSANs: []string{"good.example.com"}}
	if matchRule(sc, rule) {
		t.Fatal("should not match SAN mismatch")
	}
}

// ─── policy.go: CheckPolicy ──────────────────────────────────────

func TestCheckPolicy_NilPolicy(t *testing.T) {
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer}
	if err := CheckPolicy(sc); err != nil {
		t.Fatalf("nil policy should pass: %v", err)
	}
}

func TestCheckPolicy_NoMatch(t *testing.T) {
	policy := &Policy{Rules: []PolicyRule{
		{AllowedCNs: []string{"other.example.com"}},
	}}
	sc := &SignConfig{CommonName: "test", Profile: ProfileTLSServer, Policy: policy}
	if err := CheckPolicy(sc); err == nil {
		t.Fatal("expected error for no matching rule")
	}
}

func TestCheckPolicy_Match(t *testing.T) {
	policy := &Policy{Rules: []PolicyRule{
		{AllowedCNs: []string{"*.example.com"}},
	}}
	sc := &SignConfig{CommonName: "test.example.com", Profile: ProfileTLSServer, Policy: policy}
	if err := CheckPolicy(sc); err != nil {
		t.Fatalf("should match: %v", err)
	}
}

// ─── policy.go: LoadPolicy ───────────────────────────────────────

func TestLoadPolicy_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(`{"rules":[{"allowed_cns":["test"]}]}`), 0644)
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	if _, err := LoadPolicy("/nonexistent/policy.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPolicy_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(`bad json`), 0644)
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadPolicy_EmptyRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(`{"rules":[]}`), 0644)
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("expected error for empty rules")
	}
}

// ─── policy.go: DefaultPolicyPath ────────────────────────────────

func TestDefaultPolicyPath(t *testing.T) {
	got := DefaultPolicyPath("/etc/pki")
	if filepath.ToSlash(got) != "/etc/pki/policy.json" {
		t.Fatalf("expected /etc/pki/policy.json, got %s", filepath.ToSlash(got))
	}
}

// ─── import_ca.go: isRootCA ──────────────────────────────────────

func TestIsRootCA_SelfSigned(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA", Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	if !isRootCA(cert) {
		t.Fatal("self-signed CA should be detected as root")
	}
}

func TestIsRootCA_Intermediate(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)
	if isRootCA(intCert) {
		t.Fatal("intermediate CA should not be detected as root")
	}
}

func TestIsRootCA_NonCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	if isRootCA(cert) {
		t.Fatal("non-CA cert should not be detected as root")
	}
}

// ─── import_ca.go: pubKeyAlgorithm ───────────────────────────────

func TestPubKeyAlgorithm_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got := pubKeyAlgorithm(&key.PublicKey)
	if got != "ecdsa-p256" {
		t.Fatalf("expected ecdsa-p256, got %s", got)
	}
}

func TestPubKeyAlgorithm_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	got := pubKeyAlgorithm(&key.PublicKey)
	if got != "rsa-4096" {
		t.Fatalf("expected rsa-4096, got %s", got)
	}
}

func TestPubKeyAlgorithm_Unknown(t *testing.T) {
	got := pubKeyAlgorithm("not-a-key")
	if got == "" {
		t.Fatal("expected non-empty string for unknown type")
	}
}

// ─── import_ca.go: verifyKeyPair ─────────────────────────────────

func TestVerifyKeyPair_Match(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyKeyPair(&key.PublicKey, key); err != nil {
		t.Fatalf("matching key pair should pass: %v", err)
	}
}

func TestVerifyKeyPair_Mismatch(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyKeyPair(&key1.PublicKey, key2); err == nil {
		t.Fatal("mismatched key pair should fail")
	}
}

// ─── buffer.go ───────────────────────────────────────────────────

func TestDefaultPersistConfig(t *testing.T) {
	cfg := DefaultPersistConfig()
	if cfg.Mode != PersistRealtime {
		t.Fatalf("expected realtime, got %d", cfg.Mode)
	}
	if cfg.BatchSize != 100 || cfg.QueueSize != 10000 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestParsePersistConfig(t *testing.T) {
	tests := []struct {
		input string
		want  PersistMode
	}{
		{"batch", PersistBatch},
		{"async", PersistAsync},
		{"realtime", PersistRealtime},
		{"", PersistRealtime},
		{"unknown", PersistRealtime},
	}
	for _, tt := range tests {
		got := ParsePersistConfig(tt.input)
		if got != tt.want {
			t.Errorf("ParsePersistConfig(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestNewMemoryBuffer_RealtimeMode(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistRealtime, BatchSize: 10, QueueSize: 100}
	buf, err := NewMemoryBuffer(d, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer buf.Close()
	if buf.Size() != 0 {
		t.Fatalf("expected empty buffer, got size %d", buf.Size())
	}
}

func TestNewMemoryBuffer_BatchMode(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistBatch, BatchSize: 10, BatchInterval: 50 * time.Millisecond, QueueSize: 100}
	buf, err := NewMemoryBuffer(d, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer buf.Close()
	if buf.Size() != 0 {
		t.Fatalf("expected empty buffer, got size %d", buf.Size())
	}
}

func TestNewMemoryBuffer_AsyncMode(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistAsync, BatchInterval: 50 * time.Millisecond, QueueSize: 100}
	buf, err := NewMemoryBuffer(d, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer buf.Close()
}

func TestMemoryBuffer_Add_Batch(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistBatch, BatchSize: 10, QueueSize: 100}
	buf, _ := NewMemoryBuffer(d, cfg)
	defer buf.Close()

	item := &CertBufferItem{
		Record: &db.CertRecord{
			SerialNumber: "test-serial-1",
			CAName:       "test-ca",
			Status:       "active",
			CommonName:   "test.example.com",
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		},
	}
	if err := buf.Add(item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Size() != 1 {
		t.Fatalf("expected size 1, got %d", buf.Size())
	}
}

func TestMemoryBuffer_Flush_Empty(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistBatch, BatchSize: 10, QueueSize: 100}
	buf, _ := NewMemoryBuffer(d, cfg)
	defer buf.Close()

	if err := buf.Flush(); err != nil {
		t.Fatalf("flushing empty buffer should succeed: %v", err)
	}
}

func TestMemoryBuffer_Close(t *testing.T) {
	d := newTestDB(t)
	cfg := PersistConfig{Mode: PersistAsync, BatchInterval: 10 * time.Millisecond, QueueSize: 100}
	buf, _ := NewMemoryBuffer(d, cfg)
	// Add some items
	item := &CertBufferItem{
		Record: &db.CertRecord{
			SerialNumber: "close-test",
			CAName:       "test-ca",
			Status:       "active",
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		},
	}
	buf.Add(item)
	if err := buf.Close(); err != nil {
		t.Fatalf("close should succeed: %v", err)
	}
}

// ─── trust.go: trustAnchorDisplayName ────────────────────────────

func TestTrustAnchorDisplayName_CN(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "My Root CA"}}
	got := trustAnchorDisplayName(cert)
	if got != "My Root CA" {
		t.Fatalf("expected My Root CA, got %s", got)
	}
}

func TestTrustAnchorDisplayName_Org(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Acme Inc"}}}
	got := trustAnchorDisplayName(cert)
	if got != "Acme Inc" {
		t.Fatalf("expected Acme Inc, got %s", got)
	}
}

func TestTrustAnchorDisplayName_OU(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"Security"}}}
	got := trustAnchorDisplayName(cert)
	if got != "Security" {
		t.Fatalf("expected Security, got %s", got)
	}
}

func TestTrustAnchorDisplayName_SubjectString(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{SerialNumber: "12345"}}
	got := trustAnchorDisplayName(cert)
	if got == "" || got == "(unnamed)" {
		t.Fatalf("expected subject string, got %q", got)
	}
}

func TestTrustAnchorDisplayName_Unnamed(t *testing.T) {
	cert := &x509.Certificate{}
	got := trustAnchorDisplayName(cert)
	if got != "(unnamed)" {
		t.Fatalf("expected (unnamed), got %s", got)
	}
}

func TestTrustAnchorDisplayName_Long(t *testing.T) {
	longCN := make([]byte, 100)
	for i := range longCN {
		longCN[i] = 'a'
	}
	cert := &x509.Certificate{Subject: pkix.Name{SerialNumber: string(longCN)}}
	got := trustAnchorDisplayName(cert)
	if len(got) > 84 { // 80 + "..."
		t.Fatalf("expected truncated string, got len=%d: %s", len(got), got)
	}
}

// ─── sign.go: extractCAName ──────────────────────────────────────

func TestExtractCAName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"/etc/pki/ca.pem", "ca"},
		{"/path/to/my-ca-cert.pem", "my-ca-cert"},
		{"ca.pem", "ca"},
		{"/unix\\path\\file.pem", "file"},
		{"noext", "noext"},
	}
	for _, tt := range tests {
		got := extractCAName(tt.input)
		if got != tt.want {
			t.Errorf("extractCAName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── sign.go: CertToPEM ──────────────────────────────────────────

func TestCertToPEM_CoverageBoost(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemBytes := CertToPEM(der)
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}
}

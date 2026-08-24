package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func normSN(s *big.Int) string {
	n, err := NormalizeSerial(fmt.Sprintf("%X", s))
	if err != nil {
		panic(err)
	}
	return n
}

func makeAICCert(t *testing.T, cn, principalUid, caName string, serial *big.Int) (*x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aicExt, err := BuildAIC(AICConfig{
		AgentId:                 "agent-" + cn,
		PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: principalUid, KeyHash: testAICKeyHash()},
		Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}},
		DelegationAuthorization: testAICDelegation(),
	})
	if err != nil {
		t.Fatalf("BuildAIC: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{aicExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, der
}

func TestParseRevokeReason(t *testing.T) {
	tests := []struct {
		input string
		want  int
		err   bool
	}{
		{"", 0, false},
		{"unspecified", 0, false},
		{"keyCompromise", 1, false},
		{"cACompromise", 2, false},
		{"affiliationChanged", 3, false},
		{"superseded", 4, false},
		{"cessationOfOperation", 5, false},
		{"certificateHold", 6, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseRevokeReason(tt.input)
		if tt.err && err == nil {
			t.Errorf("expected error for %q", tt.input)
		}
		if !tt.err && err != nil {
			t.Errorf("unexpected error for %q: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("for %q: got %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSerial(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"2A", "000000000000000000000000000000000000002A", false},
		{"0x2A", "000000000000000000000000000000000000002A", false},
		{"0X2A", "000000000000000000000000000000000000002A", false},
		{"", "", true},
		{"xyz", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeSerial(tt.input)
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
		if got != tt.want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRevoke(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	der := []byte("fake-cert-der")
	serialHex := "000000000000000000000000000000000000002A"
	record := &db.CertRecord{
		SerialNumber: serialHex,
		CAName:       "TestCA",
		Status:       "V",
		Subject:      "CN=test",
		CommonName:   "test",
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		CertDER:      der,
		Fingerprint:  db.Fingerprint(der),
	}
	if err := d.InsertCert(record); err != nil {
		t.Fatal(err)
	}

	// Normal revoke path
	if err := Revoke(d, "TestCA", "2A", 1); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	cert, err := d.GetCert("TestCA", serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "R" {
		t.Errorf("expected status R, got %q", cert.Status)
	}
	if cert.RevokeReason == nil || *cert.RevokeReason != 1 {
		t.Errorf("expected revoke reason 1, got %v", cert.RevokeReason)
	}

	// Non-existent serial → error
	if err := Revoke(d, "TestCA", "DEADBEEF", 0); err == nil {
		t.Error("expected error for non-existent serial")
	}
}

func TestExtractPrincipalUid_Valid(t *testing.T) {
	cert, _ := makeAICCert(t, "test-agent", "alice@example.com", "TestCA", big.NewInt(100))

	uid, err := extractPrincipalUid(cert.Raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice@example.com", KeyHash: testAICKeyHash()}.String()
	if uid != want {
		t.Fatalf("expected %s, got %s", want, uid)
	}
}

func TestExtractPrincipalUid_NoAIC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "no-aic"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	_, err := extractPrincipalUid(der)
	if err != ErrNoAIC {
		t.Fatalf("expected ErrNoAIC, got %v", err)
	}
}

func TestExtractPrincipalUid_InvalidDER(t *testing.T) {
	_, err := extractPrincipalUid([]byte{0xff, 0xff})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestRevokeByPrincipalUid_Match(t *testing.T) {
	d := newTestDB(t)
	cert1, der1 := makeAICCert(t, "agent1", "user1@test.com", "CA1", big.NewInt(10))
	cert2, der2 := makeAICCert(t, "agent2", "user1@test.com", "CA2", big.NewInt(11))
	cert3, der3 := makeAICCert(t, "agent3", "other@test.com", "CA1", big.NewInt(12))

	now := time.Now()
	for _, rec := range []*db.CertRecord{
		{
			SerialNumber: normSN(cert1.SerialNumber),
			CAName:       "CA1", Status: "V", CommonName: "agent1",
			CertDER: der1, Fingerprint: db.Fingerprint(der1),
			NotBefore: now, NotAfter: now.Add(time.Hour),
		},
		{
			SerialNumber: normSN(cert2.SerialNumber),
			CAName:       "CA2", Status: "V", CommonName: "agent2",
			CertDER: der2, Fingerprint: db.Fingerprint(der2),
			NotBefore: now, NotAfter: now.Add(time.Hour),
		},
		{
			SerialNumber: normSN(cert3.SerialNumber),
			CAName:       "CA1", Status: "V", CommonName: "agent3",
			CertDER: der3, Fingerprint: db.Fingerprint(der3),
			NotBefore: now, NotAfter: now.Add(time.Hour),
		},
	} {
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
	}

	revoked, err := RevokeByPrincipalUid(d, testPrincipalUID("varwof", "user1@test.com"), 1)
	if err != nil {
		t.Fatalf("RevokeByPrincipalUid: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("expected 2 revoked, got %d", revoked)
	}

	// Verify cert1 and cert2 are revoked, cert3 is still valid
	for _, tc := range []struct {
		ca     string
		serial string
		want   string
	}{
		{"CA1", normSN(cert1.SerialNumber), "R"},
		{"CA2", normSN(cert2.SerialNumber), "R"},
		{"CA1", normSN(cert3.SerialNumber), "V"},
	} {
		rec, err := d.GetCert(tc.ca, tc.serial)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != tc.want {
			t.Errorf("cert %s/%s: expected status %s, got %s", tc.ca, tc.serial, tc.want, rec.Status)
		}
	}
}

func TestRevokeByPrincipalUid_NoMatch(t *testing.T) {
	d := newTestDB(t)
	cert, der := makeAICCert(t, "agent1", "only@test.com", "CA1", big.NewInt(20))
	now := time.Now()
	if err := d.InsertCert(&db.CertRecord{
		SerialNumber: normSN(cert.SerialNumber),
		CAName:       "CA1", Status: "V", CommonName: "agent1",
		CertDER: der, Fingerprint: db.Fingerprint(der),
		NotBefore: now, NotAfter: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	revoked, err := RevokeByPrincipalUid(d, testPrincipalUID("varwof", "nonexistent@test.com"), 1)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if revoked != 0 {
		t.Fatalf("expected 0 revoked, got %d", revoked)
	}
}

func TestRevokeWithCascade(t *testing.T) {
	d := newTestDB(t)
	cert1, der1 := makeAICCert(t, "primary", "shared@test.com", "CA1", big.NewInt(30))
	cert2, der2 := makeAICCert(t, "secondary", "shared@test.com", "CA1", big.NewInt(31))

	now := time.Now()
	for _, rec := range []*db.CertRecord{
		{
			SerialNumber: normSN(cert1.SerialNumber),
			CAName:       "CA1", Status: "V", CommonName: "primary",
			CertDER: der1, Fingerprint: db.Fingerprint(der1),
			NotBefore: now, NotAfter: now.Add(time.Hour),
		},
		{
			SerialNumber: normSN(cert2.SerialNumber),
			CAName:       "CA1", Status: "V", CommonName: "secondary",
			CertDER: der2, Fingerprint: db.Fingerprint(der2),
			NotBefore: now, NotAfter: now.Add(time.Hour),
		},
	} {
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
	}

	// Revoke primary with cascade
	cascaded, err := RevokeWithCascade(d, "CA1", normSN(cert1.SerialNumber), 4)
	if err != nil {
		t.Fatalf("RevokeWithCascade: %v", err)
	}
	if cascaded != 1 {
		t.Fatalf("expected 1 cascaded revocation, got %d", cascaded)
	}

	// Both should be revoked
	for _, tc := range []struct {
		serial string
		want   string
	}{
		{normSN(cert1.SerialNumber), "R"},
		{normSN(cert2.SerialNumber), "R"},
	} {
		rec, err := d.GetCert("CA1", tc.serial)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != tc.want {
			t.Errorf("cert %s: expected status %s, got %s", tc.serial, tc.want, rec.Status)
		}
	}
}

func TestRevokeWithCascade_NoAIC(t *testing.T) {
	d := newTestDB(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(40),
		Subject:      pkix.Name{CommonName: "no-aic-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	serialHex := normSN(cert.SerialNumber)

	now := time.Now()
	if err := d.InsertCert(&db.CertRecord{
		SerialNumber: serialHex,
		CAName:       "CA1", Status: "V", CommonName: "no-aic",
		CertDER: der, Fingerprint: db.Fingerprint(der),
		NotBefore: now, NotAfter: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Revoke cert without AIC — no cascade expected
	cascaded, err := RevokeWithCascade(d, "CA1", serialHex, 0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cascaded != 0 {
		t.Fatalf("expected 0 cascaded revocations (no AIC), got %d", cascaded)
	}

	// The primary cert should be revoked
	rec, err := d.GetCert("CA1", serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "R" {
		t.Fatalf("expected primary cert to be revoked, got %s", rec.Status)
	}
}

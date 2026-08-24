package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestRotatingSignerBasic(t *testing.T) {
	cert, key := newTestCA(t)
	rs := NewRotatingSigner(cert, key)

	if rs.Cert() != cert {
		t.Fatal("Cert() should return the active cert")
	}
	if rs.Key() != key {
		t.Fatal("Key() should return the active key")
	}
	if rs.Public() == nil {
		t.Fatal("Public() should be non-nil")
	}
	if rs.Legacy() != nil {
		t.Fatal("no legacy should be present initially")
	}
}

func TestRotatingSignerSigns(t *testing.T) {
	cert, key := newTestCA(t)
	rs := NewRotatingSigner(cert, key)

	// Sign a digest with the RotatingSigner (implements crypto.Signer).
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	sig, err := rs.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestRotatingSignerRotate(t *testing.T) {
	cert1, key1 := newTestCA(t)
	rs := NewRotatingSigner(cert1, key1)

	// New CA cert/key (same identity).
	cert2, key2 := newTestCA(t)
	// Make cert2 a different cert than cert1.
	rs.Rotate(cert2, key2)

	if rs.Cert() != cert2 {
		t.Fatal("active cert should be the new one after rotate")
	}
	if rs.Key() != key2 {
		t.Fatal("active key should be the new one after rotate")
	}
	if lg := rs.Legacy(); lg == nil || lg.Cert != cert1 || lg.Key != key1 {
		t.Fatal("legacy should retain the old cert+key during transition")
	}
}

func TestRotatingSignerClearLegacy(t *testing.T) {
	cert1, key1 := newTestCA(t)
	rs := NewRotatingSigner(cert1, key1)
	cert2, key2 := newTestCA(t)
	rs.Rotate(cert2, key2)
	if rs.Legacy() == nil {
		t.Fatal("legacy should exist after rotate")
	}
	rs.ClearLegacy()
	if rs.Legacy() != nil {
		t.Fatal("legacy should be cleared")
	}
}

func TestRotatingSignerNeedsRotation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Expiring soon.
	expiring := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Expiring CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:         true,
	}
	rs := NewRotatingSigner(expiring, key)
	if !rs.NeedsRotation(7 * 24 * time.Hour) {
		t.Fatal("should need rotation when expiring within 7 days")
	}

	// Long-lived.
	longLived := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Long CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:         true,
	}
	rs2 := NewRotatingSigner(longLived, key)
	if rs2.NeedsRotation(7 * 24 * time.Hour) {
		t.Fatal("should NOT need rotation when far from expiry")
	}
}

func TestRotatingSignerNilSafe(t *testing.T) {
	var rs *RotatingSigner
	if rs.Cert() != nil {
		t.Fatal("nil receiver Cert should be nil")
	}
	if rs.Key() != nil {
		t.Fatal("nil receiver Key should be nil")
	}
	if rs.Public() != nil {
		t.Fatal("nil receiver Public should be nil")
	}
	if rs.Legacy() != nil || rs.Active() != nil {
		t.Fatal("nil receiver should return nil")
	}
	if !rs.NeedsRotation(time.Hour) {
		t.Fatal("nil receiver should need rotation")
	}
	rs.Rotate(nil, nil)
	rs.ClearLegacy()
	if _, err := rs.Sign(nil, nil, nil); err == nil {
		t.Fatal("nil receiver Sign should error")
	}
}

func TestRotatingSignerSignUsesNewKey(t *testing.T) {
	rootCert, rootKey := newTestCA(t)
	rs := NewRotatingSigner(rootCert, rootKey)

	// Create a NEW CA cert signed by root, with a different key.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Rotated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, rootCert, &subKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	subCert, err := x509.ParseCertificate(subDER)
	if err != nil {
		t.Fatal(err)
	}

	rs.Rotate(subCert, subKey)

	// A leaf issued by the rotated CA must verify against the NEW cert.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rs.Cert(), &leafKey.PublicKey, rs)
	if err != nil {
		t.Fatalf("issue leaf via rotating signer: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leafCert.CheckSignatureFrom(subCert); err != nil {
		t.Fatalf("leaf should verify against rotated CA cert: %v", err)
	}
}

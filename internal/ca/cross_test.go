package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func TestCrossSign(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cross-sign-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	d, err := db.Open(tmpDir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Create issuer CA
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	// Create target CA in ca_meta
	targetKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	targetTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Target CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	targetDER, _ := x509.CreateCertificate(rand.Reader, targetTmpl, targetTmpl, &targetKey.PublicKey, targetKey)
	targetCert, _ := x509.ParseCertificate(targetDER)

	targetCAMeta := &db.CAMeta{
		Name:         "target",
		CertDER:      targetDER,
		Subject:      targetCert.Subject.String(),
		NotBefore:    targetCert.NotBefore,
		NotAfter:     targetCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(targetDER),
	}
	if err := d.InsertCAMeta(targetCAMeta); err != nil {
		t.Fatal(err)
	}

	// Cross-sign
	result, err := CrossSign(d, issuerCert, issuerKey, "issuer", targetCAMeta, 365*24*time.Hour, nil)
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}

	if result.Cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if !result.Cert.IsCA {
		t.Fatal("cross cert should be a CA certificate")
	}
	if result.Cert.Subject.CommonName != "Target CA" {
		t.Fatalf("expected subject Target CA, got %s", result.Cert.Subject.CommonName)
	}
	if result.Cert.Issuer.CommonName != "Issuer CA" {
		t.Fatalf("expected issuer Issuer CA, got %s", result.Cert.Issuer.CommonName)
	}

	// Verify stored in DB
	got, err := d.GetCrossCert("issuer", result.SerialHex)
	if err != nil {
		t.Fatalf("GetCrossCert after CrossSign: %v", err)
	}
	if got.SubjectCA != "target" {
		t.Fatalf("expected subjectCA target, got %s", got.SubjectCA)
	}

	// Verify the cert can be verified by the issuer
	roots := x509.NewCertPool()
	roots.AddCert(issuerCert)
	opts := x509.VerifyOptions{Roots: roots}
	if _, err := result.Cert.Verify(opts); err != nil {
		t.Fatalf("cross cert verify: %v", err)
	}
}

func TestCrossSignRevokeInCRL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cross-crl-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	d, err := db.Open(tmpDir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CRL Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	targetKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	targetTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CRL Target CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	targetDER, _ := x509.CreateCertificate(rand.Reader, targetTmpl, targetTmpl, &targetKey.PublicKey, targetKey)
	targetCert, _ := x509.ParseCertificate(targetDER)

	targetCAMeta := &db.CAMeta{
		Name:         "crl-target",
		CertDER:      targetDER,
		Subject:      targetCert.Subject.String(),
		NotBefore:    targetCert.NotBefore,
		NotAfter:     targetCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(targetDER),
	}
	if err := d.InsertCAMeta(targetCAMeta); err != nil {
		t.Fatal(err)
	}

	result, err := CrossSign(d, issuerCert, issuerKey, "CRL Issuer CA", targetCAMeta, 365*24*time.Hour, nil)
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}

	// Revoke
	if err := d.RevokeCrossCert("CRL Issuer CA", result.SerialHex, 1); err != nil {
		t.Fatalf("RevokeCrossCert: %v", err)
	}

	// Generate CRL - should include revoked cross cert
	crlDER, err := GenerateCRL(&CRLConfig{
		DB:              d,
		CACert:          issuerCert,
		CAKey:           issuerKey,
		CAName:          "CRL Issuer CA",
		ValidityDays:    30,
		ThisUpdate:      time.Now(),
		Partition:       -1,
		TotalPartitions: 1,
	})
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("expected non-empty CRL")
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) == 0 {
		t.Fatal("expected at least one revoked entry in CRL")
	}
}

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/pkcs7"
)

func testPolicyCA(t *testing.T, ou string) (*x509.CertPool, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Policy Test CA", OrganizationalUnit: []string{"admin"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Policy Admin", OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTmpl, caCert, &signerKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	signerCert, err := x509.ParseCertificate(signerDER)
	if err != nil {
		t.Fatal(err)
	}
	return roots, signerCert, signerKey
}

func TestVerifySignedPolicy_RoundTrip(t *testing.T) {
	roots, cert, key := testPolicyCA(t, "admin")
	data := []byte(`{"version":"v2","roles":[]}`)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySignedPolicy(sig, data, &PolicySignatureOptions{Roots: roots, RequireAdminOU: true})
	if err != nil {
		t.Fatalf("VerifySignedPolicy: %v", err)
	}
	if got.Subject.CommonName != "Policy Admin" {
		t.Fatalf("signer CN: got %s", got.Subject.CommonName)
	}
}

func TestVerifySignedPolicy_TamperedData(t *testing.T) {
	roots, cert, key := testPolicyCA(t, "admin")
	data := []byte(`{"version":"v2","roles":[]}`)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(`{"version":"v2","roles":[{"name":"superadmin"}]}`)
	if _, err := VerifySignedPolicy(sig, tampered, &PolicySignatureOptions{Roots: roots}); err == nil {
		t.Fatal("expected tamper rejection, got nil")
	}
}

func TestVerifySignedPolicy_NonAdminOU(t *testing.T) {
	roots, cert, key := testPolicyCA(t, "ops")
	data := []byte(`{"version":"v2","roles":[]}`)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedPolicy(sig, data, &PolicySignatureOptions{Roots: roots, RequireAdminOU: true}); err == nil {
		t.Fatal("expected non-admin OU rejection, got nil")
	}
}

func TestVerifySignedPolicy_UntrustedChain(t *testing.T) {
	_, cert, key := testPolicyCA(t, "admin")
	data := []byte(`{"version":"v2","roles":[]}`)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Empty pool: does not contain the issuing CA → chain verification fails (fail-closed).
	if _, err := VerifySignedPolicy(sig, data, &PolicySignatureOptions{Roots: x509.NewCertPool(), RequireAdminOU: true}); err == nil {
		t.Fatal("expected untrusted chain rejection, got nil")
	}
}

func TestVerifySignedPolicy_NoOptsSkipsChecks(t *testing.T) {
	_, cert, key := testPolicyCA(t, "ops")
	data := []byte(`{"version":"v2","roles":[]}`)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// When opts=nil, only verifies the detached signature, does not enforce admin OU / chain verification.
	if _, err := VerifySignedPolicy(sig, data, nil); err != nil {
		t.Fatalf("opts=nil should only verify detached sig: %v", err)
	}
}

func TestIsAdminOU(t *testing.T) {
	if !IsAdminOU("admin") {
		t.Fatal("admin")
	}
	if !IsAdminOU("gateway:admin") {
		t.Fatal("gateway:admin")
	}
	if IsAdminOU("ops") {
		t.Fatal("ops should not be admin")
	}
}

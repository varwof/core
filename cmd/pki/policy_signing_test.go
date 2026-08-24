package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/pkcs7"
)

var validPolicyJSON = []byte(`{
  "version": "v2",
  "roles": {
    "superadmin": {
      "display_name": "superadmin",
      "profiles": ["m-superadmin"],
      "grants": ["ca:*", "cert:*"]
    }
  },
  "ou_mapping": {
    "admin": "superadmin"
  },
  "gateway_namespaces": {}
}`)

func makePolicySigningCert(t *testing.T, ou string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", OrganizationalUnit: []string{"admin"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Admin", OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTmpl, caCert, &signerKey.PublicKey, caKey)
	signerCert, _ := x509.ParseCertificate(signerDER)
	return signerCert, signerKey, caCert
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func writePolicyTestFile(t *testing.T, cfg *internal.Config, cert *x509.Certificate, key *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicyWithSigning_OK(t *testing.T) {
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	path := writePolicyTestFile(t, cfg, signerCert, signerKey, validPolicyJSON)
	tru := true
	cfg.PolicySigning = internal.PolicySigningConfig{
		Enabled:        true,
		RequireAdminOU: &tru,
		Require:        true,
	}
	dir := t.TempDir()
	pemBytes := pemEncodeCert(caCert)
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.PolicySigning.CAFile = filepath.Join(dir, "ca.pem")
	if _, err := loadPolicyWithSigning(cfg, path); err != nil {
		t.Fatalf("loadPolicyWithSigning with valid sig should pass: %v", err)
	}
}

func TestLoadPolicyWithSigning_MissingSig_RequireFalse(t *testing.T) {
	cfg := &internal.Config{}
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	os.WriteFile(path, validPolicyJSON, 0600)
	tru := true
	cfg.PolicySigning = internal.PolicySigningConfig{Enabled: true, Require: false, RequireAdminOU: &tru}
	// No .sig file, Require=false → degrade to loading plaintext
	if _, err := loadPolicyWithSigning(cfg, path); err != nil {
		t.Fatalf("missing sig + require=false should degrade to plain load: %v", err)
	}
}

func TestLoadPolicyWithSigning_MissingSig_RequireTrue(t *testing.T) {
	cfg := &internal.Config{}
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	os.WriteFile(path, validPolicyJSON, 0600)
	tru := true
	cfg.PolicySigning = internal.PolicySigningConfig{Enabled: true, Require: true, RequireAdminOU: &tru}
	if _, err := loadPolicyWithSigning(cfg, path); err == nil {
		t.Fatal("missing sig + require=true should fail closed")
	}
}

func TestLoadPolicyWithSigning_Disabled(t *testing.T) {
	cfg := &internal.Config{}
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	os.WriteFile(path, validPolicyJSON, 0600)
	// signing disabled → load plaintext directly
	if _, err := loadPolicyWithSigning(cfg, path); err != nil {
		t.Fatalf("signing disabled should plain load: %v", err)
	}
}

func TestPolicySigningOpts_DefaultAdminOU(t *testing.T) {
	cfg := &internal.Config{}
	cfg.PolicySigning = internal.PolicySigningConfig{Enabled: true}
	opts, err := policySigningOpts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
	if !opts.RequireAdminOU {
		t.Fatal("default RequireAdminOU should be true")
	}
}

func TestLoadRouteRulesWithSigning(t *testing.T) {
	cfg := &internal.Config{}
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	rules := []byte(`{"version":"v1","rules":[{"method":"GET","path":"/api/v1/certs","permission":"cert:list"}]}`)
	if err := os.WriteFile(path, rules, 0600); err != nil {
		t.Fatal(err)
	}
	// Signing not enabled → load directly
	if _, err := loadRouteRulesWithSigning(cfg, path); err != nil {
		t.Fatalf("routes load without signing: %v", err)
	}
	// Signing enabled but require=false + missing sig → degrade
	tru := true
	cfg.PolicySigning = internal.PolicySigningConfig{Enabled: true, Require: false, RequireAdminOU: &tru}
	if _, err := loadRouteRulesWithSigning(cfg, path); err != nil {
		t.Fatalf("routes load missing sig + require=false: %v", err)
	}
	// require=true → reject
	cfg.PolicySigning.Require = true
	if _, err := loadRouteRulesWithSigning(cfg, path); err == nil {
		t.Fatal("routes load missing sig + require=true should fail closed")
	}
}

package ca

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
)

func TestCreateRootCA(t *testing.T) {
	FlushSignerCache()
	d := newTestDB(t)
	cfg := &CreateConfig{
		DB:       d,
		Name:     "test-root",
		Profile:  ProfileRootCA,
		KeyType:  "ecdsa-p256",
		Validity: 10 * 365 * 24 * time.Hour,
	}
	result, err := CreateCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cert == nil {
		t.Fatal("nil cert")
	}
	if !result.Cert.IsCA {
		t.Fatal("root should be CA")
	}
	if result.Cert.MaxPathLen != -1 {
		t.Fatalf("expected pathlen -1 (unlimited), got %d", result.Cert.MaxPathLen)
	}
	if result.SerialHex == "" {
		t.Fatal("empty serial")
	}

	meta, err := d.GetCAMeta("test-root")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "test-root" {
		t.Fatalf("expected test-root, got %q", meta.Name)
	}
}

func TestCreateSubCA(t *testing.T) {
	d := newTestDB(t)

	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parentTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root", Organization: []string{"test"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentTmpl, parentTmpl, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parentCert, err := x509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &CreateConfig{
		DB:        d,
		Name:      "test-sub",
		Profile:   ProfileSubCA,
		Parent:    parentCert,
		ParentKey: parentKey,
		KeyType:   "ecdsa-p256",
		Validity:  5 * 365 * 24 * time.Hour,
	}
	result, err := CreateCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cert.MaxPathLen != 0 {
		t.Fatalf("sub-ca expected pathlen 0, got %d", result.Cert.MaxPathLen)
	}

	meta, err := d.GetCAMeta("test-sub")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "test-sub" {
		t.Fatalf("expected test-sub, got %q", meta.Name)
	}
}

func TestCreateCAInvalidProfile(t *testing.T) {
	d := newTestDB(t)
	cfg := &CreateConfig{
		DB:       d,
		Name:     "bad",
		Profile:  "invalid",
		KeyType:  "ecdsa-p256",
		Validity: 365 * 24 * time.Hour,
	}
	_, err := CreateCA(cfg)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
}

func TestCreateCAWithKeys(t *testing.T) {
	d := newTestDB(t)

	for _, kt := range []string{"ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096", "ed25519"} {
		cfg := &CreateConfig{
			DB:       d,
			Name:     "test-" + kt,
			Profile:  ProfileRootCA,
			KeyType:  kt,
			Validity: 365 * 24 * time.Hour,
		}
		result, err := CreateCA(cfg)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if result.Signer == nil {
			t.Fatalf("%s: nil signer", kt)
		}
	}
}

func TestCreateCAAndPEMOutput(t *testing.T) {
	d := newTestDB(t)
	cfg := &CreateConfig{
		DB:       d,
		Name:     "pem-test",
		Profile:  ProfileRootCA,
		KeyType:  "ecdsa-p256",
		Validity: 365 * 24 * time.Hour,
	}
	result, err := CreateCA(cfg)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.CertDER}), 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(result.Signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}

	loadedCert, loadedKey, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedCert == nil || loadedKey == nil {
		t.Fatal("nil after reload")
	}
}

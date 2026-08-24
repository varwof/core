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

func writeTestRootKeyCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "root.pem")
	keyPath = filepath.Join(dir, "root.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestColdBackupRoundTrip(t *testing.T) {
	certPath, keyPath := writeTestRootKeyCert(t)
	out := filepath.Join(t.TempDir(), "backup.json")
	pwd := "strong-backup-password"

	if err := ColdBackupCA("root", certPath, keyPath, pwd, "", out); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("backup file not written: %v", err)
	}

	summary, err := VerifyColdBackup(out, pwd)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary == "" {
		t.Fatal("empty summary")
	}
}

func TestColdBackupWrongPasswordRejected(t *testing.T) {
	certPath, keyPath := writeTestRootKeyCert(t)
	out := filepath.Join(t.TempDir(), "backup.json")
	if err := ColdBackupCA("root", certPath, keyPath, "right-password", "", out); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := VerifyColdBackup(out, "wrong-password"); err == nil {
		t.Fatal("expected rejection on wrong password")
	}
}

func TestColdBackupEncryptedSourceKey(t *testing.T) {
	// Source key on disk is itself PBES2-encrypted; backup must still succeed.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	enc, err := EncryptKeyDERPKCS8(keyDER, "source-key-pw")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "backup.json")
	if err := ColdBackupCA("root", certPath, keyPath, "backup-pw", "source-key-pw", out); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := VerifyColdBackup(out, "backup-pw"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

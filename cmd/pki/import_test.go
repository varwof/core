package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func newTestImportDB(t *testing.T) (*db.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/test.db"
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path
}

func newTestCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestEndEntityCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return certDER
}

func TestFieldIndices(t *testing.T) {
	tests := []struct {
		n              int
		wantSerial     int
		wantRevDate    int
		wantReason     int
	}{
		{6, 3, 2, -1},
		{7, 4, 2, 3},
		{8, 4, 2, 3},
		{5, 3, 2, -1},
	}
	for _, tc := range tests {
		si, rd, ri := fieldIndices(tc.n)
		if si != tc.wantSerial || rd != tc.wantRevDate || ri != tc.wantReason {
			t.Errorf("fieldIndices(%d) = (%d,%d,%d), want (%d,%d,%d)",
				tc.n, si, rd, ri, tc.wantSerial, tc.wantRevDate, tc.wantReason)
		}
	}
}

func TestRegisterCACert(t *testing.T) {
	d, _ := newTestImportDB(t)
	cert, _ := newTestCACert(t)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := registerCACert(d, "test-ca", certPath); err != nil {
		t.Fatal(err)
	}

	meta, err := d.GetCAMeta("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "test-ca" {
		t.Errorf("got name %q, want test-ca", meta.Name)
	}
	if meta.KeyAlgorithm != "ecdsa-p256" {
		t.Errorf("got key algo %q, want ecdsa-p256", meta.KeyAlgorithm)
	}
}

func TestImportIndex(t *testing.T) {
	d, dbPath := newTestImportDB(t)
	dir := t.TempDir()

	caCert, caKey := newTestCACert(t)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caCertPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := registerCACert(d, "issuing", caCertPath); err != nil {
		t.Fatal(err)
	}

	serials := []int64{1, 2, 3}
	names := []string{"server-a", "server-b", "server-c"}
	for i := range serials {
		certDER := newTestEndEntityCert(t, caCert, caKey, serials[i], names[i])
		p := filepath.Join(dir, names[i]+".pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(p, pemBytes, 0644); err != nil {
			t.Fatal(err)
		}
	}

	expDate := time.Now().Add(365 * 24 * time.Hour).UTC().Format("060102150405Z")
	revDate := "230101000000Z"

	lines := []string{
		fmt.Sprintf("V\t%s\t\t01\t%s.pem\tCN=server-a", expDate, names[0]),
		fmt.Sprintf("R\t%s\t%s\t02\t%s.pem\tCN=server-b", expDate, revDate, names[1]),
		fmt.Sprintf("V\t%s\t\t03\t%s.pem\tCN=server-c", expDate, names[2]),
	}

	indexPath := filepath.Join(dir, "index.txt")
	if err := os.WriteFile(indexPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := cmdImport(&internal.Config{DB: dbPath}, []string{
		"-index", indexPath,
		"-cert-dir", dir,
		"-ca", "issuing",
	}); err != nil {
		t.Fatal(err)
	}

	for _, serial := range []int64{1, 2, 3} {
		rec, err := d.GetCert("issuing", fmt.Sprintf("%040X", serial))
		if err != nil {
			t.Fatalf("get cert serial %d: %v", serial, err)
		}
		if serial == 2 {
			if rec.Status != "R" {
				t.Errorf("serial %d: status = %q, want R", serial, rec.Status)
			}
			if rec.RevokedAt == nil {
				t.Errorf("serial %d: RevokedAt is nil", serial)
			}
		} else {
			if rec.Status != "V" {
				t.Errorf("serial %d: status = %q, want V", serial, rec.Status)
			}
		}
	}

	// Test 7-field format with reason
	certDER4 := newTestEndEntityCert(t, caCert, caKey, 4, "server-d")
	path4 := filepath.Join(dir, "server-d.pem")
	pemBytes4 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER4})
	if err := os.WriteFile(path4, pemBytes4, 0644); err != nil {
		t.Fatal(err)
	}

	reasonLines := []string{
		fmt.Sprintf("R\t%s\t%s\tkeyCompromise\t04\t%s.pem\tCN=server-d", expDate, revDate, "server-d"),
	}
	indexPath2 := filepath.Join(dir, "index2.txt")
	if err := os.WriteFile(indexPath2, []byte(strings.Join(reasonLines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := cmdImport(&internal.Config{DB: dbPath}, []string{
		"-index", indexPath2,
		"-cert-dir", dir,
		"-ca", "issuing",
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := d.GetCert("issuing", "0000000000000000000000000000000000000004")
	if err != nil {
		t.Fatalf("get cert serial 4: %v", err)
	}
	if rec.Status != "R" {
		t.Errorf("serial 4: status = %q, want R", rec.Status)
	}
	if rec.RevokeReason == nil || *rec.RevokeReason != 1 {
		t.Errorf("serial 4: RevokeReason = %v, want 1", rec.RevokeReason)
	}
}

func TestImportIndexEmptyLines(t *testing.T) {
	d, dbPath := newTestImportDB(t)
	dir := t.TempDir()

	caCert, caKey := newTestCACert(t)
	certDER := newTestEndEntityCert(t, caCert, caKey, 1, "test")
	p := filepath.Join(dir, "test.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(p, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}

	expDate := time.Now().Add(365 * 24 * time.Hour).UTC().Format("060102150405Z")
	content := fmt.Sprintf("\n\nV\t%s\t\t01\ttest.pem\tCN=test\n\n# comment\n", expDate)
	indexPath := filepath.Join(dir, "index.txt")
	if err := os.WriteFile(indexPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := cmdImport(&internal.Config{DB: dbPath}, []string{
		"-index", indexPath,
		"-cert-dir", dir,
		"-ca", "issuing",
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := d.GetCert("issuing", "0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if rec.Status != "V" {
		t.Errorf("status = %q, want V", rec.Status)
	}
}

func TestPubKeyAlgorithmECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := pubKeyAlgorithm(&key.PublicKey)
	if s != "ecdsa-p256" {
		t.Fatalf("expected ecdsa-p256, got %q", s)
	}
}

func TestPubKeyAlgorithmRSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	s := pubKeyAlgorithm(&key.PublicKey)
	if s != "rsa-4096" {
		t.Fatalf("expected rsa-4096, got %q", s)
	}
}

func TestPubKeyAlgorithmUnknown(t *testing.T) {
	s := pubKeyAlgorithm("not a key")
	if s == "" {
		t.Fatal("expected non-empty string for unknown type")
	}
}

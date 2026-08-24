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
	"github.com/varwof/engine/db"
)

// makeAdminCertPEM 生成一张带 admin OU 的自签证书 + 密钥 PEM（用于 policy sign）。
func makeAdminCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "admin-test", OrganizationalUnit: []string{"admin"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func insertCertRecord(t *testing.T, d *db.DB, serial, cn, status string, notAfter time.Time) {
	t.Helper()
	nb := time.Now().Add(-time.Hour)
	rec := &db.CertRecord{
		SerialNumber: serial,
		CAName:       "test-ca",
		Status:       status,
		Subject:      "CN=" + cn,
		CommonName:   cn,
		NotBefore:    nb,
		NotAfter:     notAfter,
		CertDER:      []byte{1, 2, 3},
		Fingerprint:  "fp-" + serial,
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
}

func TestCmdListCert(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	insertCertRecord(t, d, "AA1", "alice", "V", time.Now().Add(24*time.Hour))
	insertCertRecord(t, d, "AA2", "bob", "R", time.Now().Add(48*time.Hour))
	insertCertRecord(t, d, "AA3", "carol", "V", time.Now().Add(-time.Hour))
	d.Close()

	cfg := &internal.Config{DB: dbPath}

	// raw query path (no --ca)
	if err := cmdListCert(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// --ca path with filters
	if err := cmdListCert(cfg, []string{"--ca", "test-ca", "--status", "V", "--cn", "ali", "--limit", "10"}); err != nil {
		t.Fatal(err)
	}
	// json / csv formats
	if err := cmdListCert(cfg, []string{"--format", "json"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdListCert(cfg, []string{"--format", "csv"}); err != nil {
		t.Fatal(err)
	}
	// limit truncation
	if err := cmdListCert(cfg, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	// empty result (unknown CA)
	if err := cmdListCert(cfg, []string{"--ca", "nope"}); err != nil {
		t.Fatal(err)
	}
}

func TestCmdPolicy(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}

	// help / no args
	if err := cmdPolicy(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// unknown subcommand
	if err := cmdPolicy(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}

	// missing flags
	if err := cmdPolicySign(cfg, nil); err == nil {
		t.Fatal("expected missing flags error")
	}
	// missing file
	if err := cmdPolicySign(cfg, []string{"--file", filepath.Join(dir, "nope.json"), "--cert", "x", "--key", "y"}); err == nil {
		t.Fatal("expected read error")
	}

	// happy path
	policyFile := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(policyFile, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := makeAdminCertPEM(t)
	certPath := filepath.Join(dir, "admin.pem")
	keyPath := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	sigOut := filepath.Join(dir, "authz.sig")
	if err := cmdPolicySign(cfg, []string{"--file", policyFile, "--cert", certPath, "--key", keyPath, "--out", sigOut}); err != nil {
		t.Fatalf("policy sign: %v", err)
	}
	// default out path (no --out)
	if err := cmdPolicySign(cfg, []string{"--file", policyFile, "--cert", certPath, "--key", keyPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(policyFile + ".sig"); err != nil {
		t.Fatal("expected default .sig output")
	}

	// bad cert / key parsing
	if err := cmdPolicySign(cfg, []string{"--file", policyFile, "--cert", certPath, "--key", filepath.Join(dir, "nope.key")}); err == nil {
		t.Fatal("expected key read error")
	}
	// non-admin OU cert
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "plain-user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key2.PublicKey, key2)
	nonAdminCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	nonAdminPath := filepath.Join(dir, "plain.pem")
	if err := os.WriteFile(nonAdminPath, nonAdminCert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPolicySign(cfg, []string{"--file", policyFile, "--cert", nonAdminPath, "--key", keyPath}); err == nil {
		t.Fatal("expected admin OU error")
	}
}

func TestCmdCRLVerify(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}

	// missing flags
	if err := cmdCRLVerify(cfg, nil); err == nil {
		t.Fatal("expected missing flags error")
	}
	// missing file
	if err := cmdCRLVerify(cfg, []string{"--in", filepath.Join(dir, "nope.crl"), "--cacert", "x"}); err == nil {
		t.Fatal("expected read error")
	}

	// generate a self-signed CA + CRL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crl-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, caCert, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(dir, "ca.pem")
	crlPath := filepath.Join(dir, "test.crl")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crlPath, crlDER, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCRLVerify(cfg, []string{"--in", crlPath, "--cacert", caPath}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// tampered CRL → invalid signature
	tampered := append([]byte{}, crlDER...)
	tampered[len(tampered)-1] ^= 0x01
	tamperedPath := filepath.Join(dir, "bad.crl")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCRLVerify(cfg, []string{"--in", tamperedPath, "--cacert", caPath}); err == nil {
		t.Fatal("expected signature invalid error")
	}
}

func TestCmdCrossCertCLI(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}

	// no subcommand
	if err := cmdCrossCert(cfg, nil); err == nil {
		t.Fatal("expected usage error")
	}
	// unknown subcommand
	if err := cmdCrossCert(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// list empty DB
	if err := cmdCrossCertList(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdCrossCertList(cfg, []string{"--issuer", "x"}); err != nil {
		t.Fatal(err)
	}
	// revoke missing flags
	if err := cmdCrossCertRevoke(cfg, nil); err == nil {
		t.Fatal("expected missing flags error")
	}
	// revoke unknown serial → not found error
	if err := cmdCrossCertRevoke(cfg, []string{"--issuer", "x", "--serial", "00", "--reason", "keyCompromise"}); err == nil {
		t.Fatal("expected not-found error")
	}
	// invalid reason
	if err := cmdCrossCertRevoke(cfg, []string{"--issuer", "x", "--serial", "00", "--reason", "bogus"}); err == nil {
		t.Fatal("expected invalid reason error")
	}
	// successful revoke with a real record
	d, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCrossCert(&db.CrossCertRecord{
		IssuerCA:     "issuer-ca",
		SubjectCA:    "target-ca",
		SerialNumber: "00AA",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Status:       "V",
		CertDER:      []byte{1, 2, 3},
	}); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := cmdCrossCertRevoke(cfg, []string{"--issuer", "issuer-ca", "--serial", "00AA", "--reason", "superseded"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// list now shows the revoked record
	if err := cmdCrossCertList(cfg, []string{"--issuer", "issuer-ca"}); err != nil {
		t.Fatal(err)
	}
	// issue missing args
	if err := cmdCrossCertIssue(cfg, nil); err == nil {
		t.Fatal("expected usage error")
	}
	if err := cmdCrossCertIssue(cfg, []string{"--issuer", "x"}); err == nil {
		t.Fatal("expected missing target error")
	}
	// invalid validity
	if err := cmdCrossCertIssue(cfg, []string{"--issuer", "x", "--target", "y", "--validity", "abc"}); err == nil {
		t.Fatal("expected invalid validity error")
	}
}

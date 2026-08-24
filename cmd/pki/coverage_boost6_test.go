// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

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
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/pkcs12"
)

func makeSubCA(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCmdImportCA(t *testing.T) {
	dir := t.TempDir()
	d, dbPath := newTestImportDB(t)
	defer d.Close()
	cfg := &internal.Config{DB: dbPath}

	caCert, caKey := newTestCACert(t)
	subCert, subKey := makeSubCA(t, caCert, caKey, "Import Sub CA")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	keyPEM, _ := ca.KeyToPEM(subKey)

	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// missing --name
	if err := cmdImportCA(cfg, []string{"--cert", certPath, "--key", keyPath}); err == nil {
		t.Fatal("expected --name required error")
	}
	// missing --cert
	if err := cmdImportCA(cfg, []string{"--name", "imp-ca", "--key", keyPath}); err == nil {
		t.Fatal("expected --cert required error")
	}
	// missing files
	if err := cmdImportCA(cfg, []string{"--name", "imp-ca", "--cert", filepath.Join(dir, "nope.pem"), "--key", keyPath}); err == nil {
		t.Fatal("expected read error")
	}

	// happy path
	cfgOut := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgOut, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImportCA(cfg, []string{"--name", "imp-ca", "--cert", certPath, "--key", keyPath, "--key-password", "testpass", "--write-config", cfgOut}); err != nil {
		t.Fatalf("import: %v", err)
	}
	// verify DB record
	meta, err := d.GetCAMeta("imp-ca")
	if err != nil || meta == nil {
		t.Fatalf("expected imported meta, got %v %v", meta, err)
	}
	// verify config entry
	cfgData, err := os.ReadFile(cfgOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfgData) == "{}" {
		t.Fatal("expected CA entry appended to config")
	}

	// import again → root CA safety check? self-signed CA rejected without --force
	// write-config missing file → appendCAConfig error path
	if err := cmdImportCA(cfg, []string{"--name", "imp-ca2", "--cert", certPath, "--key", keyPath, "--write-config", filepath.Join(dir, "nope.json")}); err == nil {
		t.Fatal("expected write-config error")
	}
}

func TestImportCARootSafetyAndP12(t *testing.T) {
	dir := t.TempDir()
	_, dbPath := newTestImportDB(t)
	cfg := &internal.Config{DB: dbPath}

	caCert, caKey := newTestCACert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	keyPEM, _ := ca.KeyToPEM(caKey)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// self-signed root rejected without --force
	if err := cmdImportCA(cfg, []string{"--name", "root-ca", "--cert", certPath, "--key", keyPath}); err == nil {
		t.Fatal("expected root CA rejection")
	}
	// with --force the CLI check is bypassed, but ImportExternalCA still refuses root keys
	if err := cmdImportCA(cfg, []string{"--name", "root-ca", "--cert", certPath, "--key", keyPath, "--force"}); err == nil {
		t.Fatal("expected root CA key import rejection")
	}

	// a non-self-signed sub-CA cert imports cleanly (with --force unused)
	subCert, subKey := makeSubCA(t, caCert, caKey, "Sub CA")
	subCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	subKeyPEM, _ := ca.KeyToPEM(subKey)
	subCertPath := filepath.Join(dir, "sub.pem")
	subKeyPath := filepath.Join(dir, "sub.key")
	if err := os.WriteFile(subCertPath, subCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(subKeyPath, subKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImportCA(cfg, []string{"--name", "sub-ca", "--cert", subCertPath, "--key", subKeyPath, "--key-password", "testpass"}); err != nil {
		t.Fatalf("import sub-ca: %v", err)
	}

	// p12 path
	p12Data, err := pkcs12.Encode(caKey, caCert, nil, "pfxpw")
	if err != nil {
		t.Fatal(err)
	}
	p12Path := filepath.Join(dir, "bundle.p12")
	if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImportCA(cfg, []string{"--name", "p12-ca", "--p12", p12Path, "--password", "pfxpw", "--force"}); err == nil {
		// p12 of a root CA: CLI force bypass accepted, but ImportExternalCA rejects
		// root keys — so we expect an error here too.
		t.Fatal("expected root CA key import rejection via p12")
	}
	// p12 wrong password (with a sub-CA bundle so only password failure remains)
	subP12, err := pkcs12.Encode(subKey, subCert, nil, "pfxpw")
	if err != nil {
		t.Fatal(err)
	}
	subP12Path := filepath.Join(dir, "sub.p12")
	if err := os.WriteFile(subP12Path, subP12, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImportCA(cfg, []string{"--name", "p12-bad", "--p12", subP12Path, "--password", "wrong"}); err == nil {
		t.Fatal("expected p12 decode error")
	}
	// p12 success with correct password
	if err := cmdImportCA(cfg, []string{"--name", "p12-good", "--p12", subP12Path, "--password", "pfxpw", "--key-password", "testpass"}); err != nil {
		t.Fatalf("import p12: %v", err)
	}
	// extractP12 direct error
	if _, _, err := extractP12([]byte("garbage"), "pw"); err == nil {
		t.Fatal("expected extractP12 error")
	}
}

func TestAppendCAConfig(t *testing.T) {
	dir := t.TempDir()
	// missing file
	if err := appendCAConfig(filepath.Join(dir, "nope.json"), "ca1", "cert.pem", "key.pem"); err == nil {
		t.Fatal("expected read error")
	}
	// invalid json
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendCAConfig(bad, "ca1", "cert.pem", "key.pem"); err == nil {
		t.Fatal("expected parse error")
	}
	// happy path with existing cas entry
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"cas":{"a":{"cert":"x"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendCAConfig(good, "ca1", "cert.pem", "key.pem"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(good)
	if len(data) == 0 {
		t.Fatal("expected written config")
	}
}

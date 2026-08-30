// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/signer"
	"github.com/varwof/engine/db"
)

// ---------- Key encrypt / decrypt ----------

func TestCLIKeyEncryptDecryptEC(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.KeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(inPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "enc.pem")
	decPath := filepath.Join(dir, "dec.pem")
	password := "test-password-123"

	cfg := &internal.Config{}

	// Encrypt
	if err := cmdKeyEncrypt(cfg, []string{
		"--in", inPath,
		"--out", encPath,
		"--password", password,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := os.Stat(encPath); err != nil {
		t.Fatal("encrypted file not created")
	}
	encData, _ := os.ReadFile(encPath)
	encBlock, _ := pem.Decode(encData)
	if encBlock == nil || encBlock.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatal("expected ENCRYPTED PRIVATE KEY PEM")
	}

	// Decrypt
	if err := cmdKeyDecrypt(cfg, []string{
		"--in", encPath,
		"--out", decPath,
		"--password", password,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	decData, _ := os.ReadFile(decPath)
	decBlock, _ := pem.Decode(decData)
	if decBlock == nil {
		t.Fatal("no PEM in decrypted key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(decBlock.Bytes)
	if err != nil {
		t.Fatalf("parse decrypted key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatal("decrypted key is not ECDSA")
	}
}

func TestCLIKeyEncryptDecryptRSA(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.KeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(inPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "rsa-enc.pem")
	decPath := filepath.Join(dir, "rsa-dec.pem")
	password := "rsa-password"

	cfg := &internal.Config{}
	if err := cmdKeyEncrypt(cfg, []string{
		"--in", inPath, "--out", encPath, "--password", password,
	}); err != nil {
		t.Fatalf("encrypt RSA: %v", err)
	}
	if err := cmdKeyDecrypt(cfg, []string{
		"--in", encPath, "--out", decPath, "--password", password,
	}); err != nil {
		t.Fatalf("decrypt RSA: %v", err)
	}
	decData, _ := os.ReadFile(decPath)
	decBlock, _ := pem.Decode(decData)
	parsed, err := x509.ParsePKCS8PrivateKey(decBlock.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatal("not RSA")
	}
}

func TestCLIKeyEncryptDecryptEd25519(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.KeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "ed.pem")
	if err := os.WriteFile(inPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "ed-enc.pem")
	decPath := filepath.Join(dir, "ed-dec.pem")
	password := "ed-pw"

	cfg := &internal.Config{}
	if err := cmdKeyEncrypt(cfg, []string{
		"--in", inPath, "--out", encPath, "--password", password,
	}); err != nil {
		t.Fatalf("encrypt Ed25519: %v", err)
	}
	if err := cmdKeyDecrypt(cfg, []string{
		"--in", encPath, "--out", decPath, "--password", password,
	}); err != nil {
		t.Fatalf("decrypt Ed25519: %v", err)
	}
	decData, _ := os.ReadFile(decPath)
	decBlock, _ := pem.Decode(decData)
	parsed, err := x509.ParsePKCS8PrivateKey(decBlock.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Fatal("not Ed25519")
	}
}

func TestCLIKeyEncryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, _ := ca.KeyToPEM(key)
	inPath := filepath.Join(dir, "k.pem")
	os.WriteFile(inPath, keyPEM, 0600)
	encPath := filepath.Join(dir, "e.pem")

	cfg := &internal.Config{}
	if err := cmdKeyEncrypt(cfg, []string{
		"--in", inPath, "--out", encPath, "--password", "ok",
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdKeyDecrypt(cfg, []string{
		"--in", encPath, "--out", filepath.Join(dir, "d.pem"), "--password", "wrong",
	}); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestCLIKeyEncryptMissingFlags(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdKeyEncrypt(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
	if err := cmdKeyDecrypt(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

func TestCLIKeyEncryptBadInput(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdKeyEncrypt(cfg, []string{
		"--in", "/nonexistent", "--out", "/tmp/x", "--password", "pw",
	})
	if err == nil {
		t.Fatal("expected error for bad input")
	}
}

// ---------- Completion ----------

func TestCLICompletionBash(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCompletion(cfg, []string{"bash"}); err != nil {
		t.Fatalf("bash completion: %v", err)
	}
}

func TestCLICompletionZsh(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCompletion(cfg, []string{"zsh"}); err != nil {
		t.Fatalf("zsh completion: %v", err)
	}
}

func TestCLICompletionFish(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCompletion(cfg, []string{"fish"}); err != nil {
		t.Fatalf("fish completion: %v", err)
	}
}

func TestCLICompletionNoArgs(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdCompletion(cfg, []string{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCLICompletionUnsupported(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCompletion(cfg, []string{"tcsh"}); err == nil {
		t.Fatal("expected error for unsupported shell")
	}
}

// ---------- Init config ----------

func TestCLIInitConfig(t *testing.T) {
	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	cfg := &internal.Config{}
	if err := cmdInitConfig(cfg, []string{}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)

	output := buf.Bytes()
	if len(output) == 0 {
		t.Fatal("expected non-empty output")
	}

	// Verify it's valid JSON
	var parsed any
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	m, ok := parsed.(map[string]any)
	if !ok {
		t.Fatal("expected JSON object")
	}
	if m["db"] == nil {
		t.Fatal("expected db field")
	}
	if m["cas"] == nil {
		t.Fatal("expected cas field")
	}
}

func TestSampleConfigPath(t *testing.T) {
	path := sampleConfigPath()
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if !strings.HasSuffix(path, "pki.json") {
		t.Fatalf("expected goca.json, got %q", path)
	}
}

// ---------- Renew ----------

func writeCACertKey(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA " + name},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, _ := ca.KeyToPEM(key)

	certPath = filepath.Join(dir, name+"-ca.pem")
	keyPath = filepath.Join(dir, name+"-ca.key")
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)
	return certPath, keyPath
}

func issueTestCert(t *testing.T, database *db.DB, caCert *x509.Certificate, caKey crypto.Signer, caName, cn string) (serial string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result, err := ca.Sign(&ca.SignConfig{
		DB:            database,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        caName,
		Profile:       ca.ProfileTLSServer,
		CommonName:    cn,
		SubjectPubKey: key.Public(),
		SANs:          []string{"DNS:" + cn},
		Validity:      90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return result.SerialHex
}

func TestCLIRenewBySerial(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "test")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	caCertPEM, _ := os.ReadFile(caCertPath)
	os.WriteFile(filepath.Join(dir, "ca.pem"), caCertPEM, 0644)

	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"test-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			CA:      "test-ca",
			KeyType: "ecdsa-p256",
		},
	}

	// Register the CA cert
	if err := registerCACert(d, "test-ca", caCertPath); err != nil {
		t.Fatal(err)
	}

	// Load CA cert for sign
	caCert, caKey, err := ca.LoadSigner(caCertPath, caKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	serial := issueTestCert(t, d, caCert, caKey, "test-ca", "renew-test.example.com")

	outDir := filepath.Join(dir, "renewed")
	os.MkdirAll(outDir, 0755)

	if err := cmdRenew(cfg, []string{
		"--ca", "test-ca",
		"--serial", serial,
		"--out-dir", outDir,
		"--validity", "30",
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// Check renewed cert was written
	entries, _ := os.ReadDir(outDir)
	if len(entries) == 0 {
		t.Fatal("expected renewed cert output")
	}
}

func TestCLIRenewByCertFile(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "test2")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"test-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			CA:      "test-ca",
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "test-ca", caCertPath)
	caCert, caKey, _ := ca.LoadSigner(caCertPath, caKeyPath)

	// Issue and save cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result, err := ca.Sign(&ca.SignConfig{
		DB: d, CAKey: caKey, CACert: caCert, CAName: "test-ca",
		Profile: ca.ProfileTLSServer, CommonName: "file-renew.example.com",
		SubjectPubKey: key.Public(), SANs: []string{"DNS:file-renew.example.com"},
		Validity: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	certPEM := ca.CertToPEM(result.CertDER)
	certPath := filepath.Join(dir, "old.pem")
	os.WriteFile(certPath, certPEM, 0644)

	outDir := filepath.Join(dir, "renewed2")
	os.MkdirAll(outDir, 0755)

	if err := cmdRenew(cfg, []string{
		"--cert", certPath,
		"--ca", "test-ca",
		"--out-dir", outDir,
		"--validity", "30",
	}); err != nil {
		t.Fatalf("renew from file: %v", err)
	}

	entries, _ := os.ReadDir(outDir)
	if len(entries) == 0 {
		t.Fatal("expected output files")
	}
}

func TestCLIRenewKeepKey(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "kk")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"test-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			CA:      "test-ca",
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "test-ca", caCertPath)
	caCert, caKey, _ := ca.LoadSigner(caCertPath, caKeyPath)

	// Issue cert with keepable key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, _ := ca.KeyToPEM(key)
	keyPath := filepath.Join(dir, "orig.key")
	os.WriteFile(keyPath, keyPEM, 0600)

	result, err := ca.Sign(&ca.SignConfig{
		DB: d, CAKey: caKey, CACert: caCert, CAName: "test-ca",
		Profile: ca.ProfileTLSServer, CommonName: "keep-key.example.com",
		SubjectPubKey: key.Public(), SANs: []string{"DNS:keep-key.example.com"},
		Validity: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certPEM := ca.CertToPEM(result.CertDER)
	certPath := filepath.Join(dir, "kk.pem")
	os.WriteFile(certPath, certPEM, 0644)

	outDir := filepath.Join(dir, "kk-out")
	os.MkdirAll(outDir, 0755)

	if err := cmdRenew(cfg, []string{
		"--cert", certPath,
		"--ca", "test-ca",
		"--keep-key",
		"--key", keyPath,
		"--out-dir", outDir,
		"--validity", "30",
	}); err != nil {
		t.Fatalf("renew keep-key: %v", err)
	}

	// With --keep-key, no .key file is written (only cert)
	entries, _ := os.ReadDir(outDir)
	foundCert := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pem") && !strings.HasSuffix(e.Name(), ".key") {
			foundCert = true
			break
		}
	}
	if !foundCert {
		t.Fatal("expected cert PEM output")
	}
}

func TestCLIRenewMissingFlags(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRenew(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

func TestCLIRenewKeepKeyMissingKey(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdRenew(cfg, []string{
		"--cert", "/some/cert.pem",
		"--ca", "test",
		"--keep-key",
	})
	if err == nil {
		t.Fatal("expected error for --keep-key without --key")
	}
}

// ---------- Batch ----------

func TestCLIBatchCSV(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "batch")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"batch-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			CA:      "batch-ca",
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "batch-ca", caCertPath)

	csvPath := filepath.Join(dir, "batch.csv")
	csvContent := "cn,san,profile,validity\n" +
		"batch-a.example.com,DNS:batch-a.example.com,tls-server,30\n" +
		"batch-b.example.com,DNS:batch-b.example.com,tls-server,30\n"
	os.WriteFile(csvPath, []byte(csvContent), 0644)

	outDir := filepath.Join(dir, "batch-out")
	os.MkdirAll(outDir, 0755)

	if err := cmdBatch(cfg, []string{
		"--ca", "batch-ca",
		"--csv", csvPath,
		"--out-dir", outDir,
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}

	entries, _ := os.ReadDir(outDir)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 output files, got %d", len(entries))
	}
}

func TestCLIBatchCSVMissingFile(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdBatch(cfg, []string{
		"--ca", "test",
		"--csv", "/nonexistent.csv",
	}); err == nil {
		t.Fatal("expected error for missing CSV")
	}
}

func TestCLIBatchCSVBadContent(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "bad.csv")
	os.WriteFile(csvPath, []byte("not,valid,header\n"), 0644)

	cfg := &internal.Config{}
	if err := cmdBatch(cfg, []string{
		"--ca", "test",
		"--csv", csvPath,
	}); err == nil {
		t.Fatal("expected error for bad CSV")
	}
}

// ---------- CA info / CA list ----------

func TestCLICAListAndInfo(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "listinfo")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"listinfo-ca": {Cert: caCertPath, Key: caKeyPath},
		},
	}
	registerCACert(d, "listinfo-ca", caCertPath)

	if err := cmdCAList(cfg, []string{}); err != nil {
		t.Fatalf("ca-list: %v", err)
	}

	if err := cmdCAInfo(cfg, []string{"--name", "listinfo-ca"}); err != nil {
		t.Fatalf("ca-info: %v", err)
	}
}

func TestCLICAInfoMissing(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCAInfo(cfg, []string{"--name", "nonexistent"}); err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

// ---------- Revoke / CRL ----------

func newTestDBPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir + "/pki.db"
}

func setupTestCA(t *testing.T, dir string) (*db.DB, *internal.Config, *x509.Certificate, crypto.Signer) {
	t.Helper()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "revtest")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"rev-ca": {Cert: caCertPath, Key: caKeyPath},
		},
	}
	registerCACert(d, "rev-ca", caCertPath)
	caCert, caKey, _ := ca.LoadSigner(caCertPath, caKeyPath)
	return d, cfg, caCert, caKey
}

func TestCLIRevokeAndCRL(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "revoke-me.example.com")

	if err := cmdRevoke(cfg, []string{
		"--ca", "rev-ca",
		"--serial", serial,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	rec, err := d.GetCert("rev-ca", serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "R" {
		t.Fatalf("expected revoked status, got %q", rec.Status)
	}

	// Generate CRL
	crlPath := filepath.Join(dir, "test.crl")
	if err := cmdCRL(cfg, []string{
		"--ca", "rev-ca",
		"--out", crlPath,
	}); err != nil {
		t.Fatalf("crl: %v", err)
	}
	if _, err := os.Stat(crlPath); err != nil {
		t.Fatal("CRL file not created")
	}
}

func TestCLIRevokeWithReason(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "reason.example.com")

	if err := cmdRevoke(cfg, []string{
		"--ca", "rev-ca",
		"--serial", serial,
		"--reason", "keyCompromise",
	}); err != nil {
		t.Fatalf("revoke with reason: %v", err)
	}

	rec, err := d.GetCert("rev-ca", serial)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RevokeReason == nil || *rec.RevokeReason != 1 {
		t.Fatalf("expected reason 1 (keyCompromise), got %v", rec.RevokeReason)
	}
}

// ---------- Issue ----------

func TestCLIIssue(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "issue")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"issue-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "issue-ca", caCertPath)

	if err := cmdIssue(cfg, []string{
		"--ca", "issue-ca",
		"--cn", "issue-test.example.com",
		"--san", "DNS:issue-test.example.com",
		"--out", filepath.Join(dir, "issued.pem"),
		"--out-key", filepath.Join(dir, "issued.key"),
		"--profile", "tls-server",
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "issued.pem")); err != nil {
		t.Fatalf("expected cert output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "issued.key")); err != nil {
		t.Fatalf("expected key output: %v", err)
	}
}

func TestCLIIssueWithSubject(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "issue-subj")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"issue-subj-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "issue-subj-ca", caCertPath)

	if err := cmdIssue(cfg, []string{
		"--ca", "issue-subj-ca",
		"--cn", "subject-test.example.com",
		"--san", "DNS:subject-test.example.com",
		"--subject", "/C=US/ST=CA/L=SF/O=Test/CN=subject-test.example.com",
		"--profile", "tls-server",
		"--out", filepath.Join(dir, "subj-issued.pem"),
		"--out-key", filepath.Join(dir, "subj-issued.key"),
	}); err != nil {
		t.Fatalf("issue with subject: %v", err)
	}
}

func TestCLIIssueFromCSR(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "issue-csr")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"issue-csr-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "csr-only.example.com"},
		DNSNames:    []string{"csr-only.example.com", "alt.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.1.2.3")},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(dir, "req.csr")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}
	registerCACert(d, "issue-csr-ca", caCertPath)

	certOut := filepath.Join(dir, "csr-issued.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "issue-csr-ca",
		"--csr", csrPath,
		"--san", "DNS:csr-only.example.com",
		"--profile", "tls-server",
		"--out", certOut,
	}); err != nil {
		t.Fatalf("issue from csr: %v", err)
	}

	// No private key should be written in CSR mode.
	if _, err := os.Stat(filepath.Join(dir, "csr-issued.key")); !os.IsNotExist(err) {
		t.Fatalf("expected no key file in CSR mode, stat err=%v", err)
	}

	// Cert must carry the CSR public key and CN from the CSR subject.
	certPEM, err := os.ReadFile(certOut)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in cert output")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	csrPubBytes, err := x509.MarshalPKIXPublicKey(csrKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	certPubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csrPubBytes, certPubBytes) {
		t.Fatal("cert public key does not match CSR public key")
	}
	if cert.Subject.CommonName != "csr-only.example.com" {
		t.Fatalf("expected CN from CSR subject, got %q", cert.Subject.CommonName)
	}
	// SANs must be inherited from the CSR (DNS + IP), matching the API path.
	if !slices.Contains(cert.DNSNames, "csr-only.example.com") || !slices.Contains(cert.DNSNames, "alt.example.com") {
		t.Fatalf("expected CSR DNS SANs in cert, got %v", cert.DNSNames)
	}
	if !slices.ContainsFunc(cert.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.ParseIP("10.1.2.3")) }) {
		t.Fatalf("expected CSR IP SAN in cert, got %v", cert.IPAddresses)
	}
}

func TestCLIIssueFromCSRRejectsBadSignature(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "issue-csr-bad")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"issue-csr-bad-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "issue-csr-bad-ca", caCertPath)

	// Build a CSR with one key, then re-sign the DER with a different key to
	// force a signature mismatch.
	goodKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "bad.example.com"},
		DNSNames: []string{"bad.example.com"},
	}, goodKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := ecdsa.SignASN1(rand.Reader, badKey, parsed.RawTBSCertificateRequest)
	if err != nil {
		t.Fatal(err)
	}
	// Re-wrap the original TBS with a signature produced by a different key.
	// CertificateRequest ::= SEQUENCE { certRequestInfo, sigAlg, signature }
	type csrSigAlg struct {
		Algorithm asn1.ObjectIdentifier
	}
	outer := struct {
		TBS       asn1.RawValue
		SigAlg    csrSigAlg
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: parsed.RawTBSCertificateRequest},
		SigAlg:    csrSigAlg{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature: asn1.BitString{Bytes: badSig, BitLength: len(badSig) * 8},
	}
	tbs, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(dir, "bad.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tbs}), 0644); err != nil {
		t.Fatal(err)
	}

	err = cmdIssue(cfg, []string{
		"--ca", "issue-csr-bad-ca",
		"--csr", csrPath,
		"--cn", "bad.example.com",
		"--profile", "tls-server",
	})
	if err == nil {
		t.Fatal("expected error for tampered CSR signature")
	}
}

// ---------- Recorder (newTestDB helper similar to import_test) ----------

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(dir + "/pki.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// ---------- Hash / detectProfile / extractSANs edge cases ----------

func TestParseHashEdge(t *testing.T) {
	if parseHash("") != crypto.SHA256 {
		t.Fatal("empty should default to SHA256")
	}
	if parseHash("sha512") != crypto.SHA512 {
		t.Fatal("sha512")
	}
}

func TestDetectProfileDocumentOnly(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageContentCommitment,
	}
	if got := detectProfile(cert); got != ca.ProfileDocument {
		t.Fatalf("expected document, got %q", got)
	}
}

func TestExtractSANsIPAndURI(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com"},
		EmailAddresses: []string{"a@b.com"},
	}
	// IPAddresses and URIs need actual parsed values
	sans := extractSANs(cert)
	foundDNS := false
	foundEmail := false
	for _, s := range sans {
		if s == "DNS:example.com" {
			foundDNS = true
		}
		if s == "email:a@b.com" {
			foundEmail = true
		}
	}
	if !foundDNS || !foundEmail {
		t.Fatalf("missing expected SANs: %v", sans)
	}
}

// ---------- DB backup ----------

func TestCLIDBBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure DB is fully written before backup.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(dir, "backup.db")
	cfg := &internal.Config{DB: dbPath}

	if err := cmdDBBackup(cfg, []string{"--out", backupPath}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	fi, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal("backup file not created")
	}
	if fi.Size() == 0 {
		t.Fatal("backup file is empty")
	}
}

func TestCLIDBBackupDefaultPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	cfg := &internal.Config{DB: dbPath}
	if err := cmdDBBackup(cfg, []string{}); err != nil {
		t.Fatalf("backup default: %v", err)
	}
	defaultPath := dbPath + ".backup"
	if _, err := os.Stat(defaultPath); err != nil {
		t.Fatal("default backup path not created")
	}
	os.Remove(defaultPath)
}

func TestCLIDBBackupNoDBPath(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdDBBackup(cfg, []string{}); err == nil {
		t.Fatal("expected error for no db path")
	}
}

func TestCLIDBBackupBadDBPath(t *testing.T) {
	cfg := &internal.Config{DB: "/nonexistent/db"}
	if err := cmdDBBackup(cfg, []string{}); err == nil {
		t.Fatal("expected error for bad db path")
	}
}

func TestCLIDBNoSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdDB(cfg, []string{}); err == nil {
		t.Fatal("expected error for no subcommand")
	}
}

func TestCLIDBBadSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdDB(cfg, []string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestCLIDBInitSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nested", "pki.db")
	cfg := &internal.Config{DB: dbPath}

	// First run: auto-create parent dirs + init DB + migrate to latest version.
	if err := cmdDBInit(cfg, []string{}); err != nil {
		t.Fatalf("db init: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("db file not created: %v", err)
	}

	// Idempotent: second run produces no error.
	if err := cmdDBInit(cfg, []string{}); err != nil {
		t.Fatalf("db init (2nd): %v", err)
	}
}

func TestCLIDBInitSQLiteDSNFlag(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := &internal.Config{DB: "/nonexistent/should-be-overridden.db"}
	if err := cmdDBInit(cfg, []string{"--dsn", dbPath}); err != nil {
		t.Fatalf("db init --dsn: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("dsn-flagged db file not created: %v", err)
	}
}

func TestCLIDBInitNoDBPath(t *testing.T) {
	if os.Getenv("DATABASE_URL") != "" {
		t.Skip("DATABASE_URL set; cannot test empty-dsn path")
	}
	cfg := &internal.Config{}
	if err := cmdDBInit(cfg, []string{}); err == nil {
		t.Fatal("expected error for no db path")
	}
}

// ---------- cmdKey dispatcher ----------

func TestCLIKeyNoSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdKey(cfg, []string{}); err == nil {
		t.Fatal("expected error for no subcommand")
	}
}

func TestCLIKeyBadSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdKey(cfg, []string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// ---------- cmdVersion + printUsage ----------

func TestCLIVersion(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdVersion(cfg, []string{}); err != nil {
		t.Fatalf("version: %v", err)
	}
}

func TestCLIUsage(t *testing.T) {
	// printUsage should not panic or error; capture output.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "Usage:") {
		t.Fatal("usage output missing Usage header")
	}
	if !strings.Contains(out, "verify") {
		t.Fatal("usage output missing verify command")
	}
}

// ---------- RA CLI ----------

func TestCLIRAFullFlow(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ra")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"ra-ca": {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}
	registerCACert(d, "ra-ca", caCertPath)

	// Generate CSR
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ra-test.example.com"},
		DNSNames: []string{"ra-test.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(dir, "ra.csr")
	os.WriteFile(csrPath, csrPEM, 0644)

	// Submit
	if err := cmdRA(cfg, []string{
		"submit",
		"--csr", csrPath,
		"--cn", "ra-test.example.com",
		"--ca", "ra-ca",
		"--profile", "tls-server",
		"--approvals", "1",
	}); err != nil {
		t.Fatalf("ra submit: %v", err)
	}

	// List
	if err := cmdRA(cfg, []string{"list"}); err != nil {
		t.Fatalf("ra list: %v", err)
	}

	// Show pending
	if err := cmdRA(cfg, []string{"show", "--id", "1"}); err != nil {
		t.Fatalf("ra show: %v", err)
	}

	// Approve (threshold=1, so cert should be issued)
	if err := cmdRA(cfg, []string{"approve", "--id", "1"}); err != nil {
		t.Fatalf("ra approve: %v", err)
	}

	// Show issued
	if err := cmdRA(cfg, []string{"show", "--id", "1"}); err != nil {
		t.Fatalf("ra show after approve: %v", err)
	}
}

func TestCLIRASubmitMissingFlags(t *testing.T) {
	cfg := &internal.Config{
		DB: filepath.Join(t.TempDir(), "pki.db"),
	}
	if err := cmdRA(cfg, []string{"submit", "--cn", "x"}); err == nil {
		t.Fatal("expected error for missing --csr")
	}
	if err := cmdRA(cfg, []string{"submit", "--csr", "/tmp/fake.csr"}); err == nil {
		t.Fatal("expected error for missing --cn")
	}
}

func TestCLIRAApproveMissingID(t *testing.T) {
	cfg := &internal.Config{
		DB: filepath.Join(t.TempDir(), "pki.db"),
	}
	if err := cmdRA(cfg, []string{"approve"}); err == nil {
		t.Fatal("expected error for missing --id")
	}
}

func TestCLIRAReject(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ra-rej")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"ra-rej-ca": {Cert: caCertPath, Key: caKeyPath},
		},
	}
	registerCACert(d, "ra-rej-ca", caCertPath)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "reject-test.example.com"},
	}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(dir, "rej.csr")
	os.WriteFile(csrPath, csrPEM, 0644)

	if err := cmdRA(cfg, []string{
		"submit",
		"--csr", csrPath,
		"--cn", "reject-test.example.com",
		"--ca", "ra-rej-ca",
		"--profile", "tls-server",
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if err := cmdRA(cfg, []string{"reject", "--id", "1", "--reason", "not needed"}); err != nil {
		t.Fatalf("reject: %v", err)
	}
}

func TestCLIRARejectMissingID(t *testing.T) {
	cfg := &internal.Config{
		DB: filepath.Join(t.TempDir(), "pki.db"),
	}
	if err := cmdRA(cfg, []string{"reject"}); err == nil {
		t.Fatal("expected error for missing --id")
	}
}

func TestCLIRAShowMissingID(t *testing.T) {
	cfg := &internal.Config{
		DB: filepath.Join(t.TempDir(), "pki.db"),
	}
	if err := cmdRA(cfg, []string{"show"}); err == nil {
		t.Fatal("expected error for missing --id")
	}
}

func TestCLIRABadSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRA(cfg, []string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestCLIRANoSubcommand(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRA(cfg, []string{}); err == nil {
		t.Fatal("expected error for no subcommand")
	}
}

// ---------- Recover missing flags ----------

func TestCLIRecoverMissingFlags(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRecover(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

// ---------- User CLI ----------

func TestCLIUserNoArgs(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdUser(cfg, []string{}); err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestCLIUserBadSubcommand(t *testing.T) {
	if err := cmdUser(&internal.Config{}, []string{"badcmd"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestCLIUserAddMissingFlags(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

func TestCLIUserAdd(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "alice", "--password", "Secret123", "--role", "admin"}); err != nil {
		t.Fatalf("add user: %v", err)
	}
	user, err := d.GetUserByUsername("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != "admin" {
		t.Fatalf("expected admin role, got %s", user.Role)
	}
}

func TestCLIUserDeleteMissingFlag(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserDelete(d, []string{}); err == nil {
		t.Fatal("expected error for missing --username")
	}
}

func TestCLIUserDeleteNotFound(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserDelete(d, []string{"--username", "nonexistent"}); err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestCLIUserDelete(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "bob", "--password", "Pass1234"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdUserDelete(d, []string{"--username", "bob"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.GetUserByUsername("bob"); err == nil {
		t.Fatal("expected user to be deleted")
	}
}

func TestCLIUserListEmpty(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserList(d); err != nil {
		t.Fatalf("list: %v", err)
	}
}

func TestCLIUserPasswdMissingFlags(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserPasswd(d, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

func TestCLIUserPasswdNotFound(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserPasswd(d, []string{"--username", "nobody", "--password", "Newpass1"}); err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestCLIUserPasswd(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "charlie", "--password", "Oldpass1"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdUserPasswd(d, []string{"--username", "charlie", "--password", "Newpass1"}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
}

func TestCLIUserBindOperatorCert(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "op", "--password", "Secret123", "--role", "operator"}); err != nil {
		t.Fatal(err)
	}

	// Missing parameters
	if err := cmdUserBindOperatorCert(d, []string{}); err == nil {
		t.Fatal("expected error for missing flags")
	}

	// Generate an m-operator management cert (scope=Client CA) and write to PEM file
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "test")
	caCertPEM, _ := os.ReadFile(caCertPath)
	caKeyPEM, _ := os.ReadFile(caKeyPath)
	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ca.ParsePrivateKey(caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	res, err := ca.Sign(&ca.SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test",
		Profile:       ca.ProfileMOperator,
		CommonName:    "op-cert",
		SubjectPubKey: leafKey.Public(),
		Scope:         "Client CA",
		Validity:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("sign m-operator: %v", err)
	}
	certPEM := ca.CertToPEM(res.CertDER)

	certFile := filepath.Join(dir, "op-cert.pem")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := cmdUserBindOperatorCert(d, []string{"--username", "op", "--cert", certFile}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	user, err := d.GetUserByUsername("op")
	if err != nil {
		t.Fatal(err)
	}
	if user.OperatorCertPEM == "" {
		t.Fatal("expected operator cert to be stored")
	}

	// Invalid cert → reject
	badFile := filepath.Join(dir, "bad.pem")
	os.WriteFile(badFile, []byte("not a pem"), 0644)
	if err := cmdUserBindOperatorCert(d, []string{"--username", "op", "--cert", badFile}); err == nil {
		t.Fatal("expected error for invalid cert")
	}

	// Revoked cert → reject (fail-closed, consistent with API)
	if err := d.RevokeCert("test", res.SerialHex, 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := cmdUserBindOperatorCert(d, []string{"--username", "op", "--cert", certFile}); err == nil {
		t.Fatal("expected error for revoked operator cert")
	}

	// Unbind
	if err := cmdUserUnbindOperatorCert(d, []string{"--username", "op"}); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	user, _ = d.GetUserByUsername("op")
	if user.OperatorCertPEM != "" {
		t.Fatal("expected operator cert cleared after unbind")
	}
}

// ---------- Token CLI ----------

func TestCLITokenNoArgs(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdToken(cfg, []string{}); err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestCLITokenBadSubcommand(t *testing.T) {
	if err := cmdToken(&internal.Config{}, []string{"badcmd"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestCLITokenCreateMissingFlag(t *testing.T) {
	d := newTestDB(t)
	if err := cmdTokenCreate(d, []string{}); err == nil {
		t.Fatal("expected error for missing --username")
	}
}

func TestCLITokenCreateNotFound(t *testing.T) {
	d := newTestDB(t)
	if err := cmdTokenCreate(d, []string{"--username", "nobody"}); err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestCLITokenCreate(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "tokenuser", "--password", "Pass1234"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTokenCreate(d, []string{"--username", "tokenuser", "--description", "test-token"}); err != nil {
		t.Fatalf("create token: %v", err)
	}
}

func TestCLITokenListMissingFlag(t *testing.T) {
	d := newTestDB(t)
	if err := cmdTokenList(d, []string{}); err == nil {
		t.Fatal("expected error for missing --username")
	}
}

func TestCLITokenListNotFound(t *testing.T) {
	d := newTestDB(t)
	if err := cmdTokenList(d, []string{"--username", "nobody"}); err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestCLITokenList(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "listuser", "--password", "Pass1234"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTokenCreate(d, []string{"--username", "listuser", "--description", "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTokenList(d, []string{"--username", "listuser"}); err != nil {
		t.Fatalf("list: %v", err)
	}
}

func TestCLITokenRevokeMissingFlag(t *testing.T) {
	d := newTestDB(t)
	if err := cmdTokenRevoke(d, []string{}); err == nil {
		t.Fatal("expected error for missing --id")
	}
}

func TestCLITokenRevoke(t *testing.T) {
	d := newTestDB(t)
	if err := cmdUserAdd(d, []string{"--username", "revokeuser", "--password", "Pass1234"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTokenCreate(d, []string{"--username", "revokeuser", "--description", "to-revoke"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTokenRevoke(d, []string{"--id", "1"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// ---------- Audit CLI ----------

func TestCLIAuditEmpty(t *testing.T) {
	cfg := &internal.Config{DB: newTestDBPath(t)}
	if err := cmdAudit(cfg, []string{}); err != nil {
		t.Fatalf("audit empty: %v", err)
	}
}

func TestCLIAuditVerifyEmpty(t *testing.T) {
	cfg := &internal.Config{DB: newTestDBPath(t)}
	if err := cmdAudit(cfg, []string{"verify"}); err != nil {
		t.Fatalf("audit verify empty: %v", err)
	}
}

// ---------- CT submit error paths ----------

func TestCLICTSubmitMissingURL(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ct-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certFile := filepath.Join(dir, "cert.pem")
	os.WriteFile(certFile, certPEM, 0644)

	cfg := &internal.Config{CTLog: internal.CTLogConfig{}}
	err := cmdCTSubmit(cfg, []string{"--cert", certFile})
	if err == nil {
		t.Fatal("expected error for missing CT log URL")
	}
}

func TestCLICTSubmitMissingCert(t *testing.T) {
	cfg := &internal.Config{CTLog: internal.CTLogConfig{URL: "https://example.com/ct"}}
	if err := cmdCTSubmit(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing --cert")
	}
}

func TestCLICTSubmitBadPEM(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "bad.pem")
	os.WriteFile(certFile, []byte("not a pem"), 0644)
	cfg := &internal.Config{CTLog: internal.CTLogConfig{URL: "https://example.com/ct"}}
	if err := cmdCTSubmit(cfg, []string{"--cert", certFile}); err == nil {
		t.Fatal("expected error for bad PEM")
	}
}

func TestCLICTSubmitMissingFile(t *testing.T) {
	cfg := &internal.Config{CTLog: internal.CTLogConfig{URL: "https://example.com/ct"}}
	if err := cmdCTSubmit(cfg, []string{"--cert", "/nonexistent/cert.pem"}); err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

// ---------- addCAdESTimestampToFile ----------

func TestAddCAdESTimestampMissingFile(t *testing.T) {
	if err := addCAdESTimestampToFile("/nonexistent/sig.p7s", nil); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAddCAdESTimestampValid(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(filePath, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath, err := signer.SignDetached(filePath, &signer.Config{
		Cert: cert,
		Key:  key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := addCAdESTimestampToFile(sigPath, nil); err != nil {
		t.Fatalf("add timestamp: %v", err)
	}
	data, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty sig file after timestamp")
	}
}

// ---------- loadTSAConfig ----------

func writeSignerKey(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Signer " + name},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, _ := ca.KeyToPEM(key)
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)
	return
}

func TestLoadTSAConfigMissingCert(t *testing.T) {
	cfg := &internal.Config{}
	if _, _, err := loadTSAConfig(cfg); err == nil {
		t.Fatal("expected error when TSA cert not configured")
	}
}

func TestLoadTSAConfigSuccess(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSignerKey(t, dir, "tsa")
	cfg := &internal.Config{
		TSA: internal.TSAConfig{
			SignerCert: certPath,
			SignerKey:  keyPath,
		},
	}
	h, _, err := loadTSAConfig(cfg)
	if err != nil {
		t.Fatalf("load TSA config: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

// ---------- loadOCSPConfig ----------

func TestLoadOCSPConfigMissingSigner(t *testing.T) {
	d := newTestDB(t)
	cfg := &internal.Config{Defaults: internal.DefaultsConfig{CA: "testca"}}
	if _, err := loadOCSPConfig(cfg, d); err == nil {
		t.Fatal("expected error for missing OCSP signer")
	}
}

func TestLoadOCSPConfigSuccess(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ocsptest")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ocspCertPath, ocspKeyPath := writeSignerKey(t, dir, "ocsp")
	cfg := &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			CA: "ocsptest",
		},
		CAs: map[string]internal.CAConfig{
			"ocsptest": {Cert: caCertPath, Key: caKeyPath},
		},
		OCSP: internal.OCSPConfig{
			SignerCert: ocspCertPath,
			SignerKey:  ocspKeyPath,
		},
	}
	h, err := loadOCSPConfig(cfg, d)
	if err != nil {
		t.Fatalf("load OCSP config: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestLoadOCSPConfigWithCache(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ocspcache")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ocspCertPath, ocspKeyPath := writeSignerKey(t, dir, "ocspsigner")
	cfg := &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			CA: "ocspcache",
		},
		CAs: map[string]internal.CAConfig{
			"ocspcache": {Cert: caCertPath, Key: caKeyPath},
		},
		OCSP: internal.OCSPConfig{
			SignerCert: ocspCertPath,
			SignerKey:  ocspKeyPath,
			CacheSize:  100,
			CacheTTL:   "30m",
		},
	}
	h, err := loadOCSPConfig(cfg, d)
	if err != nil {
		t.Fatalf("load OCSP config with cache: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

// ---------- issueSigner ----------

func TestIssueSignerMissingCA(t *testing.T) {
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{}}
	_, _, _, err := issueSigner(cfg, "nonexistent", "", "", "")
	if err == nil {
		t.Fatal("expected error for missing CA")
	}
}

func TestIssueSignerSuccess(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "issuer")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			CA:      "issuer",
			KeyType: "ecdsa-p256",
		},
		CAs: map[string]internal.CAConfig{
			"issuer": {Cert: caCertPath, Key: caKeyPath},
		},
	}
	cert, key, chain, err := issueSigner(cfg, "issuer", "", "test-signer", "tls-server")
	if err != nil {
		t.Fatalf("issue signer: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if len(chain) == 0 {
		t.Fatal("expected non-empty chain")
	}
}

func TestIssueSignerWithChainPath(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "cachain")
	rootCertPath, _ := writeCACertKey(t, dir, "rootchain")
	dbPath := newTestDBPath(t)
	d, _ := db.Open(dbPath)
	d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			CA:      "cachain",
			KeyType: "ecdsa-p256",
		},
		CAs: map[string]internal.CAConfig{
			"cachain": {Cert: caCertPath, Key: caKeyPath},
		},
	}
	cert, key, chain, err := issueSigner(cfg, "cachain", rootCertPath, "", "")
	if err != nil {
		t.Fatalf("issue with chain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if len(chain) < 2 {
		t.Fatalf("expected chain of 2+, got %d", len(chain))
	}
}

func TestIssueSignerWithRootCAChain(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "subca")
	rootCertPath, _ := writeCACertKey(t, dir, "rootca")
	dbPath := newTestDBPath(t)
	d, _ := db.Open(dbPath)
	d.Close()

	cfg := &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			CA:      "subca",
			KeyType: "ecdsa-p256",
		},
		CAs: map[string]internal.CAConfig{
			"subca": {Cert: caCertPath, Key: caKeyPath},
			"root":  {Cert: rootCertPath},
		},
	}
	_, _, chain, err := issueSigner(cfg, "subca", "", "", "tls-server")
	if err != nil {
		t.Fatalf("issue with root CA: %v", err)
	}
	if len(chain) < 2 {
		t.Fatalf("expected chain of 2+, got %d", len(chain))
	}
}

func TestIssueSignerDefaultProfileByName(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		caName  string
		wantPfx string
	}{
		{"code-signing", "codesigning"},
		{"tsa-server", "timestamp"},
		{"ocsp-responder", "ocsp-signer"},
		{"generic-ca", "tls-server"},
	} {
		caCertPath, caKeyPath := writeCACertKey(t, dir, tc.caName)
		dbPath := newTestDBPath(t)
		d, _ := db.Open(dbPath)
		d.Close()
		cfg := &internal.Config{
			DB: dbPath,
			Defaults: internal.DefaultsConfig{
				CA:      tc.caName,
				KeyType: "ecdsa-p256",
				Profile: "",
			},
			CAs: map[string]internal.CAConfig{
				tc.caName: {Cert: caCertPath, Key: caKeyPath},
			},
		}
		cert, _, _, err := issueSigner(cfg, tc.caName, "", "test-"+tc.caName, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.caName, err)
		}
		if cert == nil {
			t.Fatalf("%s: expected non-nil cert", tc.caName)
		}
	}
}

// ---------- loadTSAConfig extra branches ----------

func TestLoadTSAConfigWithChain(t *testing.T) {
	dir := t.TempDir()
	signerCert, signerKey := writeSignerKey(t, dir, "tsa")
	chainCert, _ := writeCACertKey(t, dir, "tsachain")
	cfg := &internal.Config{
		TSA: internal.TSAConfig{
			SignerCert: signerCert,
			SignerKey:  signerKey,
			Chain:      chainCert,
		},
	}
	h, _, err := loadTSAConfig(cfg)
	if err != nil {
		t.Fatalf("load TSA with chain: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestLoadTSAConfigWithPolicy(t *testing.T) {
	dir := t.TempDir()
	signerCert, signerKey := writeSignerKey(t, dir, "tsapolicy")
	cfg := &internal.Config{
		TSA: internal.TSAConfig{
			SignerCert:      signerCert,
			SignerKey:       signerKey,
			TSAPolicy:       "1.2.3.4.5",
			Ordering:        internal.BoolPtr(true),
			AccuracySeconds: 1,
			AccuracyMillis:  2,
			AccuracyMicros:  3,
		},
	}
	h, _, err := loadTSAConfig(cfg)
	if err != nil {
		t.Fatalf("load TSA with policy: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestLoadTSAConfigBadPolicy(t *testing.T) {
	dir := t.TempDir()
	signerCert, signerKey := writeSignerKey(t, dir, "tsabad")
	cfg := &internal.Config{
		TSA: internal.TSAConfig{
			SignerCert: signerCert,
			SignerKey:  signerKey,
			TSAPolicy:  "bad-oid",
		},
	}
	_, _, err := loadTSAConfig(cfg)
	if err == nil {
		t.Fatal("expected error for bad OID")
	}
}

// ---------- cmdRecover full flow ----------

func TestCLIRecoverFullFlow(t *testing.T) {
	dir := t.TempDir()

	// Generate RSA admin key
	adminKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	adminKeyDER, err := x509.MarshalPKCS8PrivateKey(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	adminKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: adminKeyDER})
	adminKeyPath := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(adminKeyPath, adminKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// Generate ECDSA key to be escrowed/recovered
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerDER, err := x509.MarshalPKCS8PrivateKey(signerKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt signer key with admin RSA public key
	encBlob, err := ca.EncryptPrivateKey(signerDER, &adminKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Store in DB
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreEscrowedKey("testca", "ABCD1234", encBlob); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()

	// Call cmdRecover
	outPath := filepath.Join(dir, "recovered.key")
	cfg := &internal.Config{DB: dbPath}
	if err := cmdRecover(cfg, []string{
		"--serial", "ABCD1234",
		"--ca", "testca",
		"--admin-key", adminKeyPath,
		"--out", outPath,
	}); err != nil {
		t.Fatalf("recover: %v", err)
	}

	// Verify recovered key
	recoveredPEM, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(recoveredPEM)
	if block == nil {
		t.Fatal("expected PEM block")
	}
	recoveredKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse recovered key: %v", err)
	}
	if _, ok := recoveredKey.(*ecdsa.PrivateKey); !ok {
		t.Fatal("expected ECDSA private key")
	}
}

func TestCLIRecoverBadAdminKey(t *testing.T) {
	dir := t.TempDir()
	badKeyPath := filepath.Join(dir, "bad.key")
	os.WriteFile(badKeyPath, []byte("not a pem"), 0600)

	cfg := &internal.Config{DB: newTestDBPath(t), KeyEscrow: internal.KeyEscrowConfig{AdminPublicKey: badKeyPath}}
	err := cmdRecover(cfg, []string{"--serial", "x", "--ca", "test"})
	if err == nil {
		t.Fatal("expected error for bad admin key")
	}
}

func TestCLIRecoverECDSAAdminKey(t *testing.T) {
	dir := t.TempDir()
	adminKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adminDER, _ := x509.MarshalPKCS8PrivateKey(adminKey)
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: adminDER})
	adminKeyPath := filepath.Join(dir, "admin-ecdsa.key")
	os.WriteFile(adminKeyPath, adminPEM, 0600)

	cfg := &internal.Config{DB: newTestDBPath(t), KeyEscrow: internal.KeyEscrowConfig{AdminPublicKey: adminKeyPath}}
	err := cmdRecover(cfg, []string{"--serial", "x", "--ca", "test"})
	if err == nil {
		t.Fatal("expected error for ECDSA admin key (must be RSA)")
	}
}

func TestCLIRecoverPKCS1AdminKey(t *testing.T) {
	dir := t.TempDir()
	adminKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	adminDER := x509.MarshalPKCS1PrivateKey(adminKey)
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: adminDER})
	adminKeyPath := filepath.Join(dir, "admin-pkcs1.key")
	os.WriteFile(adminKeyPath, adminPEM, 0600)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerDER, _ := x509.MarshalPKCS8PrivateKey(signerKey)
	encBlob, _ := ca.EncryptPrivateKey(signerDER, &adminKey.PublicKey)

	dbPath := newTestDBPath(t)
	d, _ := db.Open(dbPath)
	d.StoreEscrowedKey("testca", "PKCS10001", encBlob)
	d.Close()

	outPath := filepath.Join(dir, "rec-pkcs1.key")
	cfg := &internal.Config{DB: dbPath, KeyEscrow: internal.KeyEscrowConfig{AdminPublicKey: adminKeyPath}}
	if err := cmdRecover(cfg, []string{
		"--serial", "PKCS10001",
		"--ca", "testca",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("recover with PKCS#1 key: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("recovered key not created")
	}
}

func TestCLIRecoverWithConfigPath(t *testing.T) {
	dir := t.TempDir()
	adminKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	adminDER, _ := x509.MarshalPKCS8PrivateKey(adminKey)
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: adminDER})
	adminKeyPath := filepath.Join(dir, "admin.key")
	os.WriteFile(adminKeyPath, adminPEM, 0600)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerDER, _ := x509.MarshalPKCS8PrivateKey(signerKey)
	encBlob, _ := ca.EncryptPrivateKey(signerDER, &adminKey.PublicKey)

	dbPath := newTestDBPath(t)
	d, _ := db.Open(dbPath)
	d.StoreEscrowedKey("testca", "EEFF0011", encBlob)
	d.Close()

	// Write a config file with admin key path (use forward slashes for valid JSON on Windows)
	cfgMap := map[string]any{
		"db": filepath.ToSlash(dbPath),
		"key_escrow": map[string]any{
			"admin_public_key": filepath.ToSlash(adminKeyPath),
		},
	}
	cfgJSON, _ := json.Marshal(cfgMap)
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, cfgJSON, 0644)

	outPath := filepath.Join(dir, "rec.key")
	loaded, _ := internal.LoadConfig(cfgPath)
	merged := internal.MergeConfig(&internal.Config{}, loaded)
	if err := cmdRecover(merged, []string{
		"--serial", "EEFF0011",
		"--ca", "testca",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("recover with config: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("recovered key not created")
	}
}

// ---------- Audit verify with entries ----------

func TestCLIAuditVerifyWithEntries(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 3; i++ {
		if err := d.LogAudit("admin", "127.0.0.1", "POST", "/api/certs", "issue", fmt.Sprintf("entry %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdAuditVerify(d); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
}

func TestCLIAuditWithLimit(t *testing.T) {
	dbPath := newTestDBPath(t)
	d, _ := db.Open(dbPath)
	for i := 0; i < 3; i++ {
		d.LogAudit("tester", "::1", "GET", "/test", "read", fmt.Sprintf("entry %d", i))
	}
	d.Close()

	if err := cmdAudit(&internal.Config{DB: dbPath}, []string{"--limit", "2"}); err != nil {
		t.Fatalf("audit with limit: %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }

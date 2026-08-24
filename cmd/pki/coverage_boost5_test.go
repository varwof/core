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
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func writeSubCAResource(t *testing.T, dir string) (certPath, keyPath, csrPath string) {
	t.Helper()
	certPath, keyPath = writeCACertKey(t, dir, "root")

	// generate a CSR for a sub-CA
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Sub CA", Organization: []string{"acme"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath = filepath.Join(dir, "sub-ca.csr")
	if err := os.WriteFile(csrPath, csrPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, csrPath
}

func TestCmdCAOfflineSign(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, csrPath := writeSubCAResource(t, dir)
	outPath := filepath.Join(dir, "signed.pem")

	// missing flags
	if err := cmdCAOfflineSign(&internal.Config{}, nil); err == nil {
		t.Fatal("expected missing flag error")
	}
	// missing files
	if err := cmdCAOfflineSign(&internal.Config{}, []string{"--ca-cert", filepath.Join(dir, "nope.pem"), "--ca-key", keyPath, "--csr", csrPath, "--out", outPath}); err == nil {
		t.Fatal("expected read error")
	}
	// happy path with sha384
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", certPath, "--ca-key", keyPath, "--csr", csrPath,
		"--out", outPath, "--validity", "365", "--pathlen", "1", "--hash", "sha384",
	}); err != nil {
		t.Fatalf("offline sign: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("expected output cert")
	}
	// invalid hash falls back to sha256
	out2 := filepath.Join(dir, "signed2.pem")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", certPath, "--ca-key", keyPath, "--csr", csrPath,
		"--out", out2, "--hash", "md5",
	}); err != nil {
		t.Fatalf("offline sign fallback: %v", err)
	}
}

func TestCmdCAEncryptKey(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "enc")
	outPath := filepath.Join(dir, "enc.key")

	// missing --key
	if err := cmdCAEncryptKey(&internal.Config{}, nil); err == nil {
		t.Fatal("expected --key required error")
	}
	// missing file
	if err := cmdCAEncryptKey(&internal.Config{}, []string{"--key", filepath.Join(dir, "nope.key")}); err == nil {
		t.Fatal("expected read error")
	}
	// happy path with --out and --verify
	if err := cmdCAEncryptKey(&internal.Config{}, []string{"--key", keyPath, "--out", outPath, "--password", "pwd", "--verify"}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("expected encrypted PEM, got %v", block)
	}
	// overwrite in place (backup created) using a fresh plain key
	_, keyPath2 := writeCACertKey(t, dir, "enc2")
	if err := cmdCAEncryptKey(&internal.Config{}, []string{"--key", keyPath2, "--password", "pwd2"}); err != nil {
		t.Fatalf("encrypt in place: %v", err)
	}
	if _, err := os.Stat(keyPath2 + ".bak"); err != nil {
		t.Fatal("expected .bak backup")
	}
}

func TestCmdReport(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{DB: dbPath}

	for _, tmpl := range []string{"soc2", "pci", "nist", "iso"} {
		out := filepath.Join(dir, tmpl+".pdf")
		if err := cmdReport(cfg, []string{"--template", tmpl, "--out", out}); err != nil {
			t.Fatalf("report %s: %v", tmpl, err)
		}
		if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
			t.Fatalf("expected non-empty pdf for %s", tmpl)
		}
	}
	// with CA filter
	if err := cmdReport(cfg, []string{"--template", "soc2", "--ca", "some-ca", "--out", filepath.Join(dir, "filtered.pdf")}); err != nil {
		t.Fatalf("report filtered: %v", err)
	}
	// default out path
	if err := cmdReport(cfg, []string{"--template", "soc2"}); err != nil {
		t.Fatalf("report default out: %v", err)
	}
	// getControlChecks via unknown standard → soc2 fallback
	_ = getControlChecks("bogus")
	// truncStr
	if truncStr("hello", 2) != "he" {
		t.Fatal("truncStr")
	}
	if truncStr("hi", 10) != "hi" {
		t.Fatal("truncStr short")
	}
}

func TestCmdAutoRenewDispatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}
	if err := cmdAutoRenew(cfg, nil); err != nil {
		t.Fatalf("cmdAutoRenew once: %v", err)
	}
}

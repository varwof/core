package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/pkcs7"
)

// writeSignedBinary writes a fake binary and its detached signature.
func writeSignedBinary(t *testing.T, content []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "tool.bin")
	if err := os.WriteFile(binPath, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, content, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	return binPath
}

func TestCmdRunVerifiedExec(t *testing.T) {
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	dir := t.TempDir()
	caPEM := pemEncodeCert(caCert)
	caPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	binPath := writeSignedBinary(t, []byte("#!/bin/sh\necho hello\n"), signerCert, signerKey)

	called := false
	var gotBinary string
	var gotArgs []string
	origExecFn := execFn
	execFn = func(binary string, args []string) error {
		called = true
		gotBinary = binary
		gotArgs = args
		return nil
	}
	defer func() { execFn = origExecFn }()

	if err := cmdRun(cfg, []string{"--ca", caPath, binPath, "--flag", "value"}); err != nil {
		t.Fatalf("cmdRun should succeed: %v", err)
	}
	if !called {
		t.Fatal("execFn was not invoked")
	}
	if gotBinary != binPath {
		t.Errorf("exec binary = %q, want %q", gotBinary, binPath)
	}
	if len(gotArgs) != 2 || gotArgs[0] != "--flag" || gotArgs[1] != "value" {
		t.Errorf("exec args = %v, want [--flag value]", gotArgs)
	}
}

func TestCmdRunDefaultSigPath(t *testing.T) {
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(caPath, pemEncodeCert(caCert), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := writeSignedBinary(t, []byte("data"), signerCert, signerKey)

	origExecFn := execFn
	execFn = func(string, []string) error { return nil }
	defer func() { execFn = origExecFn }()

	if err := cmdRun(cfg, []string{"--ca", caPath, binPath}); err != nil {
		t.Fatalf("default .p7s path should be used: %v", err)
	}
}

func TestCmdRunRejectsTamperedBinary(t *testing.T) {
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(caPath, pemEncodeCert(caCert), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := writeSignedBinary(t, []byte("original\n"), signerCert, signerKey)
	// Tamper with the binary.
	if err := os.WriteFile(binPath, []byte("malicious\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	called := false
	origExecFn := execFn
	execFn = func(string, []string) error { called = true; return nil }
	defer func() { execFn = origExecFn }()

	if err := cmdRun(cfg, []string{"--ca", caPath, binPath}); err == nil {
		t.Fatal("tampered binary should be refused")
	}
	if called {
		t.Fatal("execFn must not run when verification fails")
	}
}

func TestCmdRunMissingSignature(t *testing.T) {
	_, _, caCert := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(caPath, pemEncodeCert(caCert), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "nosig.bin")
	if err := os.WriteFile(binPath, []byte("data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := cmdRun(cfg, []string{"--ca", caPath, binPath}); err == nil {
		t.Fatal("missing .p7s should be refused")
	}
}

func TestCmdRunUntrustedCA(t *testing.T) {
	signerCert, signerKey, _ := makePolicySigningCert(t, "admin")
	// Use a different CA as the trust anchor; the chain is untrusted.
	_, _, otherCA := makePolicySigningCert(t, "admin")
	cfg := &internal.Config{}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "other-root.pem")
	if err := os.WriteFile(caPath, pemEncodeCert(otherCA), 0600); err != nil {
		t.Fatal(err)
	}
	binPath := writeSignedBinary(t, []byte("data"), signerCert, signerKey)
	if err := cmdRun(cfg, []string{"--ca", caPath, binPath}); err == nil {
		t.Fatal("signer from untrusted CA should be refused")
	}
}

func TestCmdRunNoTrustAnchor(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRun(cfg, []string{"missing.bin"}); err == nil {
		t.Fatal("no trust anchor should error")
	}
}

func TestCmdRunMissingBinaryArg(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdRun(cfg, []string{"--ca", "root.pem"}); err == nil {
		t.Fatal("missing binary argument should error")
	}
}

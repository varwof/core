package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pem")
	der := []byte("test-der-data")
	writePEM(path, "CERTIFICATE", der)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE, got %s", block.Type)
	}
	if string(block.Bytes) != "test-der-data" {
		t.Fatalf("expected test-der-data, got %s", block.Bytes)
	}
	if len(rest) != 0 {
		t.Fatal("unexpected trailing data")
	}
}

func TestWriteKey(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "test.key")
	writeKey(path, key)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY, got %s", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatal("expected ECDSA key")
	}
}

func TestMainGeneratesFiles(t *testing.T) {
	origWd, _ := os.Getwd()
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	// Run main — will generate files in testdata/ subdir
	main()

	expected := []string{
		"test-root-ca.pem", "test-root-ca.key",
		"test-ca.pem", "test-ca.key",
		"test-ocsp.pem", "test-ocsp.key",
		"test-tsa.pem", "test-tsa.key",
		"sample-csr.pem",
	}
	for _, name := range expected {
		path := filepath.Join(dir, "testdata", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing generated file %s: %v", name, err)
		}
	}
}

func TestWritePEMErrorIgnored(t *testing.T) {
	// Path with nonexistent parent dir — os.Create will fail silently
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "cert.pem")
	writePEM(path, "CERTIFICATE", []byte("data"))
	// Function ignores the error, so file won't exist — just check no panic
}

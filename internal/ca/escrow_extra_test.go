// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeAdminPub(t *testing.T, dir, name string, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEscrowRSARoundtrip(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := writeAdminPub(t, dir, "admin-rsa.pub", &key.PublicKey)

	pub, err := LoadAdminPublicKey(path)
	if err != nil {
		t.Fatalf("load admin public key: %v", err)
	}
	blob, err := EncryptPrivateKey([]byte("top-secret-rsa"), pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := DecryptPrivateKey(blob, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != "top-secret-rsa" {
		t.Fatalf("roundtrip mismatch: %q", plain)
	}

	if _, err := DecryptPrivateKey([]byte("short"), key); err == nil {
		t.Fatal("short blob must error")
	}
}

func TestEscrowECDSARoundtrip(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeAdminPub(t, dir, "admin-ecdsa.pub", &key.PublicKey)

	pub, err := LoadAdminPublicKey(path)
	if err != nil {
		t.Fatalf("load admin public key: %v", err)
	}
	blob, err := EncryptPrivateKey([]byte("top-secret-ecdsa"), pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := DecryptPrivateKey(blob, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != "top-secret-ecdsa" {
		t.Fatalf("roundtrip mismatch: %q", plain)
	}

	native, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecryptPrivateKey([]byte("ab"), native); err == nil {
		t.Fatal("short ECDH blob must error")
	}
}

func TestEscrowErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadAdminPublicKey(filepath.Join(dir, "missing.pub")); err == nil {
		t.Fatal("missing admin key must error")
	}
	badPath := filepath.Join(dir, "garbage.pub")
	os.WriteFile(badPath, []byte("junk"), 0o600)
	if _, err := LoadAdminPublicKey(badPath); err == nil {
		t.Fatal("non-PEM admin key must error")
	}
	notPKIX := filepath.Join(dir, "notpkix.pub")
	os.WriteFile(notPKIX, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("abc")}), 0o600)
	if _, err := LoadAdminPublicKey(notPKIX); err == nil {
		t.Fatal("non-PKIX admin key must error")
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPath := writeAdminPub(t, dir, "admin-ed.pub", edPub)
	if _, err := LoadAdminPublicKey(edPath); err == nil {
		t.Fatal("Ed25519 admin key must error")
	}

	if _, err := EncryptPrivateKey([]byte("x"), edPub); err == nil {
		t.Fatal("Ed25519 encrypt must error")
	}

	edPrivPath, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := DecryptPrivateKey([]byte("blob"), ed25519.PrivateKey(edPrivPath)); err == nil {
		t.Fatal("Ed25519 decrypt must error")
	}

	if _, err := ecdhPrivateKey(ed25519.PrivateKey(make([]byte, 64))); err == nil {
		t.Fatal("unsupported ECDH private key must error")
	}
	if _, err := ecdhPublicKey(ed25519.PrivateKey(make([]byte, 64))); err == nil {
		t.Fatal("unsupported ECDH public key must error")
	}
}

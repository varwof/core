// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/pkcs7"
)

func newTestSigner(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TestSigner"},
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
	return cert, key
}

func tempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignDetached(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "test.bin", "hello world")

	cfg := &Config{
		Cert:  cert,
		Key:   key,
		Chain: nil,
		Hash:  crypto.SHA256,
	}

	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sigPath != filePath+".p7s" {
		t.Fatalf("expected %s, got %s", filePath+".p7s", sigPath)
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigData) == 0 {
		t.Fatal("empty signature")
	}
}

func TestSignEmbedded(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "embed.bin", "data to embed sign")

	cfg := &Config{
		Cert:  cert,
		Key:   key,
		Chain: nil,
		Hash:  crypto.SHA256,
	}

	if err := SignEmbedded(filePath, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= len("data to embed sign") {
		t.Fatal("embedded data should be larger than original")
	}
}

func TestSignDetachedWithChain(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestRoot"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestSigner"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTmpl, rootCert, &signerKey.PublicKey, rootKey)
	signerCert, _ := x509.ParseCertificate(signerDER)

	filePath := tempFile(t, "chain-test.bin", "signed with chain")
	cfg := &Config{
		Cert:  signerCert,
		Key:   signerKey,
		Chain: []*x509.Certificate{rootCert},
		Hash:  crypto.SHA256,
	}

	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigData) == 0 {
		t.Fatal("empty signature")
	}
}

func TestVerifyDetached(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "verify-detached.bin", "hello world")

	cfg := &Config{Cert: cert, Key: key, Chain: nil, Hash: crypto.SHA256}
	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyDetached(filePath, sigPath, nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyDetachedTampered(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "verify-tamper.bin", "original content")

	cfg := &Config{Cert: cert, Key: key, Chain: nil, Hash: crypto.SHA256}
	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filePath, []byte("tampered content"), 0644); err != nil {
		t.Fatal(err)
	}

	err = VerifyDetached(filePath, sigPath, nil)
	if err == nil {
		t.Fatal("expected error for tampered content")
	}
}

func TestVerifyDetachedMissingFile(t *testing.T) {
	err := VerifyDetached("/nonexistent/file.bin", "/nonexistent/file.bin.p7s", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestVerifyDetachedWithChain(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestRoot"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestSigner"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTmpl, rootCert, &signerKey.PublicKey, rootKey)
	signerCert, _ := x509.ParseCertificate(signerDER)

	filePath := tempFile(t, "verify-chain.bin", "content with chain")
	cfg := &Config{Cert: signerCert, Key: signerKey, Chain: []*x509.Certificate{rootCert}, Hash: crypto.SHA256}
	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	err = VerifyDetached(filePath, sigPath, rootPool)
	if err != nil {
		t.Fatalf("verify with chain failed: %v", err)
	}
}

func TestVerifyEmbedded(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "verify-embed.bin", "data to embed sign")

	cfg := &Config{Cert: cert, Key: key, Chain: nil, Hash: crypto.SHA256}
	if err := SignEmbedded(filePath, cfg); err != nil {
		t.Fatal(err)
	}

	err := VerifyEmbedded(filePath, nil)
	if err != nil {
		t.Fatalf("verify embedded failed: %v", err)
	}
}

func TestVerifyEmbeddedTampered(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "verify-embed-tamper.bin", "original data")

	cfg := &Config{Cert: cert, Key: key, Chain: nil, Hash: crypto.SHA256}
	if err := SignEmbedded(filePath, cfg); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatal(err)
	}

	err = VerifyEmbedded(filePath, nil)
	if err == nil {
		t.Fatal("expected error for tampered embedded content")
	}
}

func TestVerifyEmbeddedNoSig(t *testing.T) {
	filePath := tempFile(t, "no-sig.bin", "no signature here")
	err := VerifyEmbedded(filePath, nil)
	if err == nil {
		t.Fatal("expected error for file without embedded signature")
	}
}

func TestVerifySignatureECDSA(t *testing.T) {
	_, key := newTestSigner(t)
	pub := key.Public()
	hash := crypto.SHA256
	data := []byte("hello world")
	h := hash.New()
	h.Write(data)
	sigHash := h.Sum(nil)
	sig, err := key.Sign(rand.Reader, sigHash, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(pub, hash, sigHash, sig); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(pub, hash, []byte("badhash"), sig); err == nil {
		t.Fatal("expected error for bad hash")
	}
}

func TestVerifySignatureRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.SHA256
	data := []byte("hello rsa")
	h := hash.New()
	h.Write(data)
	sigHash := h.Sum(nil)
	sig, err := key.Sign(rand.Reader, sigHash, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&key.PublicKey, hash, sigHash, sig); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&key.PublicKey, hash, []byte("badhash"), sig); err == nil {
		t.Fatal("expected error for bad hash")
	}
}

func TestVerifySignatureEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello ed25519")
	sig, err := priv.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(pub, crypto.Hash(0), data, sig); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(pub, crypto.Hash(0), []byte("badhash"), sig); err == nil {
		t.Fatal("expected error for bad data")
	}
}

func TestVerifySignatureUnsupported(t *testing.T) {
	err := verifySignature(struct{}{}, crypto.SHA256, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestHashFromOID(t *testing.T) {
	cases := []struct {
		name string
		oid  []int
		want crypto.Hash
	}{
		{"sha256", []int{2, 16, 840, 1, 101, 3, 4, 2, 1}, crypto.SHA256},
		{"sha384", []int{2, 16, 840, 1, 101, 3, 4, 2, 2}, crypto.SHA384},
		{"sha512", []int{2, 16, 840, 1, 101, 3, 4, 2, 3}, crypto.SHA512},
		{"unknown-defaults-to-sha256", []int{1, 2, 3, 4}, crypto.SHA256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, newHash := hashFromOID(asn1.ObjectIdentifier(tc.oid))
			if h != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, h)
			}
			dig := newHash()
			dig.Write([]byte("hello"))
			if tc.want == crypto.SHA384 && len(dig.Sum(nil)) != 48 {
				t.Fatalf("expected 48-byte digest, got %d", len(dig.Sum(nil)))
			}
			if tc.want == crypto.SHA512 && len(dig.Sum(nil)) != 64 {
				t.Fatalf("expected 64-byte digest, got %d", len(dig.Sum(nil)))
			}
		})
	}
}

func TestNewSM3Stub(t *testing.T) {
	if sm3Available {
		t.Skip("SM3 available in gmsm build")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from NewSM3 stub")
		}
	}()
	NewSM3()
}

func TestSignDetachedMissingFile(t *testing.T) {
	_, err := SignDetached("/nonexistent/file.bin", &Config{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSignEmbeddedUnwritablePath(t *testing.T) {
	cert, key := newTestSigner(t)
	err := SignEmbedded("/nonexistent-dir/out.bin", &Config{Cert: cert, Key: key, Hash: crypto.SHA256})
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestVerifyDetachedSHA512(t *testing.T) {
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "verify-sha512.bin", "sha512 signed content")

	cfg := &Config{Cert: cert, Key: key, Chain: nil, Hash: crypto.SHA512}
	sigPath, err := SignDetached(filePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetached(filePath, sigPath, nil); err != nil {
		t.Fatalf("verify sha512 failed: %v", err)
	}
}

func TestSignEmbeddedBackwardCompat(t *testing.T) {
	// Verify that the old magic-based format is still readable
	cert, key := newTestSigner(t)
	filePath := tempFile(t, "legacy-embed.bin", "legacy content")

	// Write old-format signature manually
	magic := []byte("PKISIG\x00")
	sdDER, err := pkcs7.BuildSignedDataWithHash(
		pkcs7.OIDData, []byte("legacy content"),
		cert, key, nil, crypto.SHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf("%s%08x", magic, len(sdDER))
	embedded := append([]byte("legacy content"), []byte(header)...)
	embedded = append(embedded, sdDER...)
	if err := os.WriteFile(filePath, embedded, 0644); err != nil {
		t.Fatal(err)
	}

	// ASN.1 format should still verify
	err = VerifyEmbedded(filePath, nil)
	if err != nil {
		t.Fatalf("legacy format verify failed: %v", err)
	}
}

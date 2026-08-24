// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"testing"
)

func TestEncryptDecryptKeyP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := "test-password-123"

	encrypted, err := EncryptKeyPKCS8(key, password)
	if err != nil {
		t.Fatalf("EncryptKeyPKCS8: %v", err)
	}

	decrypted, err := DecryptKeyPKCS8(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptKeyPKCS8: %v", err)
	}

	original, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("original key is not *ecdsa.PublicKey")
	}
	recovered, ok := decrypted.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("decrypted key is not *ecdsa.PublicKey")
	}

	if original.X.Cmp(recovered.X) != 0 || original.Y.Cmp(recovered.Y) != 0 || original.Params().Name != recovered.Params().Name {
		t.Fatal("public key mismatch after encrypt/decrypt round-trip")
	}
}

func TestEncryptDecryptKeyRSA2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	password := "rsa-test-pass"

	encrypted, err := EncryptKeyPKCS8(key, password)
	if err != nil {
		t.Fatalf("EncryptKeyPKCS8: %v", err)
	}

	decrypted, err := DecryptKeyPKCS8(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptKeyPKCS8: %v", err)
	}

	original := key.Public().(*rsa.PublicKey)
	recovered := decrypted.Public().(*rsa.PublicKey)

	if original.N.Cmp(recovered.N) != 0 || original.E != recovered.E {
		t.Fatal("public key mismatch after RSA encrypt/decrypt round-trip")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptKeyPKCS8(key, "correct-password")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptKeyPKCS8(encrypted, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestDecryptInvalidDER(t *testing.T) {
	_, err := DecryptKeyPKCS8([]byte("not-valid-der"), "password")
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestEncryptDecryptDERPKCS8(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptKeyDERPKCS8(der, "p384-test")
	if err != nil {
		t.Fatalf("EncryptKeyDERPKCS8: %v", err)
	}

	decrypted, err := DecryptKeyPKCS8(encrypted, "p384-test")
	if err != nil {
		t.Fatalf("DecryptKeyPKCS8: %v", err)
	}

	recovered, ok := decrypted.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("decrypted key is not *ecdsa.PrivateKey")
	}
	if recovered.Params().Name != "P-384" {
		t.Fatalf("expected P-384, got %s", recovered.Params().Name)
	}
}

func TestEncryptDecryptEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptKeyPKCS8(priv, "ed25519-pass")
	if err != nil {
		t.Fatalf("EncryptKeyPKCS8 ed25519: %v", err)
	}

	decrypted, err := DecryptKeyPKCS8(encrypted, "ed25519-pass")
	if err != nil {
		t.Fatalf("DecryptKeyPKCS8 ed25519: %v", err)
	}

	_, ok := decrypted.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("decrypted key is not ed25519.PrivateKey")
	}
}

func TestEncryptKeyMarshalError(t *testing.T) {
	// Create a signer that will fail to marshal
	badSigner := &badSigner{}
	_, err := EncryptKeyPKCS8(badSigner, "pass")
	if err == nil {
		t.Fatal("expected error for unmarshalable key")
	}
}

type badSigner struct{}

func (b *badSigner) Public() crypto.PublicKey { return nil }
func (b *badSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

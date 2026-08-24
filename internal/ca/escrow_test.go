package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func newTestRSAPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

func newTestRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptEscrow(t *testing.T) {
	// Use one key pair for both encrypt and decrypt
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := EncryptPrivateKey(privDER, pub)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	decrypted, err := DecryptPrivateKey(blob, key)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if len(decrypted) != len(privDER) {
		t.Fatalf("decrypted length %d != original %d", len(decrypted), len(privDER))
	}
	for i := range privDER {
		if decrypted[i] != privDER[i] {
			t.Fatal("decrypted data mismatch at byte", i)
		}
	}
}

func TestEncryptDecryptEscrowECKey(t *testing.T) {
	pub := newTestRSAPublicKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := EncryptPrivateKey(privDER, pub)
	if err != nil {
		t.Fatalf("EncryptPrivateKey EC: %v", err)
	}

	wrongKey := newTestRSAPrivateKey(t)
	_, err = DecryptPrivateKey(blob, wrongKey)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}

	correctKey := newTestRSAPrivateKey(t)
	// Re-encrypt with correct key's public part for a valid test
	pub2 := &correctKey.PublicKey
	blob2, _ := EncryptPrivateKey(privDER, pub2)
	decrypted, err := DecryptPrivateKey(blob2, correctKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey with correct key: %v", err)
	}
	if string(decrypted) != string(privDER) {
		t.Fatal("decrypted data mismatch")
	}
}

func TestEscrowBlobTooShort(t *testing.T) {
	priv := newTestRSAPrivateKey(t)
	_, err := DecryptPrivateKey([]byte("too-short"), priv)
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestLoadAdminPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir := t.TempDir()
	path := dir + "/admin.pub"
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadAdminPublicKey(path)
	if err != nil {
		t.Fatalf("LoadAdminPublicKey: %v", err)
	}
	loadedRSA, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if loadedRSA.N.Cmp(key.PublicKey.N) != 0 || loadedRSA.E != key.PublicKey.E {
		t.Fatal("loaded key mismatch")
	}
}

func TestLoadAdminPublicKeyInvalid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/invalid.pub"
	if err := os.WriteFile(path, []byte("not-pem"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadAdminPublicKey(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	path2 := dir + "/nonexistent.pub"
	_, err = LoadAdminPublicKey(path2)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadAdminPublicKeyECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir := t.TempDir()
	path := dir + "/ec.pub"
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadAdminPublicKey(path)
	if err != nil {
		t.Fatalf("LoadAdminPublicKey(ECDSA): %v", err)
	}
	if _, ok := loaded.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", loaded)
	}
}

func TestEncryptDecryptEscrowECDSAP256(t *testing.T) {
	// Generate ECDSA key pair for admin
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPub := &adminKey.PublicKey

	// Export a "private key to escrow" (any DER blob)
	targetKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(targetKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with ECDSA public key (ECDH path)
	blob, err := EncryptPrivateKey(privDER, adminPub)
	if err != nil {
		t.Fatalf("EncryptPrivateKey with ECDSA pub: %v", err)
	}

	// Decrypt with the matching ECDSA private key
	decrypted, err := DecryptPrivateKey(blob, adminKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey with ECDSA priv: %v", err)
	}

	if string(decrypted) != string(privDER) {
		t.Fatal("decrypted data mismatch")
	}
}

func TestDecryptWithECDHInvalidBlob(t *testing.T) {
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Blob too short (< 2 bytes) → should error via DecryptPrivateKey
	_, err = DecryptPrivateKey([]byte{0}, adminKey)
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestDecryptWithECDHEphemeralLenMismatch(t *testing.T) {
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Ephemeral key length byte says 100 but only 5 bytes follow
	blob := []byte{100, 1, 2, 3, 4, 5}
	blob = append(blob, make([]byte, 12)...) // nonce
	blob = append(blob, []byte("cipher")...)
	_, err = DecryptPrivateKey(blob, adminKey)
	if err == nil {
		t.Fatal("expected error for mismatched ephemeral key length")
	}
}

func TestECDHHelpers(t *testing.T) {
	t.Run("ecdhPublicKey ECDSA P-256", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ecdhPublicKey(ecKey)
		if err != nil {
			t.Fatalf("ecdhPublicKey: %v", err)
		}
		if pub == nil {
			t.Fatal("expected non-nil public key")
		}
	})

	t.Run("ecdhPublicKey RSA error", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ecdhPublicKey(rsaKey)
		if err == nil {
			t.Fatal("expected error for RSA key")
		}
	})

	t.Run("ecdhPrivateKey ECDSA P-256", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdhPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("ecdhPrivateKey: %v", err)
		}
		if priv == nil {
			t.Fatal("expected non-nil private key")
		}
	})

	t.Run("ecdhPrivateKey RSA error", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ecdhPrivateKey(rsaKey)
		if err == nil {
			t.Fatal("expected error for RSA key")
		}
	})
}

package ca

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var errUnsupportedKey = errors.New("admin key must be RSA or ECDSA (Ed25519 unsupported)")

// escrowECDHVersion marks the ECDH KDF blob format. v1 uses HKDF-SHA256 with
// domain separation and context binding instead of the legacy bare SHA-256.
const escrowECDHVersion byte = 0x01

// escrowECDHInfo is the domain-separation context string bound into the
// HKDF-SHA256 key derivation (M10 fix).
const escrowECDHInfo = "varwof escrow ecdh hkdf-sha256 v1"

func LoadAdminPublicKey(path string) (crypto.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read admin key: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in admin key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse admin public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	case ed25519.PublicKey:
		return nil, errors.New("admin key Ed25519 unsupported for escrow encryption (use RSA or ECDSA)")
	default:
		return nil, fmt.Errorf("admin key must be RSA or ECDSA (got %T)", pub)
	}
}

func ecdhPublicKey(priv crypto.PrivateKey) (*ecdh.PublicKey, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		pk, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		return pk.PublicKey(), nil
	case *ecdh.PrivateKey:
		return k.PublicKey(), nil
	}
	return nil, fmt.Errorf("unsupported key type for ECDH: %T", priv)
}

func ecdhPrivateKey(priv crypto.PrivateKey) (*ecdh.PrivateKey, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return k.ECDH()
	case *ecdh.PrivateKey:
		return k, nil
	}
	return nil, fmt.Errorf("unsupported key type for ECDH: %T", priv)
}

func EncryptPrivateKey(privDER []byte, pub crypto.PublicKey) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, privDER, nil)

	var wrappedKey []byte
	switch p := pub.(type) {
	case *rsa.PublicKey:
		wrappedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, p, aesKey, nil)
		if err != nil {
			return nil, fmt.Errorf("wrap AES key: %w", err)
		}
	case *ecdsa.PublicKey:
		ecdhPub, eerr := p.ECDH()
		if eerr != nil {
			return nil, fmt.Errorf("ecdh public key: %w", eerr)
		}
		// Generate ephemeral ECDH key for this encryption
		ephKey, eerr := ecdhPub.Curve().GenerateKey(rand.Reader)
		if eerr != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", eerr)
		}
		shared, eerr := ephKey.ECDH(ecdhPub)
		if eerr != nil {
			return nil, fmt.Errorf("ecdh: %w", eerr)
		}
		// M10 fix: derive AES key with HKDF-SHA256 + context binding instead of
		// a bare SHA256(shared). The info string binds the ephemeral public key
		// bytes so the KDF is domain-separated per session.
		aesKey, eerr = deriveEscrowECDHKey(shared, ephKey.PublicKey().Bytes())
		if eerr != nil {
			return nil, eerr
		}
		// Regenerate cipher with the new key
		newBlock, eerr := aes.NewCipher(aesKey)
		if eerr != nil {
			return nil, fmt.Errorf("new cipher: %w", eerr)
		}
		newGCM, eerr := cipher.NewGCM(newBlock)
		if eerr != nil {
			return nil, fmt.Errorf("new GCM: %w", eerr)
		}
		// Re-encrypt with the ECDH-derived key
		ciphertext = newGCM.Seal(nil, nonce, privDER, nil)
		// Prepend version marker + ephemeral public key bytes
		ephBytes := ephKey.PublicKey().Bytes()
		wrappedKey = make([]byte, 0, len(ephBytes)+2)
		wrappedKey = append(wrappedKey, escrowECDHVersion, byte(len(ephBytes)))
		wrappedKey = append(wrappedKey, ephBytes...)
	default:
		return nil, errUnsupportedKey
	}

	blob := append(wrappedKey, nonce...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

func DecryptPrivateKey(blob []byte, priv crypto.PrivateKey) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return decryptWithRSA(blob, k)
	case *ecdsa.PrivateKey, *ecdh.PrivateKey:
		return decryptWithECDH(blob, priv)
	default:
		return nil, errUnsupportedKey
	}
}

func decryptWithRSA(blob []byte, priv *rsa.PrivateKey) ([]byte, error) {
	keySize := priv.Size()
	if len(blob) < keySize+12+1 {
		return nil, fmt.Errorf("blob too short")
	}
	wrappedKey := blob[:keySize]
	nonce := blob[keySize : keySize+12]
	ciphertext := blob[keySize+12:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decryptWithECDH(blob []byte, priv crypto.PrivateKey) ([]byte, error) {
	if len(blob) < 2 {
		return nil, fmt.Errorf("blob too short")
	}
	// Detect the blob format. New blobs start with a version marker (0x01)
	// followed by the ephemeral public key length; legacy blobs start directly
	// with the ephLen byte (whose value is always > 1, so 0x01 is unambiguous).
	var ephBytes []byte
	var v1 bool
	if blob[0] == escrowECDHVersion && len(blob) > 2 {
		v1 = true
		ephLen := int(blob[1])
		if len(blob) < 2+ephLen+12+1 {
			return nil, fmt.Errorf("blob too short")
		}
		ephBytes = blob[2 : 2+ephLen]
		blob = blob[2:]
	} else {
		ephLen := int(blob[0])
		if len(blob) < 1+ephLen+12+1 {
			return nil, fmt.Errorf("blob too short")
		}
		ephBytes = blob[1 : 1+ephLen]
	}
	nonce := blob[len(ephBytes) : len(ephBytes)+12]
	ciphertext := blob[len(ephBytes)+12:]

	ecdhPriv, err := ecdhPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	curve := ecdhPriv.Curve()
	ephPub, err := curve.NewPublicKey(ephBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	shared, err := ecdhPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	var aesKey []byte
	if v1 {
		aesKey, err = deriveEscrowECDHKey(shared, ephBytes)
		if err != nil {
			return nil, err
		}
	} else {
		// Legacy compatibility: bare SHA-256 KDF (pre-M10 blobs).
		h := sha256.Sum256(shared)
		aesKey = h[:]
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveEscrowECDHKey runs HKDF-SHA256 over the ECDH shared secret, binding the
// domain-separation info string and the ephemeral public key as context so the
// resulting 32-byte AES key is session- and protocol-specific.
func deriveEscrowECDHKey(shared, ephPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(escrowECDHInfo)+1+len(ephPub))
	info = append(info, escrowECDHInfo...)
	info = append(info, 0x00)
	info = append(info, ephPub...)
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf derive escrow key: %w", err)
	}
	return key, nil
}

package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncryptPrivateKeyPEM encrypts a private key with a password using
// PKCS#8 EncryptedPrivateKeyInfo (PBKDF2-SHA256 + AES-256-CBC, RFC 5958).
// Output is PEM-compatible with OpenSSL's "ENCRYPTED PRIVATE KEY" format:
//
//	openssl pkey -aes-256-cbc -pass pass:xxx -in key.pem -out enc-key.pem
func EncryptPrivateKeyPEM(key crypto.Signer, password string) ([]byte, error) {
	der, err := EncryptKeyPKCS8(key, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: der,
	}), nil
}

// DecryptPrivateKeyPEM decrypts a PEM-encoded encrypted private key.
// Also handles unencrypted "PRIVATE KEY" and combined cert+key files.
func DecryptPrivateKeyPEM(pemData []byte, password string) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found")
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			return DecryptKeyPKCS8(block.Bytes, password)
		case "PRIVATE KEY":
			raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
			if s, ok := raw.(crypto.Signer); ok {
				return s, nil
			}
			return nil, fmt.Errorf("key is not a signer")
		}
		pemData = rest
	}
}

// IsEncryptedPEM checks whether a PEM block is an encrypted private key.
func IsEncryptedPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil && block.Type == "ENCRYPTED PRIVATE KEY"
}

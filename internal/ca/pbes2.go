// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	nullRaw       = asn1.RawValue{Class: 0, Tag: 5, Bytes: nil}
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedData       []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int       `asn1:"optional"`
	PRF            pbkdf2PRF `asn1:"optional"`
}

type pbkdf2PRF struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func EncryptKeyPKCS8(priv crypto.Signer, password string) ([]byte, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return EncryptKeyDERPKCS8(privDER, password)
}

func EncryptKeyDERPKCS8(privDER []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	iterations := 600000
	keyLen := 32
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	padLen := aes.BlockSize - len(privDER)%aes.BlockSize
	pad := make([]byte, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	padded := append(privDER, pad...)

	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	pbkdf2ParamsDER, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: iterations,
		KeyLength:      keyLen,
		PRF: pbkdf2PRF{
			Algorithm:  oidHMACSHA256,
			Parameters: nullRaw,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal pbkdf2: %w", err)
	}

	aesIVDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("marshal iv: %w", err)
	}

	p2 := pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: pbkdf2ParamsDER},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: aesIVDER},
		},
	}

	p2DER, err := asn1.Marshal(p2)
	if err != nil {
		return nil, fmt.Errorf("marshal pbes2: %w", err)
	}

	e := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2DER},
		},
		EncryptedData: encrypted,
	}

	return asn1.Marshal(e)
}

func DecryptKeyPKCS8(der []byte, password string) (crypto.Signer, error) {
	var e encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &e); err != nil {
		return nil, fmt.Errorf("parse EncryptedPrivateKeyInfo: %w", err)
	}

	if !e.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported encryption algorithm: %v", e.EncryptionAlgorithm.Algorithm)
	}

	var p2 pbes2Params
	if _, err := asn1.Unmarshal(e.EncryptionAlgorithm.Parameters.FullBytes, &p2); err != nil {
		return nil, fmt.Errorf("parse PBES2-params: %w", err)
	}

	if !p2.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported KDF: %v", p2.KeyDerivationFunc.Algorithm)
	}

	var p2p pbkdf2Params
	if _, err := asn1.Unmarshal(p2.KeyDerivationFunc.Parameters.FullBytes, &p2p); err != nil {
		return nil, fmt.Errorf("parse PBKDF2-params: %w", err)
	}

	iterations := p2p.IterationCount
	if iterations == 0 {
		iterations = 600000
	}
	// M12 fix: cap the KDF cost and validate key length before deriving.
	// A malicious or corrupt file must not be able to force billions of
	// PBKDF2 iterations (CPU DoS) or an unexpected key size.
	const (
		maxPBKDF2Iterations = 10_000_000
		minPBKDF2SaltLen    = 8
	)
	if iterations > maxPBKDF2Iterations {
		return nil, fmt.Errorf("pbkdf2 iterations %d exceeds cap %d", iterations, maxPBKDF2Iterations)
	}
	if iterations < 1000 {
		return nil, fmt.Errorf("pbkdf2 iterations %d too low", iterations)
	}
	if len(p2p.Salt) < minPBKDF2SaltLen {
		return nil, fmt.Errorf("pbkdf2 salt too short (%d bytes)", len(p2p.Salt))
	}
	keyLen := p2p.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}
	if keyLen != 32 {
		return nil, fmt.Errorf("unsupported key length %d (only 32 for AES-256-CBC)", keyLen)
	}

	key, err := pbkdf2.Key(sha256.New, password, p2p.Salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}

	if !p2.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("unsupported cipher: %v", p2.EncryptionScheme.Algorithm)
	}

	var iv []byte
	if _, err := asn1.Unmarshal(p2.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("parse IV: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	padded := make([]byte, len(e.EncryptedData))
	mode.CryptBlocks(padded, e.EncryptedData)

	if len(padded) == 0 {
		return nil, fmt.Errorf("empty decrypted data")
	}
	padLen := int(padded[len(padded)-1])
	if padLen > aes.BlockSize || padLen > len(padded) {
		return nil, fmt.Errorf("invalid padding")
	}
	privDER := padded[:len(padded)-padLen]

	raw, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a signer")
	}
	if err := CheckPublicKeyStrength(signer.Public()); err != nil {
		return nil, fmt.Errorf("weak key: %w", err)
	}
	return signer, nil
}

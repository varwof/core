// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package pkcs12 provides PFX/PKCS#12 export using pure Go.
package pkcs12

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// pbkdf2Iterations is the PBKDF2-HMAC-SHA-256 iteration count used for PBES2
// key derivation. The sslmate Modern encoder defaults to only 2048 iterations
// (L15), which does not meaningfully resist offline brute-force of a weak
// password. 600k is the OWASP-recommended count for PBKDF2-HMAC-SHA-256.
const pbkdf2Iterations = 600_000

// MinPasswordBytes is the minimum password length accepted for PFX export.
const MinPasswordBytes = 8

// Encode creates a PFX/PKCS#12 archive using pure Go implementation.
// Uses Modern (AES-256-CBC + SHA-256) encryption with a strong PBKDF2
// iteration count (L15).
func Encode(privateKey crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate, password string) ([]byte, error) {
	if err := checkKeyMatch(privateKey, cert); err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		chain = nil
	}
	enc := pkcs12.Modern.WithIterations(pbkdf2Iterations)
	pfxData, err := enc.Encode(privateKey, cert, chain, password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12 encode: %w", err)
	}
	return pfxData, nil
}

func checkKeyMatch(privateKey crypto.Signer, cert *x509.Certificate) error {
	pub := privateKey.Public()
	certPub := cert.PublicKey
	// Compare public keys by marshaling to DER
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal private key public part: %w", err)
	}
	certPubDER, err := x509.MarshalPKIXPublicKey(certPub)
	if err != nil {
		return fmt.Errorf("marshal cert public key: %w", err)
	}
	if string(pubDER) != string(certPubDER) {
		return fmt.Errorf("private key does not match certificate")
	}
	return nil
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/varwof/engine/db"
)

var ErrRootCAImport = errors.New("root CA key must not be imported into database; keep it offline")

func isRootCA(cert *x509.Certificate) bool {
	// Self-signed CA: Subject == Issuer + IsCA + BasicConstraintsValid.
	// H8 fix: also check BasicConstraintsValid to distinguish from attacker-wrapped
	// intermediate certs (Subject≠Issuer or no BasicConstraints) that embed a root key.
	return cert.IsCA && cert.BasicConstraintsValid && bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// isSuspectRootKey checks whether the public key in the certificate matches any
// known root CA key already in the database. This prevents an attacker from
// importing a root CA private key by wrapping it in a non-self-signed IsCA cert
// (H8 bypass: Subject≠Issuer dodges isRootCA, but key match reveals the truth).
func isSuspectRootKey(database *db.DB, cert *x509.Certificate) bool {
	if database == nil {
		return false
	}
	cas, err := database.ListCAMetas()
	if err != nil {
		return false
	}
	certKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	for _, ca := range cas {
		if ca.CertDER == nil {
			continue
		}
		existing, err := x509.ParseCertificate(ca.CertDER)
		if err != nil {
			continue
		}
		if !existing.IsCA || !bytes.Equal(existing.RawIssuer, existing.RawSubject) {
			continue
		}
		existingKeyBytes, err := x509.MarshalPKIXPublicKey(existing.PublicKey)
		if err != nil {
			continue
		}
		if bytes.Equal(certKeyBytes, existingKeyBytes) {
			return true
		}
	}
	return false
}

func ImportExternalCA(database *db.DB, name string, certPEM, keyPEM []byte, password string) (*db.CAMeta, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	if isRootCA(cert) {
		return nil, ErrRootCAImport
	}

	// H8 fix: also reject if the public key matches any known root CA in the DB,
	// even if the certificate is not self-signed (attacker bypass via Subject≠Issuer).
	if isSuspectRootKey(database, cert) {
		return nil, fmt.Errorf("certificate public key matches an existing root CA; root CA keys must not be imported")
	}

	signer, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	if err := verifyKeyPair(cert.PublicKey, signer); err != nil {
		return nil, fmt.Errorf("key pair mismatch: %w", err)
	}

	existing, err := database.GetCAMeta(name)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("check CA %q: %w", name, err)
	}
	if existing != nil {
		return nil, fmt.Errorf("CA %q already exists in database", name)
	}

	if password == "" {
		// Fail fast instead of silently skipping private-key storage: a CA
		// imported without a password would be unusable for signing and the
		// failure would only surface later at LoadSigner.
		return nil, fmt.Errorf("a key_password is required to encrypt and store the imported CA private key")
	}
	encrypted, err := EncryptKeyPKCS8(signer, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}
	keyEnc := encrypted

	record := &db.CAMeta{
		Name:         name,
		CertDER:      cert.Raw,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		KeyAlgorithm: pubKeyAlgorithm(cert.PublicKey),
		Fingerprint:  db.Fingerprint(cert.Raw),
		KeyEncrypted: keyEnc,
	}

	if err := database.InsertCAMeta(record); err != nil {
		return nil, fmt.Errorf("insert ca_meta: %w", err)
	}

	return record, nil
}

func verifyKeyPair(pub crypto.PublicKey, signer crypto.Signer) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal cert public key: %w", err)
	}
	signerPubBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal signer public key: %w", err)
	}
	if string(pubKeyBytes) != string(signerPubBytes) {
		return errors.New("certificate public key does not match private key")
	}
	return nil
}

func pubKeyAlgorithm(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ecdsa-p%d", k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", pub)
	}
}

func LoadSignerFromDB(database *db.DB, caName, password string) (*x509.Certificate, crypto.Signer, error) {
	meta, err := database.GetCAMeta(caName)
	if err != nil {
		return nil, nil, fmt.Errorf("get CA %q: %w", caName, err)
	}

	cert, err := x509.ParseCertificate(meta.CertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	if len(meta.KeyEncrypted) == 0 {
		return cert, nil, fmt.Errorf("no encrypted key for CA %q", caName)
	}

	signer, err := DecryptKeyPKCS8(meta.KeyEncrypted, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt CA key: %w", err)
	}

	return cert, signer, nil
}

func LoadSignerAny(certPath, keyPath string, database *db.DB, caName, keyPassword string) (*x509.Certificate, crypto.Signer, error) {
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return LoadSigner(certPath, keyPath)
			}
		}
	}
	if database != nil {
		return LoadSignerFromDB(database, caName, keyPassword)
	}
	return nil, nil, fmt.Errorf("CA %q: neither file nor DB key available", caName)
}

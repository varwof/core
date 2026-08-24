// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"os"
	"time"

	"github.com/varwof/pkcs7"
)

type Config struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Chain []*x509.Certificate
	Hash  crypto.Hash
}

const embeddedSigMagic = "PKISIG\x00"

type embeddedSigASN1 struct {
	Content   []byte `asn1:"octet"`
	Signature []byte `asn1:"octet"`
}

func SignDetached(filePath string, cfg *Config) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	sdDER, err := pkcs7.BuildSignedDataWithHash(
		pkcs7.OIDData,
		data,
		cfg.Cert,
		cfg.Key,
		cfg.Chain,
		cfg.Hash,
	)
	if err != nil {
		return "", fmt.Errorf("build signed data: %w", err)
	}

	sigPath := filePath + ".p7s"
	if err := os.WriteFile(sigPath, sdDER, 0644); err != nil {
		return "", fmt.Errorf("write sig: %w", err)
	}

	return sigPath, nil
}

func SignEmbedded(filePath string, cfg *Config) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	sdDER, err := pkcs7.BuildSignedDataWithHash(
		pkcs7.OIDData,
		data,
		cfg.Cert,
		cfg.Key,
		cfg.Chain,
		cfg.Hash,
	)
	if err != nil {
		return fmt.Errorf("build signed data: %w", err)
	}

	wrapped, err := asn1.Marshal(embeddedSigASN1{Content: data, Signature: sdDER})
	if err != nil {
		return fmt.Errorf("marshal embedded: %w", err)
	}

	if err := os.WriteFile(filePath, wrapped, 0644); err != nil {
		return fmt.Errorf("write embedded: %w", err)
	}

	return nil
}

func VerifyDetached(filePath, sigPath string, rootCAs *x509.CertPool) error {
	return VerifyDetachedAt(filePath, sigPath, rootCAs, time.Time{})
}

func VerifyDetachedAt(filePath, sigPath string, rootCAs *x509.CertPool, currentTime time.Time) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read sig: %w", err)
	}

	return verifyPKCS7(data, sigData, rootCAs, currentTime)
}

func verifyPKCS7(data, sigData []byte, rootCAs *x509.CertPool, currentTime time.Time) error {
	var ci pkcs7.ContentInfo
	if _, err := asn1.Unmarshal(sigData, &ci); err != nil {
		return fmt.Errorf("parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(pkcs7.OIDSignedData) {
		return fmt.Errorf("not a PKCS#7 SignedData")
	}

	var sd pkcs7.SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return fmt.Errorf("parse SignedData: %w", err)
	}

	if len(sd.SignerInfos) == 0 {
		return fmt.Errorf("no signer infos")
	}

	si := sd.SignerInfos[0]

	// Determine hash from the SignerInfo's DigestAlgorithm
	hash, newHash := hashFromOID(si.DigestAlgorithm.Algorithm)

	h := newHash()
	h.Write(data)
	contentDigest := h.Sum(nil)

	foundMessageDigest := false
	for _, attr := range si.SignedAttributes {
		if attr.Type.Equal([]int{1, 2, 840, 113549, 1, 9, 4}) && len(attr.Values) > 0 {
			if len(attr.Values[0].Bytes) != len(contentDigest) {
				return fmt.Errorf("messageDigest length mismatch")
			}
			for i := range contentDigest {
				if attr.Values[0].Bytes[i] != contentDigest[i] {
					return fmt.Errorf("messageDigest mismatch: content has been modified")
				}
			}
			foundMessageDigest = true
		}
	}
	if !foundMessageDigest {
		return fmt.Errorf("no messageDigest attribute")
	}

	// Re-encode signed attributes as SET OF and verify signature
	wrapped, err := asn1.Marshal(struct {
		Attrs []pkcs7.Attribute `asn1:"set"`
	}{Attrs: si.SignedAttributes})
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	skip := 2
	if len(wrapped) > 1 && wrapped[1]&0x80 != 0 {
		skip = 2 + int(wrapped[1]&0x7f)
	}
	attrDER := wrapped[skip:]

	h2 := newHash()
	h2.Write(attrDER)
	sigHash := h2.Sum(nil)

	// Find the signer's certificate
	var signerCert *x509.Certificate
	var serialNum big.Int
	snBytes := si.IssuerAndSerial.SerialNumber.FullBytes
	if snBytes == nil {
		snBytes = si.IssuerAndSerial.SerialNumber.Bytes
	}
	if _, err := asn1.Unmarshal(snBytes, &serialNum); err == nil {
		for _, certRaw := range sd.Certificates {
			cert, err := x509.ParseCertificate(certRaw.FullBytes)
			if err != nil {
				continue
			}
			if serialNum.Cmp(cert.SerialNumber) == 0 {
				signerCert = cert
				break
			}
		}
	}
	if signerCert == nil && len(sd.Certificates) > 0 {
		signerCert, _ = x509.ParseCertificate(sd.Certificates[0].FullBytes)
	}
	if signerCert == nil {
		return fmt.Errorf("signer certificate not found in PKCS#7")
	}

	if err := verifySignature(signerCert.PublicKey, hash, sigHash, si.Signature); err != nil {
		return err
	}

	// Chain validation if root CAs provided
	if rootCAs != nil {
		intermediates := x509.NewCertPool()
		for _, certRaw := range sd.Certificates {
			cert, err := x509.ParseCertificate(certRaw.FullBytes)
			if err != nil || cert.Equal(signerCert) {
				continue
			}
			intermediates.AddCert(cert)
		}
		if _, err := signerCert.Verify(x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediates,
			CurrentTime:   currentTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("chain verification: %w", err)
		}
	}

	return nil
}

func verifySignature(pub crypto.PublicKey, hash crypto.Hash, sigHash, signature []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, sigHash, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, hash, sigHash, signature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, sigHash, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key type: %T", pub)
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, func() hash.Hash) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		return crypto.SHA256, crypto.SHA256.New
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}):
		return crypto.SHA384, crypto.SHA384.New
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}):
		return crypto.SHA512, crypto.SHA512.New
	case sm3Available && oid.Equal(sm3OID):
		return SM3Hash, NewSM3
	default:
		return crypto.SHA256, crypto.SHA256.New
	}
}

func VerifyEmbedded(filePath string, rootCAs *x509.CertPool) error {
	return VerifyEmbeddedAt(filePath, rootCAs, time.Time{})
}

func VerifyEmbeddedAt(filePath string, rootCAs *x509.CertPool, currentTime time.Time) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Try ASN.1 format first
	var asn1Sig embeddedSigASN1
	if _, err := asn1.Unmarshal(data, &asn1Sig); err == nil && len(asn1Sig.Content) > 0 && len(asn1Sig.Signature) > 0 {
		return verifyPKCS7(asn1Sig.Content, asn1Sig.Signature, rootCAs, currentTime)
	}

	// Fallback: legacy magic-based format
	magic := []byte(embeddedSigMagic)
	idx := lastIndex(data, magic)
	if idx < 0 {
		return fmt.Errorf("no embedded signature found")
	}

	headerLen := len(magic) + 8
	if idx+headerLen+4 > len(data) {
		return fmt.Errorf("truncated embedded signature")
	}

	var sigLen int
	fmt.Sscanf(string(data[idx+len(magic):idx+headerLen]), "%08x", &sigLen)
	if idx+headerLen+sigLen > len(data) {
		return fmt.Errorf("embedded signature truncated")
	}

	originalData := data[:idx]
	sigData := data[idx+headerLen : idx+headerLen+sigLen]

	return verifyPKCS7(originalData, sigData, rootCAs, currentTime)
}

func lastIndex(data, sep []byte) int {
	for i := len(data) - len(sep); i >= 0; i-- {
		match := true
		for j := 0; j < len(sep); j++ {
			if data[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

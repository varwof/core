// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
)

func ExtractCertFields(cert *x509.Certificate) (o, c, issuerDN, keyAlgo string, keySize int, sigAlgo, ski, aki, san string) {
	o = subjectFirst(cert.Subject.Organization)
	c = subjectFirst(cert.Subject.Country)
	issuerDN = cert.Issuer.String()
	keyAlgo, keySize = pubKeyInfo(cert.PublicKey)
	sigAlgo = cert.SignatureAlgorithm.String()
	ski = bytesHex(cert.SubjectKeyId)
	aki = bytesHex(cert.AuthorityKeyId)
	san = formatSANs(cert)
	return
}

func ExtractTrustAnchorFields(cert *x509.Certificate) (o, c, keyAlgo string, keySize int, sha1fp string, pathLen int) {
	o = subjectFirst(cert.Subject.Organization)
	c = subjectFirst(cert.Subject.Country)
	keyAlgo, keySize = pubKeyInfo(cert.PublicKey)
	h := sha1.Sum(cert.Raw)
	sha1fp = fmt.Sprintf("%x", h)
	if cert.MaxPathLen != 0 || cert.MaxPathLenZero {
		pathLen = cert.MaxPathLen
	} else {
		pathLen = -1
	}
	return
}

func subjectFirst(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func pubKeyInfo(pub crypto.PublicKey) (algo string, size int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

func bytesHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func ExtractSPKIHash(cert *x509.Certificate) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", h)
}

func formatSANs(cert *x509.Certificate) string {
	var parts []string
	for _, dns := range cert.DNSNames {
		parts = append(parts, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		parts = append(parts, "email:"+email)
	}
	return strings.Join(parts, ", ")
}

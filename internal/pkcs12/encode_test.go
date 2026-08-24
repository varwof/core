// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package pkcs12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	p12 "software.sslmate.com/src/go-pkcs12"
)

func testCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TestPFX"},
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

func testChain(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestRoot"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestSigner"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTmpl, rootCert, &signerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	signerCert, err := x509.ParseCertificate(signerDER)
	if err != nil {
		t.Fatal(err)
	}
	return signerCert, signerKey, []*x509.Certificate{rootCert}
}

func verifyPFX(t *testing.T, pfxData []byte, password string) {
	t.Helper()
	_, leaf, caCerts, err := p12.DecodeChain(pfxData, password)
	if err != nil {
		t.Fatalf("pkcs12.DecodeChain: %v", err)
	}
	if leaf == nil {
		t.Fatal("no leaf certificate decoded")
	}
	_ = caCerts
}

func TestEncode(t *testing.T) {
	cert, key := testCert(t)
	pfxData, err := Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PFX data")
	}
	verifyPFX(t, pfxData, "")
}

func TestEncodeWithPassword(t *testing.T) {
	cert, key := testCert(t)
	pfxData, err := Encode(key, cert, nil, "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PFX data")
	}
	verifyPFX(t, pfxData, "secret123")
}

func TestEncodeWithChain(t *testing.T) {
	cert, key, chain := testChain(t)
	pfxData, err := Encode(key, cert, chain, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PFX data")
	}
	verifyPFX(t, pfxData, "")
}

func TestEncodeWithChainPassword(t *testing.T) {
	cert, key, chain := testChain(t)
	pfxData, err := Encode(key, cert, chain, "chainpass")
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PFX data")
	}
	verifyPFX(t, pfxData, "chainpass")
}

func TestEncodeBadKey(t *testing.T) {
	_, wrongKey := testCert(t)
	realCert, _ := testCert(t)
	_, err := Encode(wrongKey, realCert, nil, "")
	if err == nil {
		t.Fatal("expected error for mismatched key and cert")
	}
}

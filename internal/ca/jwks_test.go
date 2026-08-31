// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/types/aicjwt"
)

func testCert(t *testing.T, tmpl *x509.Certificate, key any) *x509.Certificate {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("key is %T, not cipher.Signer", key)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func makeTestCert(t *testing.T, keyType string) (*x509.Certificate, any) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "root-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	switch keyType {
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa key: %v", err)
		}
		return testCert(t, tmpl, k), k
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		return testCert(t, tmpl, k), k
	default:
		t.Fatalf("unknown key type %q", keyType)
		return nil, nil
	}
}

func TestSPKISHA256ConsistentWithAICJWT(t *testing.T) {
	cert, _ := makeTestCert(t, "ecdsa")
	got := SPKISHA256(cert)
	if got == "" {
		t.Fatal("empty SPKI hash")
	}
	same, err := aicjwt.SPKIHash(cert, "sha-256")
	if err != nil {
		t.Fatalf("aicjwt.SPKIHash: %v", err)
	}
	if got != same {
		t.Fatalf("SPKISHA256 mismatch with aicjwt.SPKIHash: %q vs %q", got, same)
	}
}

func TestCertToJWKRSA(t *testing.T) {
	cert, _ := makeTestCert(t, "rsa")
	j, err := CertToJWK(cert)
	if err != nil {
		t.Fatalf("CertToJWK: %v", err)
	}
	if j.Kty != "RSA" || j.N == "" || j.E == "" {
		t.Fatalf("RSA JWK missing kty/n/e: %+v", j)
	}
	if j.Kid == "" || j.Kid != SPKISHA256(cert) {
		t.Fatalf("kid mismatch: %q vs %q", j.Kid, SPKISHA256(cert))
	}
	if len(j.X5c) != 1 {
		t.Fatalf("x5c length = %d, want 1", len(j.X5c))
	}
	if j.X5t == "" {
		t.Fatal("missing x5t")
	}
	if j.Use != "sig" {
		t.Fatalf("use = %q, want sig", j.Use)
	}

	// Round-trip: JWK → public key must reproduce the original key.
	der, err := base64.StdEncoding.DecodeString(j.X5c[0])
	if err != nil {
		t.Fatalf("decode x5c: %v", err)
	}
	c2, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse x5c cert: %v", err)
	}
	pubFromJWK, err := aicjwt.JWKToPublic(aicjwt.JWK{Kty: j.Kty, N: j.N, E: j.E})
	if err != nil {
		t.Fatalf("JWKToPublic: %v", err)
	}
	r1 := cert.PublicKey.(*rsa.PublicKey)
	r2 := pubFromJWK.(*rsa.PublicKey)
	if r1.N.Cmp(r2.N) != 0 || r1.E != r2.E {
		t.Fatalf("RSA JWK round-trip mismatch")
	}
	if c2.PublicKey.(*rsa.PublicKey).N.Cmp(r1.N) != 0 {
		t.Fatalf("x5c cert does not match original key")
	}
}

func TestCertToJWKEC(t *testing.T) {
	cert, _ := makeTestCert(t, "ecdsa")
	j, err := CertToJWK(cert)
	if err != nil {
		t.Fatalf("CertToJWK: %v", err)
	}
	if j.Kty != "EC" || j.Crv != "P-256" || j.X == "" || j.Y == "" {
		t.Fatalf("EC JWK missing kty/crv/x/y: %+v", j)
	}
	if j.Kid != SPKISHA256(cert) {
		t.Fatalf("kid mismatch")
	}
	alg, err := JWSToAlg(cert.PublicKey)
	if err != nil {
		t.Fatalf("JWSToAlg: %v", err)
	}
	if alg != "ES256" {
		t.Fatalf("alg = %q, want ES256", alg)
	}
	b, err := BuildJWKSJSON([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("BuildJWKSJSON: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty jwks json")
	}
}

func TestJWSToAlg(t *testing.T) {
	cases := []struct {
		make  func(t *testing.T) any
		alg   string
		rsaOK bool
	}{
		{func(t *testing.T) any { k, _ := makeTestCert(t, "ecdsa"); return k.PublicKey }, "ES256", true},
		{func(t *testing.T) any { k, _ := makeTestCert(t, "rsa"); return k.PublicKey }, "RS256", true},
	}
	for _, c := range cases {
		alg, err := JWSToAlg(c.make(t))
		if err != nil {
			t.Fatalf("JWSToAlg: %v", err)
		}
		if alg != c.alg {
			t.Fatalf("alg = %q, want %q", alg, c.alg)
		}
	}
}

func TestBuildJWKSDedup(t *testing.T) {
	cert, _ := makeTestCert(t, "ecdsa")
	ks, err := BuildJWKS([]*x509.Certificate{cert, cert})
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(ks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1 (dedupe)", len(ks.Keys))
	}
	b, err := BuildJWKSJSON([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("BuildJWKSJSON: %v", err)
	}
	var decoded struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("json unmarshal jwks: %v", err)
	}
	if len(decoded.Keys) != 1 || decoded.Keys[0].Kid == "" || decoded.Keys[0].Kty != "EC" {
		t.Fatalf("bad jwks json: %+v", decoded)
	}
}
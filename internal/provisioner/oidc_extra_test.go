// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestVerifyRSASignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := "allowed"
	hashed := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	good := &jwkKey{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	if err := verifyRSASignature(msg, sig, good, crypto.SHA256); err != nil {
		t.Fatalf("valid RSA signature rejected: %v", err)
	}
	if err := verifyRSASignature(msg, append(append([]byte{}, sig[:len(sig)-1]...), sig[len(sig)-1]^0xff), good, crypto.SHA256); err == nil {
		t.Fatal("tampered RSA signature accepted")
	}

	badN := &jwkKey{N: "!!!not-base64!!!", E: "AQAB"}
	if err := verifyRSASignature(msg, sig, badN, crypto.SHA256); err == nil {
		t.Fatal("bad N base64 must error")
	}
	badE := &jwkKey{N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: "%%%"}
	if err := verifyRSASignature(msg, sig, badE, crypto.SHA256); err == nil {
		t.Fatal("bad E base64 must error")
	}
}

func TestVerifyECDSASignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := "allowed"
	hashed := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	size := 32
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])

	good := &jwkKey{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
	if err := verifyECDSASignature(msg, sig, good, crypto.SHA256); err != nil {
		t.Fatalf("valid ECDSA signature rejected: %v", err)
	}
	if err := verifyECDSASignature(msg, append(append([]byte{}, sig[:size-1]...), sig[size-1]^0xff), good, crypto.SHA256); err == nil {
		t.Fatal("tampered ECDSA signature accepted")
	}
	// M1: wrong-length raw signature (shorter than 2*coordinate-size) must be rejected.
	if err := verifyECDSASignature(msg, sig[:size+1], good, crypto.SHA256); err == nil {
		t.Fatal("truncated ECDSA signature must be rejected")
	}
	if err := verifyECDSASignature(msg, append(append([]byte{}, sig...), 0x00), good, crypto.SHA256); err == nil {
		t.Fatal("oversized ECDSA signature must be rejected")
	}

	unsupported := &jwkKey{Crv: "P-999", X: good.X, Y: good.Y}
	if err := verifyECDSASignature(msg, sig, unsupported, crypto.SHA256); err == nil {
		t.Fatal("unsupported curve must error")
	}
	badX := &jwkKey{Crv: "P-256", X: "###", Y: good.Y}
	if err := verifyECDSASignature(msg, sig, badX, crypto.SHA256); err == nil {
		t.Fatal("bad EC x base64 must error")
	}
	badY := &jwkKey{Crv: "P-256", X: good.X, Y: "@@@"}
	if err := verifyECDSASignature(msg, sig, badY, crypto.SHA256); err == nil {
		t.Fatal("bad EC y base64 must error")
	}
}

// TestExpectedHash exercises the H1 alg allowlist + alg-to-key binding.
func TestExpectedHash(t *testing.T) {
	cases := []struct {
		name string
		alg  string
		key  *jwkKey
		want string // empty => expect an error
	}{
		{"rsa rs256", "RS256", &jwkKey{Kty: "RSA"}, ""},
		{"rsa es256 rejected", "ES256", &jwkKey{Kty: "RSA"}, "err"},
		{"rsa none rejected", "none", &jwkKey{Kty: "RSA"}, "err"},
		{"rsa hs256 rejected", "HS256", &jwkKey{Kty: "RSA"}, "err"},
		{"rsa empty rejected", "", &jwkKey{Kty: "RSA"}, "err"},
		{"ec es256 p256", "ES256", &jwkKey{Kty: "EC", Crv: "P-256"}, ""},
		{"ec es384 p384", "ES384", &jwkKey{Kty: "EC", Crv: "P-384"}, ""},
		{"ec es512 p521", "ES512", &jwkKey{Kty: "EC", Crv: "P-521"}, ""},
		{"ec es256 p384 rejected", "ES256", &jwkKey{Kty: "EC", Crv: "P-384"}, "err"},
		{"ec es384 p256 rejected", "ES384", &jwkKey{Kty: "EC", Crv: "P-256"}, "err"},
		{"ec rs256 rejected", "RS256", &jwkKey{Kty: "EC", Crv: "P-256"}, "err"},
		{"ec hs512 rejected", "HS512", &jwkKey{Kty: "EC", Crv: "P-256"}, "err"},
		{"unknown kty rejected", "RS256", &jwkKey{Kty: "OKP", Crv: "Ed25519"}, "err"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ecAlg, err := expectedHash(c.alg, c.key)
			if c.want == "err" {
				if err == nil {
					t.Fatalf("expected error for alg=%q key=%+v", c.alg, c.key)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected ok, got: %v", err)
			}
			if c.key.Kty == "EC" && ecAlg != c.alg {
				t.Fatalf("expected ecAlg %q, got %q", c.alg, ecAlg)
			}
		})
	}
}

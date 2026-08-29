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
	if err := verifyRSASignature(msg, sig, good); err != nil {
		t.Fatalf("valid RSA signature rejected: %v", err)
	}
	if err := verifyRSASignature(msg, append(append([]byte{}, sig[:len(sig)-1]...), sig[len(sig)-1]^0xff), good); err == nil {
		t.Fatal("tampered RSA signature accepted")
	}

	badN := &jwkKey{N: "!!!not-base64!!!", E: "AQAB"}
	if err := verifyRSASignature(msg, sig, badN); err == nil {
		t.Fatal("bad N base64 must error")
	}
	badE := &jwkKey{N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: "%%%"}
	if err := verifyRSASignature(msg, sig, badE); err == nil {
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
	if err := verifyECDSASignature(msg, sig, good); err != nil {
		t.Fatalf("valid ECDSA signature rejected: %v", err)
	}
	if err := verifyECDSASignature(msg, append(append([]byte{}, sig[:size-1]...), sig[size-1]^0xff), good); err == nil {
		t.Fatal("tampered ECDSA signature accepted")
	}

	unsupported := &jwkKey{Crv: "P-999", X: good.X, Y: good.Y}
	if err := verifyECDSASignature(msg, sig, unsupported); err == nil {
		t.Fatal("unsupported curve must error")
	}
	badX := &jwkKey{Crv: "P-256", X: "###", Y: good.Y}
	if err := verifyECDSASignature(msg, sig, badX); err == nil {
		t.Fatal("bad EC x base64 must error")
	}
	badY := &jwkKey{Crv: "P-256", X: good.X, Y: "@@@"}
	if err := verifyECDSASignature(msg, sig, badY); err == nil {
		t.Fatal("bad EC y base64 must error")
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCheckPublicKeyStrength_RSA(t *testing.T) {
	// RSA-2048 should pass
	k2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate 2048 key: %v", err)
	}
	if err := CheckPublicKeyStrength(k2048.Public()); err != nil {
		t.Fatalf("RSA-2048 should pass, got %v", err)
	}

	// RSA-4096 should pass
	k4096, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generate 4096 key: %v", err)
	}
	if err := CheckPublicKeyStrength(k4096.Public()); err != nil {
		t.Fatalf("RSA-4096 should pass, got %v", err)
	}
}

func TestCheckPublicKeyStrength_RSA_Weak(t *testing.T) {
	// Directly construct rsa.PublicKey with RSA-1024 to test rejection (simulating weak CSR)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate 1024 key: %v", err)
	}
	err = CheckPublicKeyStrength(weak.Public())
	if err == nil {
		t.Fatal("RSA-1024 should be rejected")
	}
	if err.Error() != "weak RSA key: 1024 bits < minimum 2048 bits (NIST SP 800-57)" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPublicKeyStrength_EC(t *testing.T) {
	// P-256 should pass
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	if err := CheckPublicKeyStrength(k.Public()); err != nil {
		t.Fatalf("P-256 should pass, got %v", err)
	}

	// P-384 should pass
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384: %v", err)
	}
	if err := CheckPublicKeyStrength(k384.Public()); err != nil {
		t.Fatalf("P-384 should pass, got %v", err)
	}

	// P-521 should pass
	k521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521: %v", err)
	}
	if err := CheckPublicKeyStrength(k521.Public()); err != nil {
		t.Fatalf("P-521 should pass, got %v", err)
	}
}

func TestCheckPublicKeyStrength_EC_Weak(t *testing.T) {
	// P-224 rejected (weak curve)
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	err = CheckPublicKeyStrength(k.Public())
	if err == nil {
		t.Fatal("P-224 should be rejected")
	}
	if err.Error() != "weak EC curve: P-224 not allowed (NIST rejects legacy curves)" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPublicKeyStrength_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	if err := CheckPublicKeyStrength(priv.Public()); err != nil {
		t.Fatalf("Ed25519 should pass, got %v", err)
	}
}

func TestCheckPublicKeyStrength_Nil(t *testing.T) {
	// nil public key should not block (caller handles missing)
	if err := CheckPublicKeyStrength(nil); err != nil {
		t.Fatalf("nil should pass-through, got %v", err)
	}
}

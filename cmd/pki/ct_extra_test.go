// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestVerifySCTWithKeyBranches(t *testing.T) {
	if err := verifySCTWithKey(nil, 0, "", 0, "", nil, ""); err == nil {
		t.Fatal("empty public_key must error")
	}
	if err := verifySCTWithKey(nil, 0, "", 0, "", nil, "not-a-key"); err == nil {
		t.Fatal("unparseable public_key must error")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// Valid key but nil cert: VerifySCT rejects before any signature work.
	if err := verifySCTWithKey(nil, 1, "logid", 0, "", []byte{1, 2, 3, 4, 5}, pubPEM); err == nil {
		t.Fatal("valid key with nil cert must error")
	}
}

func TestSplitComma(t *testing.T) {
	got := splitComma(" a ,, b , c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitComma: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitComma[%d]=%q want %q (all=%v)", i, got[i], want[i], got)
		}
	}
	if got := splitComma(""); got != nil {
		t.Fatalf("empty input: %v", got)
	}
	if got := splitComma(",,,"); len(got) != 0 {
		t.Fatalf("only separators: %v", got)
	}
}

var _ = strings.TrimSpace

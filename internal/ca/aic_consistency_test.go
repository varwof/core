// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"encoding/base64"
	"strings"
	"testing"

	pki "github.com/varwof/types"
)

// TestConsistency_ParsePrincipalUid verifies that the two independent implementations
// of ParsePrincipalUid (varwof-core and types) have consistent boundary behavior,
// preventing dual-copy drift.
// Background: 2026-08-07 review found varwof-core once missed realm/identifier length
// validation, caused by manual synchronization between two PrincipalUid implementations.
// This test locks behavioral equivalence using the same set of vectors.
func TestConsistency_ParsePrincipalUid(t *testing.T) {
	valid32 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cases := []string{
		"varwof:admin@varwof.com:" + valid32,                      // valid
		"r:id:" + base64.RawURLEncoding.EncodeToString([]byte{1}), // keyHash 1 byte (valid lower bound)
		strings.Repeat("r", 128) + ":id:" + valid32,               // realm 128 (upper bound valid)
		"r:" + strings.Repeat("i", 256) + ":" + valid32,           // identifier 256 (upper bound valid)
		strings.Repeat("r", 129) + ":id:" + valid32,               // realm 129 exceeds limit
		"r:" + strings.Repeat("i", 257) + ":" + valid32,           // identifier 257 exceeds limit
		":id:" + valid32, // empty realm
		"r::" + valid32,  // empty identifier
		"r:id:" + base64.RawURLEncoding.EncodeToString(make([]byte, 65)), // keyHash 65 exceeds limit
		"r:id:!!!invalid-base64!!!",                                      // invalid base64
		"r:id",                                                           // malformed (missing segment)
		"a:b:c:d",                                                        // extra segments
		"re:alm:id:" + valid32,                                           // realm contains colon
	}
	for _, s := range cases {
		gotCA, errCA := ParsePrincipalUid(s)
		gotPT, errPT := pki.ParsePrincipalUid(s)
		if (errCA != nil) != (errPT != nil) {
			t.Errorf("ParsePrincipalUid(%q): err mismatch ca=%v pki=%v", s, errCA, errPT)
			continue
		}
		if errCA == nil {
			if gotCA.Realm != gotPT.Realm || gotCA.Identifier != gotPT.Identifier ||
				string(gotCA.KeyHash) != string(gotPT.KeyHash) {
				t.Errorf("ParsePrincipalUid(%q): value mismatch ca=%+v pki=%+v", s, gotCA, gotPT)
			}
			if gotCA.HashAlgoOID().String() != gotPT.HashAlgoOID().String() {
				t.Errorf("ParsePrincipalUid(%q): HashAlgoOID mismatch ca=%v pki=%v", s, gotCA.HashAlgoOID(), gotPT.HashAlgoOID())
			}
		}
	}
}

// TestConsistency_ValidatePrincipalUidKeyHash verifies that the two implementations
// have consistent keyHash validation behavior.
func TestConsistency_ValidatePrincipalUidKeyHash(t *testing.T) {
	mk := func(n int) []byte { return make([]byte, n) }
	cases := []struct {
		name string
		hash []byte
	}{
		{"empty keyHash", nil},
		{"1 byte", mk(1)},
		{"31 bytes", mk(31)},
		{"32 bytes valid", mk(32)},
		{"64 bytes", mk(64)},
		{"65 bytes", mk(65)},
	}
	for _, c := range cases {
		errCA := ValidatePrincipalUidKeyHash(PrincipalUid{Realm: "r", Identifier: "i", KeyHash: c.hash})
		errPT := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{Realm: "r", Identifier: "i", KeyHash: c.hash})
		if (errCA != nil) != (errPT != nil) {
			t.Errorf("%s: err mismatch ca=%v pki=%v", c.name, errCA, errPT)
		}
	}
}

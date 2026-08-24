//go:build !gmsm

package signer

import (
	"crypto"
	"encoding/asn1"
	"hash"
)

// Non-SM3 stub: SM3Hash is an unregistered high value, sm3OID won't match.
const SM3Hash crypto.Hash = crypto.Hash(0xFFFF)

var sm3Available = false
var sm3OID = asn1.ObjectIdentifier{0} // won't match any real OID

// NewSM3 should never be called when sm3Available is false.
func NewSM3() hash.Hash { panic("SM3 not available, build with -tags gmsm") }

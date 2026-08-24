//go:build gmsm

package signer

import (
	"crypto"
	"encoding/asn1"
	"hash"

	"github.com/tjfoc/gmsm/sm3"
)

var _ hash.Hash = sm3.New() // compile-time check

// SM3Hash is our internal SM3 hash ID (not registered with crypto.RegisterHash).
const SM3Hash crypto.Hash = crypto.Hash(0x223)

var sm3Available = true

// sm3OID is the OID for SM3 hash (GB/T 32905-2016).
var sm3OID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}

// NewSM3 returns a new SM3 hash.Hash, wrapping tjfoc/gmsm.
func NewSM3() hash.Hash {
	return sm3.New()
}

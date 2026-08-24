package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// C7: CA master key auto-rotation with transition-period dual-signing
//
// RotatingSigner wraps a CA certificate + private key so that the active
// signing key can be atomically swapped at runtime without interrupting
// in-flight issuance, while the previous (legacy) key remains available for
// verification during a transition window. This is the same pattern TSA uses
// (internal/tsa/renew.go) but extended for CA master keys where dual-signing
// during rotation is required.
//
// The signer implements crypto.Signer so it can be passed anywhere a key is
// expected; callers that need the active certificate use Cert().
// ─────────────────────────────────────────────────────────────────────

// SignerKey is a CA certificate + its private key.
type SignerKey struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// RotatingSigner provides atomic hot-swap of the active CA signing key with
// a legacy key retained during the transition window.
type RotatingSigner struct {
	active atomic.Pointer[SignerKey]
	legacy atomic.Pointer[SignerKey]
}

// NewRotatingSigner wraps a signer key as the initial active key.
func NewRotatingSigner(cert *x509.Certificate, key crypto.Signer) *RotatingSigner {
	rs := &RotatingSigner{}
	rs.Store(cert, key)
	return rs
}

// Store atomically installs a new active cert+key, promoting the previous
// active key to legacy (dual-signing transition window).
func (rs *RotatingSigner) Store(cert *x509.Certificate, key crypto.Signer) {
	if rs == nil {
		return
	}
	old := rs.active.Swap(&SignerKey{Cert: cert, Key: key})
	if old != nil {
		rs.legacy.Store(old)
	}
}

// Rotate is an alias for Store with clearer semantics: the previous active
// key becomes legacy, the new one becomes active.
func (rs *RotatingSigner) Rotate(cert *x509.Certificate, key crypto.Signer) {
	rs.Store(cert, key)
}

// ClearLegacy drops the retained legacy key, ending the transition window.
func (rs *RotatingSigner) ClearLegacy() {
	if rs == nil {
		return
	}
	rs.legacy.Store(nil)
}

// Active returns the current active cert+key, or nil.
func (rs *RotatingSigner) Active() *SignerKey {
	if rs == nil {
		return nil
	}
	return rs.active.Load()
}

// Legacy returns the retained legacy cert+key during the transition window,
// or nil.
func (rs *RotatingSigner) Legacy() *SignerKey {
	if rs == nil {
		return nil
	}
	return rs.legacy.Load()
}

// Cert returns the active certificate. Safe to call on nil receiver (nil).
func (rs *RotatingSigner) Cert() *x509.Certificate {
	if k := rs.Active(); k != nil {
		return k.Cert
	}
	return nil
}

// Key returns the active signing key.
func (rs *RotatingSigner) Key() crypto.Signer {
	if k := rs.Active(); k != nil {
		return k.Key
	}
	return nil
}

// Public implements crypto.Signer.
func (rs *RotatingSigner) Public() crypto.PublicKey {
	if k := rs.Key(); k != nil {
		return k.Public()
	}
	return nil
}

// Sign implements crypto.Signer, delegating to the active key.
func (rs *RotatingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k := rs.Key()
	if k == nil {
		return nil, fmt.Errorf("rotating signer: no active key")
	}
	return k.Sign(rand, digest, opts)
}

// NeedsRotation reports whether the active CA certificate expires within the
// window (or is already expired).
func (rs *RotatingSigner) NeedsRotation(window time.Duration) bool {
	c := rs.Cert()
	if c == nil {
		return true
	}
	return time.Now().Add(window).After(c.NotAfter)
}

// NotAfter returns the active certificate's NotAfter (zero time if none).
func (rs *RotatingSigner) NotAfter() time.Time {
	if c := rs.Cert(); c != nil {
		return c.NotAfter
	}
	return time.Time{}
}

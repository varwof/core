//go:build gmsm

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

var sm2Supported = true

// sm2Signer wraps a *sm2.PrivateKey as a crypto.Signer. Its Sign method
// performs a native SM2 signature (SM3(ZA || digest)), so certificates
// produced with it carry the pure SM2-with-SM3 signature algorithm OID
// (1.2.156.10197.1.501) rather than ecdsa-with-SHA256.
type sm2Signer struct {
	priv *sm2.PrivateKey
}

func (s *sm2Signer) Public() crypto.PublicKey { return &s.priv.PublicKey }
func (s *sm2Signer) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.priv.Sign(r, digest, opts)
}

// generateSM2Key generates a real SM2 (sm2 P256Sm2 curve) key pair.
func generateSM2Key() (crypto.Signer, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sm2 key: %w", err)
	}
	return &sm2Signer{priv: priv}, nil
}

func isSM2Key(s crypto.Signer) bool {
	_, ok := s.(*sm2Signer)
	return ok
}

// exportSM2Key returns the underlying *sm2.PrivateKey for SM2-specific ops
// (gmsm marshaling, signature, public-key extraction).
func exportSM2Key(s crypto.Signer) crypto.Signer {
	if s2, ok := s.(*sm2Signer); ok {
		return s2.priv
	}
	return s
}

// toSM2PublicKey converts a public key to *sm2.PublicKey. ECDSA P256 keys
// reuse the same coordinate representation and are accepted on the SM2 curve.
func toSM2PublicKey(pub crypto.PublicKey) (*sm2.PublicKey, error) {
	if k, ok := pub.(*sm2.PublicKey); ok {
		return k, nil
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sm2: unsupported public key type %T", pub)
	}
	return &sm2.PublicKey{
		Curve: elliptic.P256(),
		X:     ec.X,
		Y:     ec.Y,
	}, nil
}

// createSM2Certificate signs tmpl with an SM2 CA key using gmsm/x509, producing
// a certificate with the pure SM2-with-SM3 signature algorithm OID.
func createSM2Certificate(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	sm2Pub, err := toSM2PublicKey(pub)
	if err != nil {
		return nil, err
	}
	gtmpl := &gmx509.Certificate{}
	gtmpl.FromX509Certificate(tmpl)
	gparent := &gmx509.Certificate{}
	if parent != nil {
		gparent.FromX509Certificate(parent)
	}
	return gmx509.CreateCertificate(gtmpl, gparent, sm2Pub, signer)
}

// parseSM2Certificate parses a DER certificate produced by gmsm/x509 and
// returns a stdlib x509.Certificate (for the rest of the pipeline).
func parseSM2Certificate(der []byte) (*x509.Certificate, error) {
	gcert, err := gmx509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return gcert.ToX509Certificate(), nil
}

// marshalSM2PrivateKey serializes an SM2 private key to unencrypted PEM
// using gmsm's writer (stdlib PKCS8 cannot encode the SM2 curve).
func marshalSM2PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	priv, ok := key.(*sm2.PrivateKey)
	if !ok {
		if s, ok2 := key.(*sm2Signer); ok2 {
			priv = s.priv
		} else {
			return nil, fmt.Errorf("sm2: not an SM2 private key")
		}
	}
	return gmx509.WritePrivateKeyToPem(priv, nil)
}

// parseSM2PrivateKeyPEM parses an SM2 private key from PEM (gmsm format).
func parseSM2PrivateKeyPEM(pemBytes []byte, pwd []byte) (crypto.Signer, error) {
	priv, err := gmx509.ReadPrivateKeyFromPem(pemBytes, pwd)
	if err != nil {
		return nil, err
	}
	return &sm2Signer{priv: priv}, nil
}

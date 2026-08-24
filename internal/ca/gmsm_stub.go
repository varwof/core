//go:build !gmsm

package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

var sm2Supported = false

func generateSM2Key() (crypto.Signer, error) {
	return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
}

func marshalSM2PrivateKey(_ crypto.PrivateKey) ([]byte, error) {
	return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
}

func isSM2Key(_ crypto.Signer) bool { return false }
func exportSM2Key(s crypto.Signer) crypto.Signer { return s }

func createSM2Certificate(_, _ *x509.Certificate, _ crypto.PublicKey, _ crypto.Signer) ([]byte, error) {
	return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
}

func parseSM2Certificate(_ []byte) (*x509.Certificate, error) {
	return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
}

func parseSM2PrivateKeyPEM(_ []byte, _ []byte) (crypto.Signer, error) {
	return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
}

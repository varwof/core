// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/pkcs7"
)

// ParseCertPEM parses the first certificate from PEM bytes.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in cert data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// PolicySignatureOptions describes the external parameters for policy signature verification.
type PolicySignatureOptions struct {
	// Roots is the trusted CA chain (Issuing CA + Root CA) used to verify the signer certificate.
	Roots *x509.CertPool
	// RequireAdminOU forces the signer certificate OU to contain the admin role when true.
	RequireAdminOU bool
}

// IsAdminOU checks whether the OU represents an admin role (compatible with core's admin and gateway's gateway:admin).
func IsAdminOU(ou string) bool {
	return ou == "admin" || ou == "gateway:admin"
}

// SignerHasAdminOU checks whether the signer certificate carries an admin OU.
func SignerHasAdminOU(cert *x509.Certificate) bool {
	for _, ou := range cert.Subject.OrganizationalUnit {
		if IsAdminOU(ou) {
			return true
		}
	}
	return false
}

// VerifySignedPolicy verifies a PKCS#7 detached signature (policyData is the raw policy bytes).
// On success it returns the signer certificate for further caller checks (OU/status).
func VerifySignedPolicy(sigDER, policyData []byte, opts *PolicySignatureOptions) (*x509.Certificate, error) {
	cert, err := pkcs7.VerifyDetached(sigDER, policyData)
	if err != nil {
		return nil, err
	}
	if opts != nil {
		if opts.RequireAdminOU && !SignerHasAdminOU(cert) {
			return nil, fmt.Errorf("policy signer cert OU missing admin role (subject=%q)", cert.Subject.String())
		}
		// M25 fix: when Roots are provided, verify chain; when nil, refuse
		// to verify — prevents self-signed certs from passing policy check.
		if opts.Roots == nil {
			return nil, fmt.Errorf("policy signer trust roots not configured — refusing to verify (fail-closed)")
		}
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     opts.Roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("policy signer cert chain not trusted: %w", err)
		}
	}
	return cert, nil
}

// LoadCAFromFile loads a PEM CA chain as a CertPool.
func LoadCAFromFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no PEM certs found in CA file")
	}
	return pool, nil
}

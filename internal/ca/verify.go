package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/varwof/engine/db"
)

type ChainNode struct {
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	Trusted     bool   `json:"trusted"`
	Source      string `json:"source,omitempty"`
}

type VerifyResult struct {
	Valid          bool        `json:"valid"`
	Chain          []ChainNode `json:"chain,omitempty"`
	Verified       bool        `json:"verified"`
	RootTrustSource string     `json:"root_trust_source,omitempty"`
}

func LoadTrustPool(cfgCAs map[string]string, database *db.DB) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0

	for _, certPath := range cfgCAs {
		if certPath == "" {
			continue
		}
		pemData, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(pemData) {
			count++
		}
	}

	if database != nil {
		anchors, err := database.ListTrustAnchors(&db.TrustAnchorFilter{
			Trusted: &[]bool{true}[0],
		})
		if err != nil {
			return nil, fmt.Errorf("list trust anchors: %w", err)
		}
		for _, a := range anchors {
			cert, err := x509.ParseCertificate(a.CertDER)
			if err != nil || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				continue
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.CertDER})
			if pool.AppendCertsFromPEM(pemBytes) {
				count++
			}
		}
	}

	if count == 0 {
		return nil, fmt.Errorf("trust pool is empty: no trusted CA certificates found — refusing to verify against system roots (fail-closed)")
	}
	return pool, nil
}

func LoadTrustPoolWithSources(cfgCAs map[string]string, database *db.DB) (*x509.CertPool, map[string]string, error) {
	pool := x509.NewCertPool()
	sources := make(map[string]string)

	for name, certPath := range cfgCAs {
		if certPath == "" {
			continue
		}
		pemData, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		pool.AppendCertsFromPEM(pemData)
		// Track by fingerprint from each cert
		rest := pemData
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
					sources[fp] = fmt.Sprintf("ca_config:%s", name)
				}
			}
			rest = remaining
		}
	}

	if database != nil {
		anchors, err := database.ListTrustAnchors(&db.TrustAnchorFilter{
			Trusted: &[]bool{true}[0],
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list trust anchors: %w", err)
		}
		for _, a := range anchors {
			cert, err := x509.ParseCertificate(a.CertDER)
			if err != nil || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				continue
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.CertDER})
			pool.AppendCertsFromPEM(pemBytes)
			sources[a.HashID] = fmt.Sprintf("trust_anchor:%s:%s", a.Source, a.Name)
		}
	}

	return pool, sources, nil
}

func VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool, sources map[string]string) (*VerifyResult, error) {
	result := &VerifyResult{}

	intermediates := x509.NewCertPool()

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		result.Valid = false
		result.Verified = false
		return result, nil
	}

	result.Valid = true

	if len(chains) > 0 {
		chain := chains[0]
		result.Chain = make([]ChainNode, 0, len(chain))

		for i, c := range chain {
			fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))
			node := ChainNode{
				Subject:     c.Subject.String(),
				Fingerprint: fp,
				Issuer:      c.Issuer.String(),
			}
			if i == len(chain)-1 {
				// Root certificate
				if sources != nil {
					if src, ok := sources[fp]; ok {
						node.Trusted = true
						node.Source = src
						result.RootTrustSource = src
					}
				}
			}
			result.Chain = append(result.Chain, node)
		}

		// Check if chain terminates in a trusted anchor
		if sources != nil && len(chain) > 0 {
			root := chain[len(chain)-1]
			rootFP := fmt.Sprintf("%x", sha256.Sum256(root.Raw))
			if _, ok := sources[rootFP]; ok {
				result.Verified = true
			}
		}
	}

	return result, nil
}

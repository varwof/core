// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/varwof/engine/db"
)

type CreateConfig struct {
	DB                *db.DB
	Name              string
	SubjectName       string // optional, overrides Name as CN
	Profile           Profile
	Parent            *x509.Certificate
	ParentKey         crypto.Signer
	KeyType           string
	ReuseKey          crypto.Signer
	Validity          time.Duration
	CRLBaseURL        string
	PermittedDomains  []string
	ExcludedDomains   []string
	PermittedEmails   []string
	ExcludedEmails    []string
	PermittedURIs     []string
	ExcludedURIs      []string
	PermittedIPRanges []string
	ExcludedIPRanges  []string
	DefaultCountry    string
	DefaultOrg        string
	MaxPathLen        int // override profile default (0 = use profile default)
	OCSPURL           string
	IssuerURL         string
}

func IsRootCAProfile(p Profile) bool {
	return p == ProfileRootCA
}

type CreateResult struct {
	Cert      *x509.Certificate
	CertDER   []byte
	Signer    crypto.Signer
	SerialHex string
}

func CreateCA(cfg *CreateConfig) (*CreateResult, error) {
	var signer crypto.Signer
	var err error
	if cfg.ReuseKey != nil {
		signer = cfg.ReuseKey
	} else {
		signer, err = GenerateKey(cfg.KeyType)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}

	now := time.Now()
	country := cfg.DefaultCountry
	if country == "" {
		country = "CN"
	}
	org := cfg.DefaultOrg
	if org == "" {
		org = "example.com"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   subjectName(cfg),
			Country:      []string{country},
			Organization: []string{org},
		},
		NotBefore:      now,
		NotAfter:       now.Add(cfg.Validity),
		SubjectKeyId:   []byte{},
		AuthorityKeyId: []byte{},
	}

	switch cfg.Profile {
	case ProfileRootCA:
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		if cfg.MaxPathLen > 0 {
			tmpl.MaxPathLen = cfg.MaxPathLen
		}
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case ProfilePolicyCA:
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		// M6 fix: encode pathlen=0 (MaxPathLenZero only honored when MaxPathLen==0).
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case ProfileSubCA:
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		// M6 fix: encode pathlen=0 (sub-CA cannot issue further CAs).
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		applyNameConstraints(tmpl, &NameConstraints{
			PermittedDomains:  cfg.PermittedDomains,
			ExcludedDomains:   cfg.ExcludedDomains,
			PermittedEmails:   cfg.PermittedEmails,
			ExcludedEmails:    cfg.ExcludedEmails,
			PermittedURIs:     cfg.PermittedURIs,
			ExcludedURIs:      cfg.ExcludedURIs,
			PermittedIPRanges: cfg.PermittedIPRanges,
			ExcludedIPRanges:  cfg.ExcludedIPRanges,
		})
	default:
		return nil, fmt.Errorf("unsupported CA profile: %s", cfg.Profile)
	}

	// Add AIA (OCSP + Issuer URL) and CRLDP to all CA profiles
	if cfg.OCSPURL != "" || cfg.IssuerURL != "" {
		addAIA(tmpl, cfg.OCSPURL, cfg.IssuerURL)
	}
	if cfg.Parent != nil && cfg.CRLBaseURL != "" {
		addCRLDP(tmpl, cfg.CRLBaseURL, cfg.Parent.Subject.CommonName, 0, nil)
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(signer.Public())
	ski := sha256hash(pubBytes)[:20]
	tmpl.SubjectKeyId = ski

	var signingCert *x509.Certificate
	var signingKey crypto.Signer

	if cfg.Parent != nil {
		signingCert = cfg.Parent
		signingKey = cfg.ParentKey
		caPubBytes, _ := x509.MarshalPKIXPublicKey(cfg.Parent.PublicKey)
		tmpl.AuthorityKeyId = sha256hash(caPubBytes)[:20]
	} else {
		signingCert = tmpl
		signingKey = signer
		tmpl.AuthorityKeyId = ski
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, signingCert, signer.Public(), signingKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}

	record := &db.CAMeta{
		Name:         cfg.Name,
		CertDER:      certDER,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		KeyAlgorithm: cfg.KeyType,
		Fingerprint:  db.Fingerprint(certDER),
	}
	if err := cfg.DB.InsertCAMeta(record); err != nil {
		return nil, fmt.Errorf("insert ca_meta: %w", err)
	}

	return &CreateResult{
		Cert:      cert,
		CertDER:   certDER,
		Signer:    signer,
		SerialHex: fmt.Sprintf("%040X", serial),
	}, nil
}

func subjectName(cfg *CreateConfig) string {
	if cfg.SubjectName != "" {
		return cfg.SubjectName
	}
	return cfg.Name
}

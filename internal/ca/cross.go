package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/varwof/engine/db"
)

func CrossSign(d *db.DB, issuerCert *x509.Certificate, issuerKey crypto.Signer, issuerName string, targetCAMeta *db.CAMeta, validity time.Duration, nc *NameConstraints) (*SignResult, error) {
	targetCert, err := x509.ParseCertificate(targetCAMeta.CertDER)
	if err != nil {
		return nil, fmt.Errorf("parse target CA cert: %w", err)
	}

	for attempt := 0; attempt < 10; attempt++ {
		serial, err := randomSerial()
		if err != nil {
			return nil, fmt.Errorf("random serial: %w", err)
		}
		serialHex := fmt.Sprintf("%040X", serial)

		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      targetCert.Subject,
			NotBefore:    now,
			NotAfter:     now.Add(validity),
			SubjectKeyId: targetCert.SubjectKeyId,
		}

		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

		if nc != nil {
			applyNameConstraints(tmpl, nc)
		}

		caPubBytes, err := x509.MarshalPKIXPublicKey(issuerCert.PublicKey)
		if err == nil {
			tmpl.AuthorityKeyId = sha256hash(caPubBytes)[:20]
		}

		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, targetCert.PublicKey, issuerKey)
		if err != nil {
			return nil, fmt.Errorf("create cross certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parse cross cert: %w", err)
		}

		record := &db.CrossCertRecord{
			IssuerCA:     issuerName,
			SubjectCA:    targetCAMeta.Name,
			CertDER:      certDER,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SerialNumber: serialHex,
			Fingerprint:  db.Fingerprint(certDER),
			Status:       "V",
		}
		if err := d.InsertCrossCert(record); err != nil {
			return nil, fmt.Errorf("insert cross cert to db: %w", err)
		}

		return &SignResult{
			Cert:      cert,
			CertDER:   certDER,
			SerialHex: serialHex,
		}, nil
	}

	return nil, fmt.Errorf("failed to generate unique serial after 10 attempts")
}

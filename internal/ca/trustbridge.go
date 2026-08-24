package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/varwof/engine/db"
)

type TrustBridgePolicy struct {
	Enabled    bool   `json:"enabled"`
	IssuerCA   string `json:"issuer_ca"`
	SubjectCA  string `json:"subject_ca"`
	Validity   int    `json:"validity_days"`
	NameConstraints []string `json:"name_constraints,omitempty"`
}

type TrustBridgeConfig struct {
	Bridges []TrustBridgePolicy `json:"bridges,omitempty"`
}

func EstablishTrustBridge(database *db.DB, issuerCert *x509.Certificate, issuerKey crypto.Signer, issuerName string, subjectMeta *db.CAMeta, validity time.Duration) (*db.CrossCertRecord, error) {
	signResult, err := CrossSign(database, issuerCert, issuerKey, issuerName, subjectMeta, validity, nil)
	if err != nil {
		return nil, fmt.Errorf("trust bridge cross-sign: %w", err)
	}

	record, err := database.GetCrossCert(issuerName, signResult.SerialHex)
	if err != nil {
		// Construct record manually
		record = &db.CrossCertRecord{
			IssuerCA:     issuerName,
			SubjectCA:    subjectMeta.Name,
			CertDER:      signResult.CertDER,
			SerialNumber: signResult.SerialHex,
			Fingerprint:  db.Fingerprint(signResult.CertDER),
			Status:       "V",
			NotBefore:    signResult.Cert.NotBefore,
			NotAfter:     signResult.Cert.NotAfter,
		}
	}

	slog.Info("trust bridge established",
		"issuer", issuerName,
		"subject", subjectMeta.Name,
		"serial", signResult.SerialHex)
	return record, nil
}

func BridgeTrustPEMs(database *db.DB, bridges []TrustBridgePolicy, caCfgs map[string]struct {
	Cert string
	Key  string
}) ([]*db.CrossCertRecord, error) {
	var results []*db.CrossCertRecord
	for _, b := range bridges {
		if !b.Enabled {
			continue
		}
		cfg, ok := caCfgs[b.IssuerCA]
		if !ok {
			slog.Warn("trust bridge: issuer CA not configured", "issuer", b.IssuerCA)
			continue
		}
		issuerCert, issuerKey, err := LoadSigner(cfg.Cert, cfg.Key)
		if err != nil {
			slog.Warn("trust bridge: load issuer", "issuer", b.IssuerCA, "error", err)
			continue
		}
		subjectMeta, err := database.GetCAMeta(b.SubjectCA)
		if err != nil {
			slog.Warn("trust bridge: subject CA not found in DB", "subject", b.SubjectCA, "error", err)
			continue
		}
		validity := time.Duration(b.Validity) * 24 * time.Hour
		if b.Validity <= 0 {
			validity = 3650 * 24 * time.Hour
		}
		record, err := EstablishTrustBridge(database, issuerCert, issuerKey, b.IssuerCA, subjectMeta, validity)
		if err != nil {
			slog.Error("trust bridge: establish failed", "issuer", b.IssuerCA, "subject", b.SubjectCA, "error", err)
			continue
		}
		results = append(results, record)
	}
	return results, nil
}

func BuildFederatedTrustPool(database *db.DB, localCAs map[string]*x509.Certificate, crossCerts []*db.CrossCertRecord) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, cert := range localCAs {
		pool.AddCert(cert)
	}
	for _, cc := range crossCerts {
		if cc.Status != "V" {
			continue
		}
		cert, err := x509.ParseCertificate(cc.CertDER)
		if err != nil {
			slog.Warn("trust bridge: parse cross cert", "issuer", cc.IssuerCA, "error", err)
			continue
		}
		pool.AddCert(cert)
	}
	anchors, err := database.ListTrustAnchors(&db.TrustAnchorFilter{})
	if err != nil {
		return pool, nil // return partial pool
	}
	for _, a := range anchors {
		if !a.Trusted {
			continue
		}
		cert, err := x509.ParseCertificate(a.CertDER)
		if err == nil {
			pool.AddCert(cert)
		}
	}
	return pool, nil
}

func TrustAnchorFederate(database *db.DB, remoteURL string) (int, error) {
	pemData, err := FetchCACertBundle(remoteURL)
	if err != nil {
		return 0, fmt.Errorf("fetch remote trust anchors: %w", err)
	}
	result, err := ImportTrustBundle(database, pemData, remoteURL)
	if err != nil {
		return 0, fmt.Errorf("import remote trust anchors: %w", err)
	}
	return result.Imported, nil
}

func ExportFederatedTrust(database *db.DB, source string) ([]byte, error) {
	anchors, err := database.ListTrustAnchors(&db.TrustAnchorFilter{Source: source})
	if err != nil {
		return nil, fmt.Errorf("list anchors by source: %w", err)
	}
	var pemData []byte
	for _, a := range anchors {
		if !a.Trusted {
			continue
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: a.CertDER}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	return pemData, nil
}

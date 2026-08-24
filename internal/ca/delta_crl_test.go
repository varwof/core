// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func newTestCertRecord(serial string) *db.CertRecord {
	return &db.CertRecord{
		SerialNumber: serial,
		CAName:       "Test CA",
		Status:       "V",
		Subject:      fmt.Sprintf("CN=test%s", serial),
		CommonName:   fmt.Sprintf("test%s", serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		CertDER:      []byte("der"),
		Fingerprint:  fmt.Sprintf("fp-%s", serial),
	}
}

func TestGenerateDeltaCRL(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	for _, s := range []string{"1", "2", "3"} {
		if err := d.InsertCert(newTestCertRecord(s)); err != nil {
			t.Fatal(err)
		}
	}

	// Base CRL: revoke cert 1, then capture the base thisUpdate window.
	if err := d.RevokeCert("Test CA", "1", 0); err != nil {
		t.Fatal(err)
	}
	baseCfg := &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30}
	baseCRL, err := GenerateCRL(baseCfg)
	if err != nil {
		t.Fatal(err)
	}
	base, err := x509.ParseRevocationList(baseCRL)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.RevokedCertificateEntries) != 1 {
		t.Fatalf("base CRL: expected 1 revoked, got %d", len(base.RevokedCertificateEntries))
	}

	// Delta window: everything since (just before) the base CRL thisUpdate.
	since := base.ThisUpdate.Add(-2 * time.Second)

	// Revoke cert 2 after the base CRL was built.
	if err := d.RevokeCert("Test CA", "2", 1); err != nil {
		t.Fatal(err)
	}

	dcfg := &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30}
	baseNum := big.NewInt(7) // arbitrary base cRLNumber to assert the extension
	deltaCRL, err := GenerateDeltaCRL(dcfg, &DeltaCRLConfig{
		Since:         since,
		BaseCRLNumber: baseNum,
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := x509.ParseRevocationList(deltaCRL)
	if err != nil {
		t.Fatalf("parse delta CRL: %v", err)
	}

	// The delta covers both cert 1 (revoked before base CRL but within the
	// since window) and cert 2 (revoked after the base CRL).
	if len(delta.RevokedCertificateEntries) != 2 {
		t.Fatalf("delta CRL: expected 2 revoked, got %d", len(delta.RevokedCertificateEntries))
	}

	// Delta CRL Indicator (2.5.29.27) must be critical.
	var hasIndicator, hasBase bool
	for _, ext := range delta.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) {
			hasIndicator = true
			if !ext.Critical {
				t.Fatal("Delta CRL Indicator must be critical")
			}
		}
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			hasBase = true
			var num int
			if _, err := asn1.Unmarshal(ext.Value, &num); err != nil {
				t.Fatalf("unmarshal base CRL number: %v", err)
			}
			if big.NewInt(int64(num)).Cmp(baseNum) != 0 {
				t.Fatalf("base CRL number: expected %s, got %d", baseNum, num)
			}
		}
	}
	if !hasIndicator {
		t.Fatal("missing Delta CRL Indicator extension")
	}
	if !hasBase {
		t.Fatal("missing Base CRL Number extension")
	}
}

func TestGenerateDeltaCRLMissingSince(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	cfg := &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30}
	if _, err := GenerateDeltaCRL(cfg, nil); err == nil {
		t.Fatal("expected error for nil delta config")
	}
	if _, err := GenerateDeltaCRL(cfg, &DeltaCRLConfig{}); err == nil {
		t.Fatal("expected error for zero since")
	}
}

func TestGenerateDeltaCRLEmptyDelta(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	for _, s := range []string{"1", "2"} {
		if err := d.InsertCert(newTestCertRecord(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RevokeCert("Test CA", "1", 0); err != nil {
		t.Fatal(err)
	}
	baseCfg := &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30}
	baseCRL, err := GenerateCRL(baseCfg)
	if err != nil {
		t.Fatal(err)
	}
	base, err := x509.ParseRevocationList(baseCRL)
	if err != nil {
		t.Fatal(err)
	}

	// No new revocations after the base CRL → empty delta. The since boundary
	// sits strictly after cert 1's revocation (second precision) so it is
	// excluded; nothing else was revoked.
	deltaCRL, err := GenerateDeltaCRL(baseCfg, &DeltaCRLConfig{
		Since:         base.ThisUpdate.Add(2 * time.Second),
		BaseCRLNumber: base.Number,
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := x509.ParseRevocationList(deltaCRL)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.RevokedCertificateEntries) != 0 {
		t.Fatalf("expected empty delta, got %d", len(delta.RevokedCertificateEntries))
	}
}

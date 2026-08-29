// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func revokedCRLCfg(t *testing.T, d *db.DB) *CRLConfig {
	t.Helper()
	caCert, caKey := newTestCA(t)
	for _, serial := range []string{"1", "2", "3"} {
		if err := d.InsertCert(&db.CertRecord{
			SerialNumber: serial, CAName: "Test CA", Status: "V",
			Subject: fmt.Sprintf("CN=rr%s", serial), CommonName: fmt.Sprintf("rr%s", serial),
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
			CertDER: []byte("der"), Fingerprint: fmt.Sprintf("fp%s", serial),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, serial := range []string{"1", "2"} {
		if err := d.RevokeCert("Test CA", serial, 1); err != nil {
			t.Fatal(err)
		}
	}
	return &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30, TotalPartitions: 2}
}

func TestGenerateDeltaCRLSinceSource(t *testing.T) {
	d := newTestDB(t)
	cfg := revokedCRLCfg(t, d)
	if _, err := GenerateCRL(cfg); err != nil {
		t.Fatalf("seed crl: %v", err)
	}
	since := time.Now().Add(-5 * time.Minute)
	crlDER, err := GenerateDeltaCRL(cfg, &DeltaCRLConfig{Since: since, BaseCRLNumber: big.NewInt(1)})
	if err != nil {
		t.Fatalf("delta crl: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("empty delta CRL")
	}
}

func TestGenerateCRLPartitionFilter(t *testing.T) {
	d := newTestDB(t)
	cfg := revokedCRLCfg(t, d)
	cfg.Partition = 0
	crlDER, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatalf("partitioned crl: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("empty partitioned CRL")
	}

	d2 := newTestDB(t)
	cfg2 := revokedCRLCfg(t, d2)
	cfg2.Partition = 7
	crlAll, err := GenerateCRL(cfg2)
	if err != nil {
		t.Fatalf("partition fallback crl: %v", err)
	}
	if len(crlAll) == 0 {
		t.Fatal("empty CRL")
	}
}

func TestGenerateCRLRealtimeRevoked(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)
	d.InsertCert(&db.CertRecord{
		SerialNumber: "9", CAName: "Test CA", Status: "V", Subject: "CN=rr9",
		CommonName: "rr9", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		CertDER: []byte("der"), Fingerprint: "fp9",
	})
	d.RevokeCert("Test CA", "9", 0)
	cfg := &CRLConfig{DB: d, CACert: caCert, CAKey: caKey, ValidityDays: 30}
	crlDER, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatalf("realtime-revoked crl: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("empty CRL")
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func TestGenerateCRL(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	for i := 1; i <= 3; i++ {
		serial := fmt.Sprintf("%X", i)
		d.InsertCert(&db.CertRecord{
			SerialNumber: serial,
			CAName:       "Test CA",
			Status:       "V",
			Subject:      fmt.Sprintf("CN=test%d", i),
			CommonName:   fmt.Sprintf("test%d", i),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			CertDER:      []byte("der"),
			Fingerprint:  fmt.Sprintf("fp%d", i),
		})
	}

	d.RevokeCert("Test CA", "1", 0)
	d.RevokeCert("Test CA", "3", 1)

	cfg := &CRLConfig{
		DB:           d,
		CACert:       caCert,
		CAKey:        caKey,
		ValidityDays: 30,
	}

	crlDER, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(crlDER) == 0 {
		t.Fatal("empty CRL")
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("expected 2 revoked, got %d", len(crl.RevokedCertificateEntries))
	}
}

func TestGenerateCRLNumberStorePersists(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	cfg := &CRLConfig{
		DB:           d,
		CACert:       caCert,
		CAKey:        caKey,
		CAName:       "Test CA",
		ValidityDays: 30,
		NumberStore:  d,
	}

	// First generation persists number 1.
	if _, err := GenerateCRL(cfg); err != nil {
		t.Fatal(err)
	}
	n, err := d.GetLastCRLNumber("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected persisted CRL number >= 1, got %d", n)
	}

	// Re-seed the in-memory counter from the store and confirm the next CRL
	// number is strictly greater (RFC 5280 §5.2.4 monotonicity).
	SeedCRLNumber(n)
	crlDER, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if crl.Number.Int64() <= n {
		t.Fatalf("expected monotonic CRL number > %d, got %d", n, crl.Number.Int64())
	}
	persisted, _ := d.GetLastCRLNumber("Test CA")
	if persisted != crl.Number.Int64() {
		t.Fatalf("persisted number %d != generated %d", persisted, crl.Number.Int64())
	}
}

func TestGenerateCRLEmpty(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	cfg := &CRLConfig{
		DB:           d,
		CACert:       caCert,
		CAKey:        caKey,
		ValidityDays: 30,
	}

	crlDER, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("expected 0 revoked, got %d", len(crl.RevokedCertificateEntries))
	}
}

func TestCRLFilename(t *testing.T) {
	tests := []struct {
		caName    string
		partition int
		total     int
		want      string
	}{
		{"myCA", 0, 0, "myca.crl"},
		{"myCA", 0, 1, "myca.crl"},
		{"myCA", 0, 3, "myca-p0-of3.crl"},
		{"myCA", 1, 3, "myca-p1-of3.crl"},
		{"myCA", 2, 3, "myca-p2-of3.crl"},
		{"Varwof Issuing CA", 0, 1, "varwof-issuing-ca.crl"},
		{"Varwof Root CA", 0, 1, "varwof-root-ca.crl"},
		{"Varwof TSA CA", 0, 1, "varwof-tsa-ca.crl"},
	}
	for _, tt := range tests {
		got := CRLFilename(tt.caName, tt.partition, tt.total)
		if got != tt.want {
			t.Errorf("CRLFilename(%q, %d, %d) = %q, want %q", tt.caName, tt.partition, tt.total, got, tt.want)
		}
	}
}

func TestPartitionOfSerial(t *testing.T) {
	// total <= 1 → returns 0
	if got := partitionOfSerial("2A", 0); got != 0 {
		t.Errorf("partitionOfSerial(_, 0) = %d, want 0", got)
	}
	if got := partitionOfSerial("2A", 1); got != 0 {
		t.Errorf("partitionOfSerial(_, 1) = %d, want 0", got)
	}

	// deterministic: same serial + total always returns same partition
	p1 := partitionOfSerial("2A", 10)
	p2 := partitionOfSerial("2A", 10)
	if p1 != p2 {
		t.Errorf("not deterministic: %d vs %d", p1, p2)
	}

	// result is always in [0, total)
	for _, serial := range []string{"0", "1", "2A", "FF", "100"} {
		p := partitionOfSerial(serial, 10)
		if p < 0 || p >= 10 {
			t.Errorf("partitionOfSerial(%q, 10) = %d, out of range [0, 10)", serial, p)
		}
	}

	// different serials may distribute to different partitions
	parts := make(map[int]bool)
	for _, s := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"} {
		parts[partitionOfSerial(s, 10)] = true
	}
	if len(parts) < 2 {
		t.Log("warning: all tested serials map to the same partition (unlikely but not incorrect)")
	}
}

// L16: CRL numbers must be monotonic per CA, independent of other CAs sharing
// the process. Previously a single global counter linked CAs, so generating a
// CRL for one CA advanced the number seen by another (contention), violating
// per-CA RFC 5280 §5.2.4 monotonicity semantics.
func TestGenerateCRLPerCANumberIndependentL16(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	genNum := func(name string) int64 {
		crlDER, err := GenerateCRL(&CRLConfig{
			DB:           d,
			CACert:       caCert,
			CAKey:        caKey,
			CAName:       name,
			ValidityDays: 30,
		})
		if err != nil {
			t.Fatal(err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatal(err)
		}
		return crl.Number.Int64()
	}

	a1 := genNum("CA-A") // CA-A first
	_ = genNum("CA-B")   // CA-B interleaves
	a2 := genNum("CA-A") // CA-A again

	if a2 <= a1 {
		t.Fatalf("CA-A CRL number not monotonic: %d then %d", a1, a2)
	}
	if a2 != a1+1 {
		t.Fatalf("CA-A CRL number advanced unexpectedly across CA-B interleave: %d -> %d (want %d); a shared global counter would consume the CA-B increment",
			a1, a2, a1+1)
	}
}

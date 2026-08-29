// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func viewTestCert(t *testing.T, serial *big.Int) (*x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: "view.example.com", Organization: []string{"ACME"}, Country: []string{"US"}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		IsCA:            true,
		MaxPathLen:      1,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:        []string{"view.example.com", "alt.example.com"},
		IPAddresses:     []net.IP{net.ParseIP("192.0.2.1")},
		EmailAddresses:  []string{"ops@example.com"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9}, Value: []byte{0x1}}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func insertViewRecord(t *testing.T, d *db.DB, serial string, certDER []byte, status string, notAfter time.Time) {
	t.Helper()
	rv := int(3)
	revokedAt := time.Now().Add(-time.Hour)
	inv := time.Now().Add(-2 * time.Hour)
	rec := &db.CertRecord{
		SerialNumber:   serial,
		CAName:         "test-ca",
		Status:         status,
		Subject:        "CN=view.example.com",
		CommonName:     "view.example.com",
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       notAfter,
		CertDER:        certDER,
		Fingerprint:    "fp1",
		SPKIHash:       "spki1",
		SubjectO:       "ACME",
		SubjectC:       "US",
		IssuerDN:       "CN=test-ca",
		KeyAlgo:        "ECDSA",
		KeySize:        256,
		SigAlgo:        "ECDSA-SHA256",
		SKI:            "ski1",
		AKI:            "aki1",
		SAN:            "view.example.com",
		Profile:        "tls-server",
		PrincipalUid:   "uid1",
		AgentId:        "agent1",
		RevokedAt:      &revokedAt,
		RevokeReason:   &rv,
		InvalidityDate: &inv,
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
}

func TestCmdViewCert(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cert, der := viewTestCert(t, big.NewInt(0x1001))
	insertViewRecord(t, d, "010001", der, "V", time.Now().Add(-time.Hour))

	cfg := &internal.Config{DB: dbPath}

	if err := cmdViewCert(cfg, []string{"-ca", "test-ca", "-serial", "010001", "-format", "table"}); err != nil {
		t.Fatalf("table view: %v", err)
	}
	if err := cmdViewCert(cfg, []string{"-ca", "test-ca", "-serial", "010001", "-format", "json"}); err != nil {
		t.Fatalf("json view: %v", err)
	}

	if err := cmdViewCert(cfg, []string{"-ca", "test-ca"}); err == nil {
		t.Fatal("missing serial must error")
	}
	if err := cmdViewCert(cfg, []string{"-ca", "missing", "-serial", "010001"}); err == nil {
		t.Fatal("missing cert must error")
	}

	// Issuer cert leg (not referenced by --serial is fine; parse the tv cert
	// directly through viewCertJSON to cover the CertVersion/ExtensionCount set.
	if err := viewCertJSON(&db.CertRecord{
		SerialNumber: "010001", CAName: "test-ca", Status: "V",
		CertDER: der, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}, cert); err != nil {
		t.Fatalf("viewCertJSON: %v", err)
	}
}

func TestViewCertTableExpired(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	_, der := viewTestCert(t, big.NewInt(0x1002))
	insertViewRecord(t, d, "010002", der, "V", time.Now().Add(-time.Hour))

	cfg := &internal.Config{DB: dbPath}
	if err := cmdViewCert(cfg, []string{"-ca", "test-ca", "-serial", "010002"}); err != nil {
		t.Fatalf("expired table view: %v", err)
	}
}

func TestViewFormatHelpers(t *testing.T) {
	if got := formatKeyUsage(0); got != "none" {
		t.Fatalf("zero key usage: %q", got)
	}
	got := formatKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
	if !strings.Contains(got, "DigitalSignature") || !strings.Contains(got, "KeyEncipherment") {
		t.Fatalf("combined key usage: %q", got)
	}
	unknown := formatKeyUsage(x509.KeyUsage(1 << 12))
	if !strings.HasPrefix(unknown, "0x") {
		t.Fatalf("unknown key usage bit: %q", unknown)
	}

	eku := formatExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel,
		x509.ExtKeyUsageIPSECUser,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsage(999),
	})
	want := []string{"ServerAuth", "CodeSigning", "IPSECEndSystem", "IPSECTunnel", "IPSECUser",
		"TimeStamping", "OCSPSigning", "MicrosoftServerGatedCrypto", "MicrosoftCommercialCodeSigning",
		"Any", "MicrosoftKernelCodeSigning", "EmailProtection", "ClientAuth", "Unknown(999)"}
	for i, w := range want {
		if i >= len(eku) || eku[i] != w {
			t.Fatalf("ext key usage[%d]=%q want %q (all=%v)", i, eku[i], w, eku)
		}
	}

	if got := formatOIDs(nil); got != "none" {
		t.Fatalf("empty oids: %q", got)
	}
	if got := formatOIDs([]asn1.ObjectIdentifier{{1, 2, 3, 4}}); got != "1.2.3.4" {
		t.Fatalf("oids: %q", got)
	}

	if got := joinStrs([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("joinStrs: %q", got)
	}
	if got := joinIPs([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.2")}); got != "192.0.2.1, 198.51.100.2" {
		t.Fatalf("joinIPs: %q", got)
	}
}

// Silence unused import warning for os in older go versions when file build tags vary.
var _ = os.Getenv

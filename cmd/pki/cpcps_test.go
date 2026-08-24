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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

// seedCPCPSDB creates a temp DB with one root CA and one subordinate CA,
// both with valid DER certs in ca_meta and a couple of issued cert records.
func seedCPCPSDB(t *testing.T) (cfg *internal.Config, dir string) {
	t.Helper()
	dir = t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	// Root CA (self-signed).
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Test Root CA", Organization: []string{"Test Org"}, Country: []string{"CN"}},
		Issuer:                pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		OCSPServer:            []string{"http://ocsp.test/root"},
		CRLDistributionPoints: []string{"http://crl.test/root.crl"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCAMeta(&db.CAMeta{
		Name:         "Test Root CA",
		CertDER:      rootDER,
		Subject:      rootCert.Subject.String(),
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,
		KeyAlgorithm: "ECDSA",
		Fingerprint:  "root-fp",
	}); err != nil {
		t.Fatal(err)
	}

	// Subordinate CA signed by root.
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "Test Sub CA", Organization: []string{"Sub Org"}},
		Issuer:                rootCert.Subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		OCSPServer:            []string{"http://ocsp.test/sub"},
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, rootCert, &subKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	subCert, err := x509.ParseCertificate(subDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCAMeta(&db.CAMeta{
		Name:         "Test Sub CA",
		CertDER:      subDER,
		Subject:      subCert.Subject.String(),
		NotBefore:    subCert.NotBefore,
		NotAfter:     subCert.NotAfter,
		KeyAlgorithm: "ECDSA",
		Fingerprint:  "sub-fp",
	}); err != nil {
		t.Fatal(err)
	}

	return &internal.Config{
		DB: dbPath,
		Defaults: internal.DefaultsConfig{
			PolicyOIDs: []string{"1.2.3.4"},
		},
	}, dir
}

func TestCmdCPCPS(t *testing.T) {
	cfg, dir := seedCPCPSDB(t)

	t.Run("md single CA", func(t *testing.T) {
		out := filepath.Join(dir, "cps.md")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--out", out}); err != nil {
			t.Fatalf("cpcps: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil || len(data) == 0 {
			t.Fatalf("expected non-empty md, err=%v", err)
		}
		for _, want := range []string{
			"Certification Practice Statement", "Test Root CA", "Root CA",
			"RFC 3647", "Key algorithm", "Certificate policies",
			"OCSP responder", "CRL distribution", "Issued certificates",
		} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("md missing %q", want)
			}
		}
	})

	t.Run("md sub CA role", func(t *testing.T) {
		out := filepath.Join(dir, "sub.md")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Sub CA", "--out", out}); err != nil {
			t.Fatalf("cpcps sub: %v", err)
		}
		data, _ := os.ReadFile(out)
		if !strings.Contains(string(data), "Subordinate CA") {
			t.Fatal("sub CA should be marked Subordinate CA")
		}
	})

	t.Run("pdf", func(t *testing.T) {
		out := filepath.Join(dir, "cps.pdf")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--format", "pdf", "--out", out}); err != nil {
			t.Fatalf("cpcps pdf: %v", err)
		}
		if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
			t.Fatalf("expected non-empty pdf, err=%v", err)
		}
	})

	t.Run("all CAs", func(t *testing.T) {
		out := filepath.Join(dir, "all.md")
		if err := cmdCPCPS(cfg, []string{"--out", out}); err != nil {
			t.Fatalf("cpcps all: %v", err)
		}
		data, _ := os.ReadFile(out)
		for _, want := range []string{"Test Root CA", "Test Sub CA"} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("all-CA output missing %q", want)
			}
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		if err := cmdCPCPS(cfg, []string{"--format", "bogus"}); err == nil {
			t.Fatal("expected unknown format error")
		}
	})

	t.Run("missing CA", func(t *testing.T) {
		if err := cmdCPCPS(cfg, []string{"--ca", "Nope", "--out", filepath.Join(dir, "x.md")}); err == nil {
			t.Fatal("expected CA not found error")
		}
	})

	t.Run("empty db", func(t *testing.T) {
		empty := &internal.Config{DB: filepath.Join(dir, "empty.db")}
		if err := cmdCPCPS(empty, []string{"--out", filepath.Join(dir, "empty.md")}); err == nil {
			t.Fatal("expected no CA error for empty DB")
		}
	})

	t.Run("default out path", func(t *testing.T) {
		sub := filepath.Join(dir, "def")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := os.Getwd()
		if err := os.Chdir(sub); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(old)
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA"}); err != nil {
			t.Fatalf("cpcps default out: %v", err)
		}
		matches, _ := filepath.Glob(filepath.Join(sub, "cpcps-*.md"))
		if len(matches) == 0 {
			t.Fatal("expected default cpcps-*.md output")
		}
	})

	t.Run("overrides", func(t *testing.T) {
		out := filepath.Join(dir, "ov.md")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--out", out,
			"--org", "ACME Corp", "--policy-oids", "1.2.3.4.5, 2.16.840.1.101.3.2.1",
			"--version", "2.0"}); err != nil {
			t.Fatalf("overrides: %v", err)
		}
		data, _ := os.ReadFile(out)
		for _, want := range []string{"ACME Corp", "1.2.3.4.5", "2.16.840.1.101.3.2.1", "2.0"} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("override output missing %q", want)
			}
		}
	})

	t.Run("version history", func(t *testing.T) {
		out := filepath.Join(dir, "hist.md")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--out", out,
			"--history", "1.0=2026-01-01=initial;1.1=2026-03-01=updated OCSP endpoint",
			"--version", "1.2"}); err != nil {
			t.Fatalf("history: %v", err)
		}
		data, _ := os.ReadFile(out)
		for _, want := range []string{
			"Version History", "| 1.0 | 2026-01-01 | initial |",
			"| 1.1 | 2026-03-01 | updated OCSP endpoint |", "1.2",
		} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("history output missing %q", want)
			}
		}
	})

	t.Run("out-dir publication", func(t *testing.T) {
		pub := filepath.Join(dir, "pub")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--out-dir", pub, "--version", "3.0"}); err != nil {
			t.Fatalf("out-dir: %v", err)
		}
		latest := filepath.Join(pub, "test-root-ca-cps.md")
		snap := filepath.Join(pub, "test-root-ca-cps-v3.0.md")
		for _, p := range []string{latest, snap} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			if !strings.Contains(string(data), "3.0") {
				t.Fatalf("%s missing version", p)
			}
		}
	})

	t.Run("separate CP", func(t *testing.T) {
		out := filepath.Join(dir, "sep.md")
		if err := cmdCPCPS(cfg, []string{"--ca", "Test Root CA", "--out", out, "--separate", "--version", "4.0"}); err != nil {
			t.Fatalf("separate: %v", err)
		}
		cpOut := filepath.Join(dir, "sep-cp.md")
		cpData, err := os.ReadFile(cpOut)
		if err != nil {
			t.Fatalf("read cp: %v", err)
		}
		if !strings.Contains(string(cpData), "Certificate Policy") {
			t.Fatal("CP doc should be titled Certificate Policy")
		}
		if strings.Contains(string(cpData), "Certification Practice Statement —") {
			t.Fatal("CP doc should not reuse the CPS title")
		}
		// CPS stays intact.
		cpsData, _ := os.ReadFile(out)
		if !strings.Contains(string(cpsData), "Certification Practice Statement") {
			t.Fatal("CPS doc missing title")
		}
	})
}

func TestCPCPSHelpers(t *testing.T) {
	t.Run("orDefault", func(t *testing.T) {
		if got := orDefault("", "d"); got != "d" {
			t.Fatalf("orDefault empty: %q", got)
		}
		if got := orDefault("v", "d"); got != "v" {
			t.Fatalf("orDefault non-empty: %q", got)
		}
	})

	t.Run("parseVersionHistory", func(t *testing.T) {
		entries := parseVersionHistory("1.0=2026-01-01=initial;1.1=2026-03-01=updated OCSP;bad-entry;=no-version=skip")
		if len(entries) != 2 {
			t.Fatalf("expected 2 valid entries, got %d: %+v", len(entries), entries)
		}
		if entries[0].Version != "1.0" || entries[0].Date != "2026-01-01" || entries[0].Change != "initial" {
			t.Fatalf("entry[0] = %+v", entries[0])
		}
		if entries[1].Version != "1.1" || entries[1].Change != "updated OCSP" {
			t.Fatalf("entry[1] = %+v", entries[1])
		}
		if got := parseVersionHistory(""); len(got) != 0 {
			t.Fatalf("empty history: %+v", got)
		}
	})

	t.Run("loadCAInfo PEM cert", func(t *testing.T) {
		cfg, _ := seedCPCPSDB(t)
		d, err := db.Open(cfg.DB)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		info, err := loadCAInfo(d.RawDB(), "Test Root CA", cfg, "", "")
		if err != nil {
			t.Fatalf("loadCAInfo: %v", err)
		}
		if !info.IsRoot {
			t.Fatal("root CA should be IsRoot")
		}
		if info.CommonName != "Test Root CA" {
			t.Fatalf("CN = %q", info.CommonName)
		}
		if info.Organization != "Test Org" {
			t.Fatalf("org = %q", info.Organization)
		}
		if info.Country != "CN" {
			t.Fatalf("country = %q", info.Country)
		}
		if info.OCSPURL != "http://ocsp.test/root" {
			t.Fatalf("OCSP from cert AIA = %q", info.OCSPURL)
		}
		if info.CRLURL != "http://crl.test/root.crl" {
			t.Fatalf("CRL from cert = %q", info.CRLURL)
		}
		if len(info.PolicyOIDs) != 1 || info.PolicyOIDs[0] != "1.2.3.4" {
			t.Fatalf("policy oids from cert = %v", info.PolicyOIDs)
		}
	})

	t.Run("loadCAInfo missing CA", func(t *testing.T) {
		cfg, _ := seedCPCPSDB(t)
		d, err := db.Open(cfg.DB)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if _, err := loadCAInfo(d.RawDB(), "Nope", cfg, "", ""); err == nil {
			t.Fatal("expected not found error")
		}
	})

	t.Run("org/policy from config", func(t *testing.T) {
		cfg, _ := seedCPCPSDB(t)
		cfg.Defaults.DefaultOrg = "Cfg Org"
		cfg.Defaults.DefaultCountry = "US"
		cfg.Defaults.PolicyOIDs = []string{"1.9.9.9"}
		cfg.Defaults.OCSPURL = "http://ocsp.cfg/"
		cfg.CRL.CRLBaseURL = "http://crl.cfg/"
		d, err := db.Open(cfg.DB)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		info, err := loadCAInfo(d.RawDB(), "Test Sub CA", cfg, "", "")
		if err != nil {
			t.Fatalf("loadCAInfo: %v", err)
		}
		if info.Organization != "Sub Org" {
			t.Fatalf("org should keep cert value, got %q", info.Organization)
		}
		if info.Country != "US" {
			t.Fatalf("country from config = %q", info.Country)
		}
		if len(info.PolicyOIDs) != 1 || info.PolicyOIDs[0] != "1.9.9.9" {
			t.Fatalf("policy oids from config = %v", info.PolicyOIDs)
		}
		if info.OCSPURL != "http://ocsp.cfg/" {
			t.Fatalf("ocsp from config = %q", info.OCSPURL)
		}
		if !strings.Contains(info.CRLURL, "test-sub-ca.crl") {
			t.Fatalf("crl from config base = %q", info.CRLURL)
		}
	})
}

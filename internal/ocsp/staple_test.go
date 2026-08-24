// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ocsp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/varwof/engine/db"
)

func stapleTestEnv(t *testing.T) (*db.DB, *x509.Certificate, crypto.Signer, *x509.Certificate, crypto.Signer) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)
	return database, caCert, caKey, ocspCert, ocspKey
}

func makeLeaf(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, serial int64, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		OCSPServer:   []string{"http://ocsp.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &eeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func insertLeaf(t *testing.T, d *db.DB, leaf *x509.Certificate, serialStr string) {
	t.Helper()
	if err := d.InsertCert(&db.CertRecord{
		SerialNumber: serialStr,
		CAName:       "Test CA",
		Status:       "V",
		Subject:      leaf.Subject.String(),
		CommonName:   leaf.Subject.CommonName,
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		CertDER:      leaf.Raw,
		Fingerprint:  db.Fingerprint(leaf.Raw),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStapleProviderGood(t *testing.T) {
	database, caCert, caKey, ocspCert, ocspKey := stapleTestEnv(t)
	leaf := makeLeaf(t, caCert, caKey, 200, "staple.example.com", time.Now().Add(365*24*time.Hour))
	insertLeaf(t, database, leaf, "00000000000000000000000000000000000000C8")

	prov := NewStapleProvider(StapleProviderConfig{
		CAName:     "Test CA",
		CACert:     caCert,
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		DB:         database,
	})
	t.Cleanup(prov.Close)

	der, err := prov.Refresh(leaf)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty staple")
	}
	if !bytes.Equal(der, prov.Staple(leaf)) {
		t.Fatal("Staple() should return cached DER")
	}

	resp, err := ocsp.ParseResponse(der, ocspCert)
	if err != nil {
		t.Fatalf("parse staple: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Fatalf("expected Good, got %d", resp.Status)
	}
	if resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("serial mismatch: %v vs %v", resp.SerialNumber, leaf.SerialNumber)
	}
}

func TestStapleProviderRevoked(t *testing.T) {
	database, caCert, caKey, ocspCert, ocspKey := stapleTestEnv(t)
	leaf := makeLeaf(t, caCert, caKey, 201, "revoked-staple.example.com", time.Now().Add(365*24*time.Hour))
	insertLeaf(t, database, leaf, "00000000000000000000000000000000000000C9")
	if err := database.RevokeCert("Test CA", "00000000000000000000000000000000000000C9", 1); err != nil {
		t.Fatal(err)
	}

	prov := NewStapleProvider(StapleProviderConfig{
		CAName:     "Test CA",
		CACert:     caCert,
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		DB:         database,
	})
	t.Cleanup(prov.Close)

	der, err := prov.Refresh(leaf)
	if err != nil {
		t.Fatalf("refresh revoked: %v", err)
	}
	resp, err := ocsp.ParseResponse(der, ocspCert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Fatalf("expected Revoked, got %d", resp.Status)
	}
}

func TestStapleProviderUnknownCert(t *testing.T) {
	_, caCert, caKey, ocspCert, ocspKey := stapleTestEnv(t)
	leaf := makeLeaf(t, caCert, caKey, 999, "unknown-staple.example.com", time.Now().Add(365*24*time.Hour))

	// DB not set → status resolution fails → unknown staple.
	prov := NewStapleProvider(StapleProviderConfig{
		CAName:     "Test CA",
		CACert:     caCert,
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})
	t.Cleanup(prov.Close)

	der, err := prov.Refresh(leaf)
	if err != nil {
		t.Fatalf("refresh unknown: %v", err)
	}
	resp, err := ocsp.ParseResponse(der, ocspCert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Status != ocsp.Unknown {
		t.Fatalf("expected Unknown, got %d", resp.Status)
	}
}

func TestStapleProviderWarmAndStart(t *testing.T) {
	database, caCert, caKey, ocspCert, ocspKey := stapleTestEnv(t)
	leaves := []*x509.Certificate{
		makeLeaf(t, caCert, caKey, 301, "w1.example.com", time.Now().Add(365*24*time.Hour)),
		makeLeaf(t, caCert, caKey, 302, "w2.example.com", time.Now().Add(365*24*time.Hour)),
	}
	for i, l := range leaves {
		insertLeaf(t, database, l, big.NewInt(int64(301+i)).String())
	}

	prov := NewStapleProvider(StapleProviderConfig{
		CAName:     "Test CA",
		CACert:     caCert,
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		DB:         database,
	})
	prov.Warm(leaves)
	for _, l := range leaves {
		if len(prov.Staple(l)) == 0 {
			t.Fatalf("no staple for %s after Warm", l.Subject.CommonName)
		}
	}
	prov.Start(time.Millisecond, func() []*x509.Certificate { return leaves })
	time.Sleep(10 * time.Millisecond)
	prov.Close()
	prov.Close() // idempotent
}

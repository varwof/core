// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckCertFile covers the certificate file health check: missing file,
// non-PEM/garbage content, a non-CERTIFICATE PEM block, and a valid cert.
func TestCheckCertFile(t *testing.T) {
	dir := t.TempDir()

	if _, err := checkCertFile(filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("missing file must error")
	}

	garbage := filepath.Join(dir, "garbage.pem")
	os.WriteFile(garbage, []byte("not pem at all"), 0o600)
	if _, err := checkCertFile(garbage); err == nil {
		t.Fatal("garbage must error")
	}

	keyBlock := filepath.Join(dir, "key.pem")
	os.WriteFile(keyBlock, []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), 0o600)
	if _, err := checkCertFile(keyBlock); err == nil {
		t.Fatal("non-CERTIFICATE PEM block must error")
	}

	cert, key := testFileCert(t)
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	if _, err := checkCertFile(certPath); err != nil {
		t.Fatalf("valid cert must parse: %v", err)
	}
}

// TestCheckKeyFile covers PKCS8/EC/PKCS1 parsing, missing and garbage content.
func TestCheckKeyFile(t *testing.T) {
	dir := t.TempDir()

	if _, err := checkKeyFile(filepath.Join(dir, "nope.key")); err == nil {
		t.Fatal("missing file must error")
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	pkcs1Path := filepath.Join(dir, "pkcs1.key")
	os.WriteFile(pkcs1Path, pkcs1, 0o600)
	if _, err := checkKeyFile(pkcs1Path); err != nil {
		t.Fatalf("PKCS1 must parse: %v", err)
	}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPath := filepath.Join(dir, "ec.key")
	os.WriteFile(ecPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), 0o600)
	if _, err := checkKeyFile(ecPath); err != nil {
		t.Fatalf("EC must parse: %v", err)
	}

	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pkcs8Path := filepath.Join(dir, "pkcs8.key")
	os.WriteFile(pkcs8Path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
	if _, err := checkKeyFile(pkcs8Path); err != nil {
		t.Fatalf("PKCS8 must parse: %v", err)
	}

	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), 0o600)
	if _, err := checkKeyFile(bad); err == nil {
		t.Fatal("corrupt key must error")
	}
}

// TestCheckCRLFreshness covers the CRL directory health check: unconfigured,
// unreadable dir, DER CRL, newest pick, expired and missing CRL cases.
func TestCheckCRLFreshnessFiles(t *testing.T) {
	if got := checkCRLFreshness(""); got != "ok" {
		t.Fatalf("empty dir must be ok, got %q", got)
	}
	if got := checkCRLFreshness(filepath.Join(t.TempDir(), "missing")); got != "error: cannot read CRL directory" {
		t.Fatalf("unreadable dir, got %q", got)
	}

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "a.crl"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)

	expired := makeTestCRL(t, -48*time.Hour, -24*time.Hour)
	stale := makeTestCRL(t, -10*time.Hour, time.Hour)
	fresh := makeTestCRL(t, -time.Hour, 24*time.Hour)

	os.WriteFile(filepath.Join(dir, "stale.crl"), updateTestCRL(stale), 0o600)
	os.WriteFile(filepath.Join(dir, "fresh.crl"), updateTestCRL(fresh), 0o600)
	os.WriteFile(filepath.Join(dir, "expired.crl"), updateTestCRL(expired), 0o600)

	if got := checkCRLFreshness(dir); got != "ok" {
		t.Fatalf("freshness with the freshest CRL must be ok, got %q", got)
	}

	os.Remove(filepath.Join(dir, "fresh.crl"))
	os.Remove(filepath.Join(dir, "stale.crl"))
	if got := checkCRLFreshness(dir); !stringsHasPrefix(got, "expired:") {
		t.Fatalf("only expired CRL must report expiration, got %q", got)
	}

	os.Remove(filepath.Join(dir, "expired.crl"))
	if got := checkCRLFreshness(dir); got != "error: no CRL found" {
		t.Fatalf("no CRL must report missing, got %q", got)
	}

	parseErr := filepath.Join(dir, "bad.crl")
	os.WriteFile(parseErr, []byte("not-a-crl"), 0o600)
	if got := checkCRLFreshness(dir); !stringsHasPrefix(got, "parse error:") {
		t.Fatalf("corrupt CRL must report parse error, got %q", got)
	}
}

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func testFileCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "health-check"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, key
}

func makeTestCRL(t *testing.T, thisUpdateDelta, nextUpdateDelta time.Duration) *x509.RevocationList {
	t.Helper()
	now := time.Now()
	return &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(thisUpdateDelta),
		NextUpdate: now.Add(nextUpdateDelta),
		RevokedCertificates: []pkix.RevokedCertificate{{
			SerialNumber:   big.NewInt(1),
			RevocationTime: now,
		}},
	}
}

func updateTestCRL(crl *x509.RevocationList) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "health-check"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{0x01, 0x02, 0x03},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	der, err := x509.CreateRevocationList(rand.Reader, crl, cert, key)
	if err != nil {
		panic(err)
	}
	return der
}

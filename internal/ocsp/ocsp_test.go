package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/varwof/engine/db"
)

func newTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:      true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestOCSPSigner(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "OCSP Signer",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestOCSPGoodStatus(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ocsp-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	database, err := db.Open(tmpDir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	// Insert a valid certificate
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, err := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	eeCert, err := x509.ParseCertificate(eeDER)
	if err != nil {
		t.Fatal(err)
	}

	record := &db.CertRecord{
		SerialNumber: "0000000000000000000000000000000000000064",
		CAName:       "Test CA",
		Status:       "V",
		Subject:      eeCert.Subject.String(),
		CommonName:   "test.example.com",
		NotBefore:    eeCert.NotBefore,
		NotAfter:     eeCert.NotAfter,
		CertDER:      eeDER,
		Fingerprint:  db.Fingerprint(eeDER),
	}
	if err := database.InsertCert(record); err != nil {
		t.Fatal(err)
	}

	// Build OCSP request for serial 100 (0x64)
	reqDER, err := ocsp.CreateRequest(eeCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})

	httpReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/ocsp-response" {
		t.Fatalf("expected application/ocsp-response, got %q", ct)
	}

	resp, err := ocsp.ParseResponse(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Fatalf("expected Good (0), got %d", resp.Status)
	}
}

func TestOCSPUnknownStatus(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ocsp-test-unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	database, err := db.Open(tmpDir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	// Build OCSP request for a certificate not in the database
	unknownKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unknownTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			CommonName: "unknown.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}
	unknownDER, err := x509.CreateCertificate(rand.Reader, unknownTmpl, caCert, &unknownKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	unknownCert, _ := x509.ParseCertificate(unknownDER)

	reqDER, err := ocsp.CreateRequest(unknownCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})

	httpReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp, err := ocsp.ParseResponse(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != ocsp.Unknown {
		t.Fatalf("expected Unknown (2), got %d", resp.Status)
	}
}

func TestBadRequest(t *testing.T) {
	handler := NewHandler(&Config{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (OCSP error), got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("expected application/ocsp-response, got %s", ct)
	}

	// Also test OPTIONS
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodOptions, "/", nil)
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 (OCSP error), got %d", w2.Code)
	}
}

func TestOCSPNextUpdateCustom(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ocsp-nextupdate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	database, err := db.Open(tmpDir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "nu.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, err := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	eeCert, _ := x509.ParseCertificate(eeDER)
	database.InsertCert(&db.CertRecord{
		SerialNumber: "00000000000000000000000000000000000000C8",
		CAName:       "Test CA",
		Status:       "V",
		Subject:      eeCert.Subject.String(),
		CommonName:   "nu.test",
		NotBefore:    eeCert.NotBefore,
		NotAfter:     eeCert.NotAfter,
		CertDER:      eeDER,
		Fingerprint:  db.Fingerprint(eeDER),
	})

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		NextUpdate: 1 * time.Hour,
	})

	reqDER, err := ocsp.CreateRequest(eeCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httpReq)

	resp, err := ocsp.ParseResponse(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedNext := time.Now().Add(1 * time.Hour)
	if resp.NextUpdate.Before(expectedNext.Add(-30*time.Minute)) || resp.NextUpdate.After(expectedNext.Add(30*time.Minute)) {
		t.Fatalf("NextUpdate %v outside expected range around %v", resp.NextUpdate, expectedNext)
	}
}

func TestOCSPGETValid(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "ocsp-get")
	defer os.RemoveAll(tmpDir)

	database, _ := db.Open(tmpDir + "/test.db")
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})

	// Build a valid OCSP request for a non-existent cert → should get Unknown
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "get.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, _ := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	unknownCert, _ := x509.ParseCertificate(eeDER)

	reqDER, _ := ocsp.CreateRequest(unknownCert, caCert, nil)
	encoded := base64.StdEncoding.EncodeToString(reqDER)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?"+url.Values{"query": {encoded}}.Encode(), nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/ocsp-response" {
		t.Fatalf("expected ocsp-response, got %s", w.Header().Get("Content-Type"))
	}
}

func TestOCSPGETBadBase64(t *testing.T) {
	handler := NewHandler(&Config{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?query=%%invalid", nil)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (OCSP error), got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("expected application/ocsp-response, got %s", ct)
	}
}

func TestOCSPRevokedStatus(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "ocsp-revoked")
	defer os.RemoveAll(tmpDir)

	database, _ := db.Open(tmpDir + "/test.db")
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	// Insert a revoked certificate
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(300),
		Subject:      pkix.Name{CommonName: "revoked.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, _ := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	eeCert, _ := x509.ParseCertificate(eeDER)

	now := time.Now()
	reason := 1
	database.InsertCert(&db.CertRecord{
		SerialNumber: "000000000000000000000000000000000000012C",
		CAName:       "Test CA",
		Status:       "R",
		Subject:      eeCert.Subject.String(),
		CommonName:   "revoked.test",
		NotBefore:    eeCert.NotBefore,
		NotAfter:     eeCert.NotAfter,
		CertDER:      eeDER,
		Fingerprint:  db.Fingerprint(eeDER),
		RevokedAt:    &now,
		RevokeReason: &reason,
	})

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})

	reqDER, _ := ocsp.CreateRequest(eeCert, caCert, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	handler.ServeHTTP(w, r)

	resp, err := ocsp.ParseResponse(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != ocsp.Revoked {
		t.Fatalf("expected Revoked (1), got %d", resp.Status)
	}
	if resp.RevocationReason != 1 {
		t.Fatalf("expected reason 1, got %d", resp.RevocationReason)
	}
}

func TestOCSPWithCacheHit(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "ocsp-cache")
	defer os.RemoveAll(tmpDir)

	database, _ := db.Open(tmpDir + "/test.db")
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	handler := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
	})
	cache := NewCache(100, 5*time.Minute)
	handler.SetCache(cache)

	// First request → miss, generates response → sets cache
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(400),
		Subject:      pkix.Name{CommonName: "cache.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, _ := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	eeCert, _ := x509.ParseCertificate(eeDER)

	database.InsertCert(&db.CertRecord{
		SerialNumber: "0000000000000000000000000000000000000190",
		CAName:       "Test CA",
		Status:       "V",
		Subject:      eeCert.Subject.String(),
		CommonName:   "cache.test",
		NotBefore:    eeCert.NotBefore,
		NotAfter:     eeCert.NotAfter,
		CertDER:      eeDER,
		Fingerprint:  db.Fingerprint(eeDER),
	})

	reqDER, _ := ocsp.CreateRequest(eeCert, caCert, nil)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	handler.ServeHTTP(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	// Second request with same reqDER → cache hit
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", w2.Code)
	}
	resp2, _ := ocsp.ParseResponse(w2.Body.Bytes(), nil)
	if resp2.Status != ocsp.Good {
		t.Fatalf("expected Good, got %d", resp2.Status)
	}
}

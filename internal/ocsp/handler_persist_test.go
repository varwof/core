package ocsp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/varwof/engine/db"
)

func TestHandlerPersistedCache(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	caCert, caKey := newTestCA(t)
	ocspCert, ocspKey := newTestOCSPSigner(t, caCert, caKey)

	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "persist.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	eeDER, err := x509.CreateCertificate(rand.Reader, eeTmpl, caCert, &eeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	eeCert, err := x509.ParseCertificate(eeDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InsertCert(&db.CertRecord{
		SerialNumber: "0000000000000000000000000000000000000064",
		CAName:       "Test CA",
		Status:       "V",
		Subject:      eeCert.Subject.String(),
		CommonName:   "persist.example.com",
		NotBefore:    eeCert.NotBefore,
		NotAfter:     eeCert.NotAfter,
		CertDER:      eeDER,
		Fingerprint:  db.Fingerprint(eeDER),
	}); err != nil {
		t.Fatal(err)
	}

	cacheFile := filepath.Join(dir, "ocsp-cache.json")
	h := NewHandler(&Config{
		DB:         database,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		CacheFile:  cacheFile,
	})
	defer h.Close()

	reqDER, err := ocsp.CreateRequest(eeCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	serve := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		r.Header.Set("Content-Type", "application/ocsp-request")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w1 := serve()
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: code=%d", w1.Code)
	}
	// Give the async save a moment to write.
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("cache file not persisted: %v", err)
	}

	w2 := serve()
	if w2.Code != http.StatusOK {
		t.Fatalf("second request: code=%d", w2.Code)
	}
	if !bytes.Equal(w1.Body.Bytes(), w2.Body.Bytes()) {
		t.Fatal("cached response differs from fresh response")
	}

	// Reload from disk into a fresh handler with no DB access: the persisted
	// cache alone must serve the same response.
	h2 := NewHandler(&Config{
		DB:         nil,
		CACert:     caCert,
		CAName:     "Test CA",
		SignerCert: ocspCert,
		SignerKey:  ocspKey,
		CacheFile:  cacheFile,
	})
	defer h2.Close()
	w3 := serveFrom(h2, reqDER)
	if w3.Code != http.StatusOK {
		t.Fatalf("stateless reload request: code=%d", w3.Code)
	}
	if !bytes.Equal(w1.Body.Bytes(), w3.Body.Bytes()) {
		t.Fatal("stateless reload response differs")
	}
}

func serveFrom(h *Handler, reqDER []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/ocsp", io.NopCloser(bytes.NewReader(reqDER)))
	r.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

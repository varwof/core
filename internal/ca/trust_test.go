package ca

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func rootCAPEM(t *testing.T) string {
	t.Helper()
	caCert, _ := newTestCA(t)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
}

// TestFetchCACertBundleValid verifies a valid remote bundle downloads and
// passes the root-CA validation.
func TestFetchCACertBundleValid(t *testing.T) {
	rootPEM := rootCAPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(rootPEM))
	}))
	defer srv.Close()

	data, err := FetchCACertBundle(srv.URL)
	if err != nil {
		t.Fatalf("FetchCACertBundle: %v", err)
	}
	if !bundleHasRootCA(data) {
		t.Fatal("expected valid root CA in fetched bundle")
	}
}

// TestFetchCACertBundleRejectsEmpty verifies an HTML error page / empty body is
// rejected rather than silently importing zero anchors.
func TestFetchCACertBundleRejectsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>error page</body></html>"))
	}))
	defer srv.Close()

	if _, err := FetchCACertBundle(srv.URL); err == nil {
		t.Fatal("expected error for non-CA bundle response")
	}
}

// TestFetchCACertBundleRejectsNonTLS verifies http:// (non-loopback) URLs are
// refused.
func TestFetchCACertBundleRejectsNonTLS(t *testing.T) {
	// The default URL is https; overriding to a non-loopback http URL must fail
	// at the scheme check even though no network call happens.
	if _, err := FetchCACertBundle("http://example.com/ca.pem"); err == nil {
		t.Fatal("expected error for non-TLS non-loopback URL")
	}
}

// TestFetchCACertBundleHTTPStatus verifies non-200 statuses are rejected.
func TestFetchCACertBundleHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := FetchCACertBundle(srv.URL); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

// TestFetchCACertBundleTooLarge verifies the size cap is enforced.
func TestFetchCACertBundleTooLarge(t *testing.T) {
	big := strings.Repeat("A", maxTrustBundleBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(big))
	}))
	defer srv.Close()

	if _, err := FetchCACertBundle(srv.URL); err == nil {
		t.Fatal("expected error for oversized bundle")
	}
}

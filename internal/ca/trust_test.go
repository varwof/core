// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

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

// M9: fetching from internal/private networks (SSRF) must be refused even over
// https, since any https:// host was previously accepted.
func TestFetchCACertBundleRejectsInternalNetworks(t *testing.T) {
	for _, u := range []string{
		"https://10.0.0.5/ca.pem",       // RFC 1918 private
		"https://192.168.1.1/ca.pem",    // RFC 1918 private
		"https://172.16.0.5/ca.pem",     // RFC 1918 private
		"http://169.254.169.254/latest", // link-local (cloud metadata)
		"https://100.64.0.1/ca.pem",     // CGNAT
		"https://[fc00::1]/ca.pem",      // IPv6 unique-local
	} {
		if _, err := FetchCACertBundle(u); err == nil {
			t.Fatalf("expected SSRF rejection for %s", u)
		}
	}
}

// M9: loopback remains allowed for local test federations.
func TestFetchCACertBundleAllowsLoopback(t *testing.T) {
	rootPEM := rootCAPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(rootPEM))
	}))
	defer srv.Close()

	if _, err := FetchCACertBundle(srv.URL); err != nil {
		t.Fatalf("loopback fetch should be allowed: %v", err)
	}
}

// M10: outbound HTTP destinations (e.g. webhook subscriptions) must never point
// at internal/private/loopback hosts, and must use http/https with a host.
func TestValidateOutboundHTTPURL(t *testing.T) {
	reject := []string{
		"http://127.0.0.1:8080/hook",    // loopback
		"http://localhost:9000/hook",    // loopback
		"https://10.0.0.5/hook",         // private
		"https://192.168.1.10/hook",     // private
		"http://169.254.169.254/latest", // link-local
		"https://[::1]/hook",            // IPv6 loopback
		"ftp://example.com/hook",        // non-http(s) scheme
		"https:///nohost",               // missing host
		"",                              // empty
		"not a url",                     // unparseable
	}
	for _, u := range reject {
		if err := ValidateOutboundHTTPURL(u); err == nil {
			t.Fatalf("expected rejection for %q", u)
		}
	}

	// Literal public addresses are allowed (no DNS needed, so deterministic).
	if err := ValidateOutboundHTTPURL("http://8.8.8.8/hook"); err != nil {
		t.Fatalf("unexpected error for http://8.8.8.8: %v", err)
	}
	if err := ValidateOutboundHTTPURL("https://8.8.8.8/hook"); err != nil {
		t.Fatalf("unexpected error for https://8.8.8.8: %v", err)
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

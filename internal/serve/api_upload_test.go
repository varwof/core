// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func selfSignedCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Varwof"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAPIUploadCert(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	certPEM := selfSignedCertPEM(t, "nas1.varwof.com")
	body, _ := json.Marshal(map[string]string{
		"cert_pem":    certPEM,
		"ca_name":     "NAS Devices",
		"device_type": "nas",
		"device_name": "nas1",
	})

	resp := authedPost(t, ts, "/api/v1/certs/upload", "application/json", strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
	}
	var out certUploadResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.CommonName != "nas1.varwof.com" {
		t.Errorf("common_name = %q", out.CommonName)
	}
	if out.CAName != "NAS Devices" {
		t.Errorf("ca_name = %q", out.CAName)
	}

	// The uploaded cert must be retrievable from the inventory.
	getResp := authedGet(t, ts, "/api/v1/cert/NAS Devices/"+out.SerialNumber)
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("uploaded cert not found: status %d", getResp.StatusCode)
	}
}

func TestAPIUploadCert_DuplicateIsConflict(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	certPEM := selfSignedCertPEM(t, "nas-dup.varwof.com")
	body, _ := json.Marshal(map[string]string{"cert_pem": certPEM, "ca_name": "NAS Devices", "device_type": "nas"})

	first := authedPost(t, ts, "/api/v1/certs/upload", "application/json", strings.NewReader(string(body)))
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first upload expected 201, got %d", first.StatusCode)
	}
	second := authedPost(t, ts, "/api/v1/certs/upload", "application/json", strings.NewReader(string(body)))
	second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate upload expected 409, got %d", second.StatusCode)
	}
	_ = srv
}

func TestAPIUploadCert_InvalidBody(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp := authedPost(t, ts, "/api/v1/certs/upload", "application/json", strings.NewReader(`{"cert_pem":""}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty cert_pem expected 400, got %d", resp.StatusCode)
	}

	resp2 := authedPost(t, ts, "/api/v1/certs/upload", "application/json", strings.NewReader(`{"cert_pem":"not-a-cert"}`))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid cert expected 400, got %d", resp2.StatusCode)
	}
}

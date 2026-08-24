// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package tsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeConfig_StoreLoad(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	got := rc.Load()
	if got == nil || got.SignerCert != cert {
		t.Fatal("expected stored cert")
	}
}

func TestRuntimeConfig_NilSafe(t *testing.T) {
	var rc *RuntimeConfig
	if got := rc.Load(); got == nil {
		// nil returns empty config
	}
	if info := rc.CertInfo(); info != nil {
		t.Fatal("expected nil CertInfo from nil receiver")
	}
}

func TestRuntimeConfig_CertInfo(t *testing.T) {
	cert, _ := newTestSigner(t)
	chain := []*x509.Certificate{cert}
	rc := NewRuntimeConfig(&TSAConfig{
		SignerCert: cert,
		Chain:      chain,
	})

	info := rc.CertInfo()
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if info.SerialNumber != cert.SerialNumber.String() {
		t.Fatalf("serial mismatch: %s vs %s", info.SerialNumber, cert.SerialNumber)
	}
	if info.Subject != cert.Subject.String() {
		t.Fatalf("subject mismatch")
	}
	if info.Issuer != cert.Issuer.String() {
		t.Fatalf("issuer mismatch")
	}
	if !info.HasChain {
		t.Fatal("expected HasChain=true")
	}
}

func TestRuntimeConfig_CertInfoNilCert(t *testing.T) {
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: nil})
	info := rc.CertInfo()
	if info != nil {
		t.Fatal("expected nil CertInfo when no signer cert")
	}
}

func TestNeedsRenewal(t *testing.T) {
	tests := []struct {
		name   string
		cert   *x509.Certificate
		window time.Duration
		want   bool
	}{
		{
			name:   "nil cert",
			cert:   nil,
			window: time.Hour,
			want:   true,
		},
		{
			name: "expires within window",
			cert: &x509.Certificate{
				NotAfter: time.Now().Add(30 * time.Minute),
			},
			window: time.Hour,
			want:   true,
		},
		{
			name: "expires outside window",
			cert: &x509.Certificate{
				NotAfter: time.Now().Add(2 * time.Hour),
			},
			window: time.Hour,
			want:   false,
		},
		{
			name: "already expired",
			cert: &x509.Certificate{
				NotAfter: time.Now().Add(-1 * time.Hour),
			},
			window: time.Hour,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NeedsRenewal(tt.cert, tt.window)
			if got != tt.want {
				t.Fatalf("NeedsRenewal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignerRenewLoop_StopsCleanly(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	stopCh := make(chan struct{})
	done := make(chan struct{})

	go func() {
		SignerRenewLoop(rc, &RenewalConfig{
			CoreURL: "http://127.0.0.1:19999",
		}, stopCh)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	close(stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal loop did not stop in time")
	}
}

func TestSignerRenewLoop_NoCoreURL(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	stopCh := make(chan struct{})
	done := make(chan struct{})

	go func() {
		SignerRenewLoop(rc, &RenewalConfig{
			CoreURL: "",
		}, stopCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		close(stopCh)
		t.Fatal("renewal loop should exit immediately with empty CoreURL")
	}
}

func TestSignerRenewLoop_NoRenewalNeeded(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	var attempted atomic.Bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempted.Store(true)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	stopCh := make(chan struct{})
	done := make(chan struct{})

	go func() {
		SignerRenewLoop(rc, &RenewalConfig{
			CoreURL:       ts.URL,
			CheckInterval: 50 * time.Millisecond,
			RenewalWindow: 1 * time.Hour,
		}, stopCh)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	close(stopCh)
	<-done

	if attempted.Load() {
		t.Fatal("renewal should not be attempted when cert is not near expiry")
	}
}

func TestParseChainPEM(t *testing.T) {
	cert, key := newTestSigner(t)
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)

	chain := ParseChainPEM(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})))
	if len(chain) != 1 {
		t.Fatalf("expected 1 cert in chain, got %d", len(chain))
	}
}

func TestParseChainPEM_Empty(t *testing.T) {
	chain := ParseChainPEM("")
	if len(chain) != 0 {
		t.Fatalf("expected empty chain, got %d certs", len(chain))
	}
}

func TestParseChainPEM_Multiple(t *testing.T) {
	cert1, key1 := newTestSigner(t)
	cert2, key2 := newTestSigner(t)
	der1, _ := x509.CreateCertificate(rand.Reader, cert1, cert1, key1.Public(), key1)
	der2, _ := x509.CreateCertificate(rand.Reader, cert2, cert2, key2.Public(), key2)

	pem1 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der1}))
	pem2 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der2}))

	chain := ParseChainPEM(pem1 + pem2)
	if len(chain) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(chain))
	}
}

func TestForceRenewSignerCert(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	dir := t.TempDir()
	err := ForceRenewSignerCert(rc, &RenewalConfig{
		CoreURL:  ts.URL,
		CertFile: filepath.Join(dir, "signer.pem"),
		KeyFile:  filepath.Join(dir, "signer.key"),
		CAName:   "tsa",
	})
	if err == nil {
		t.Fatal("expected error from ForceRenewSignerCert with 500 response")
	}
}

func TestRotateSignerCert(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	dir := t.TempDir()
	err := RotateSignerCert(rc, &RenewalConfig{
		CoreURL:  ts.URL,
		CertFile: filepath.Join(dir, "signer.pem"),
		KeyFile:  filepath.Join(dir, "signer.key"),
		CAName:   "tsa",
	})
	if err == nil {
		t.Fatal("expected error from RotateSignerCert with 500 response")
	}
}

func TestIssueCertViaAPI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/certs" {
			t.Fatalf("expected /api/v1/certs, got %s", r.URL.Path)
		}

		json.NewDecoder(r.Body).Decode(&map[string]interface{}{})

		cert, key := newTestSigner(t)
		der, _ := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem":  certPEM,
			"chain_pem": certPEM,
		})
	}))
	defer ts.Close()

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: "Test TSA"},
		PublicKey: newKey.Public(),
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, newKey)

	certPEM, chainPEM, err := issueCertViaAPI(&RenewalConfig{
		CoreURL:      ts.URL,
		CAName:       "tsa",
		ValidityDays: 365,
	}, csrDER, "test-tsa.example.com")
	if err != nil {
		t.Fatalf("issueCertViaAPI: %v", err)
	}
	if certPEM == "" {
		t.Fatal("expected non-empty cert PEM")
	}
	if chainPEM == "" {
		t.Fatal("expected non-empty chain PEM")
	}
}

func TestIssueCertViaAPI_BadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer ts.Close()

	_, _, err := issueCertViaAPI(&RenewalConfig{
		CoreURL: ts.URL,
		CAName:  "tsa",
	}, []byte("fake-csr"), "test")
	if err == nil {
		t.Fatal("expected error from bad status")
	}
}

func TestIssueCertViaAPI_MTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected mTLS client cert")
		}
		cert, key := newTestSigner(t)
		der, _ := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": certPEM})
	}))
	defer ts.Close()

	dir := t.TempDir()
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, clientTmpl, &clientKey.PublicKey, clientKey)
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER}), 0600)

	clientCert, _ := x509.ParseCertificate(clientDER)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCert)
	ts.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	ts.TLS.ClientCAs = clientPool

	caCert, _ := x509.ParseCertificate(ts.Certificate().Raw)
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0644)

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: "mtls-tsa"},
		PublicKey: newKey.Public(),
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, newKey)

	certPEM, _, err := issueCertViaAPI(&RenewalConfig{
		CoreURL:       ts.URL,
		CAName:        "tsa",
		ValidityDays:  365,
		TLSClientCert: certFile,
		TLSClientKey:  keyFile,
		CACertFile:    caFile,
	}, csrDER, "mtls-tsa.example.com")
	if err != nil {
		t.Fatalf("issueCertViaAPI mTLS: %v", err)
	}
	if certPEM == "" {
		t.Fatal("expected non-empty cert PEM")
	}
}

func TestIssueCertViaAPI_BadTLSClientCert(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "missing-client.pem")
	_, _, err := issueCertViaAPI(&RenewalConfig{
		CoreURL:       "http://127.0.0.1:19999",
		TLSClientCert: bad,
		TLSClientKey:  filepath.Join(dir, "missing-client.key"),
	}, []byte("csr"), "test")
	if err == nil {
		t.Fatal("expected error loading missing TLS client cert")
	}
}

func TestNewHandlerWithRuntime(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})
	h := NewHandlerWithRuntime(rc)

	if h.RuntimeConfig() != rc {
		t.Fatal("RuntimeConfig() should return the same pointer")
	}
}

func TestRuntimeConfig_Store(t *testing.T) {
	rc := &RuntimeConfig{}
	cert1, _ := newTestSigner(t)
	cert2, _ := newTestSigner(t)
	rc.Store(&TSAConfig{SignerCert: cert1})
	rc.Store(&TSAConfig{SignerCert: cert2})
	got := rc.Load()
	if got == nil || got.SignerCert != cert2 {
		t.Fatal("Store should replace the config")
	}
}

func TestRenewSignerCert_NoCurrentCert(t *testing.T) {
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: nil})
	err := renewSignerCert(rc, &RenewalConfig{CoreURL: "http://127.0.0.1:19999"})
	if err == nil {
		t.Fatal("expected error when no current signer cert")
	}
}

func TestRenewSignerCert_NoPEMResponse(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": "", "chain_pem": ""})
	}))
	defer ts.Close()

	dir := t.TempDir()
	err := renewSignerCert(rc, &RenewalConfig{
		CoreURL:  ts.URL,
		CertFile: filepath.Join(dir, "signer.pem"),
		KeyFile:  filepath.Join(dir, "signer.key"),
		CAName:   "tsa",
	})
	if err == nil {
		t.Fatal("expected error when API returns no PEM")
	}
}

func TestRenewSignerCert_Success(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})

	issuedCert, issuedKey := newTestSigner(t)
	der, _ := x509.CreateCertificate(rand.Reader, issuedCert, issuedCert, issuedKey.Public(), issuedKey)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": certPEM, "chain_pem": certPEM})
	}))
	defer ts.Close()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "signer.pem")
	keyFile := filepath.Join(dir, "signer.key")

	err := ForceRenewSignerCert(rc, &RenewalConfig{
		CoreURL:       ts.URL,
		CertFile:      certFile,
		KeyFile:       keyFile,
		CAName:        "tsa",
		ValidityDays:  365,
		TLSClientCert: "",
	})
	if err != nil {
		t.Fatalf("ForceRenewSignerCert: %v", err)
	}

	newCfg := rc.Load()
	if newCfg == nil || newCfg.SignerCert == nil {
		t.Fatal("expected updated config after renewal")
	}
	if newCfg.SignerCert.SerialNumber.String() != issuedCert.SerialNumber.String() {
		t.Fatal("config should contain the newly issued cert")
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("expected cert file on disk: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("expected key file on disk: %v", err)
	}
}

func TestLoadCACertFile(t *testing.T) {
	cert, key := newTestSigner(t)
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	caCert, err := loadCACertFile(p)
	if err != nil {
		t.Fatalf("loadCACertFile: %v", err)
	}
	if caCert == nil {
		t.Fatal("expected non-nil CA cert")
	}

	if _, err := loadCACertFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCACertFile(bad); err == nil {
		t.Fatal("expected error for non-PEM data")
	}
}

func TestSignerCertInfoJSON(t *testing.T) {
	cert, _ := newTestSigner(t)
	rc := NewRuntimeConfig(&TSAConfig{SignerCert: cert})
	info := rc.CertInfo()

	if info.SerialNumber == "" {
		t.Fatal("expected non-empty serial")
	}
	if info.NotBefore == "" || info.NotAfter == "" {
		t.Fatal("expected non-empty time fields")
	}

	// Verify serial is a valid big.Int string
	n := new(big.Int)
	if _, ok := n.SetString(info.SerialNumber, 10); !ok {
		t.Fatalf("serial not a valid decimal: %s", info.SerialNumber)
	}
}

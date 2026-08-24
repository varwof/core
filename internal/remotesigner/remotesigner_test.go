// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package remotesigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestPubKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemData)
}

func generateTestCertAndKey(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func newMockHSMProxy(t *testing.T, pubkeyB64 string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"public_key": pubkeyB64})
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeyAlias string `json:"key_alias"`
			Hash     string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		sig := base64.StdEncoding.EncodeToString([]byte("signed-" + req.Hash))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"signature": sig})
	})
	return httptest.NewTLSServer(mux)
}

// newMockHSMProxyConfig returns a Config pre-filled with the test server's TLS CA
// so the RemoteSigner client can connect over HTTPS.
func newMockHSMProxyConfig(t *testing.T, ts *httptest.Server) Config {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	// httptest.NewTLSServer uses the default certificate; extract its PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ts.Certificate().Raw,
	})
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Endpoint: ts.URL,
		KeyAlias: "test-key",
		CACert:   caFile,
	}
}

func newErrorHSMProxy(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

func TestNew_EmptyEndpoint(t *testing.T) {
	_, err := New(Config{})
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Errorf("expected 'endpoint is required', got: %v", err)
	}
}

func TestNew_EmptyKeyAlias(t *testing.T) {
	_, err := New(Config{Endpoint: "https://localhost:9999"})
	if err == nil || !strings.Contains(err.Error(), "key_alias is required") {
		t.Errorf("expected 'key_alias is required', got: %v", err)
	}
}

func TestNew_Success(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	cfg := newMockHSMProxyConfig(t, ts)
	rs, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Public() == nil {
		t.Error("Public() returned nil")
	}
}

func TestNew_FetchPublicKey_Error(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	_, err := New(newMockHSMProxyConfig(t, ts))
	if err == nil {
		t.Error("expected error from 500 response")
	}
}

func TestNew_FetchPublicKey_InvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	_, err := New(newMockHSMProxyConfig(t, ts))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNew_FetchPublicKey_InvalidBase64(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"public_key": "!!!invalid-base64!!!"})
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	_, err := New(newMockHSMProxyConfig(t, ts))
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestNew_FetchPublicKey_InvalidPEM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.StdEncoding.EncodeToString([]byte("not a pem block"))
		json.NewEncoder(w).Encode(map[string]string{"public_key": b64})
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	_, err := New(newMockHSMProxyConfig(t, ts))
	if err == nil {
		t.Error("expected error for invalid PEM block")
	}
}

func TestNew_FetchPublicKey_InvalidPKIX(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid-pkix")})
		b64 := base64.StdEncoding.EncodeToString(pemData)
		json.NewEncoder(w).Encode(map[string]string{"public_key": b64})
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	_, err := New(newMockHSMProxyConfig(t, ts))
	if err == nil {
		t.Error("expected error for invalid PKIX data")
	}
}

func TestSign_Success(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	digest := []byte("test-digest-data")
	sig, err := rs.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Error("empty signature")
	}
}

func TestSign_ServerError(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	// Override endpoint to a bad one for Sign
	rs.endpoint = "http://127.0.0.1:19999"
	_, err = rs.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestSign_ServerNon200(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	// Override endpoint to error server
	errTS := newErrorHSMProxy(t, 500, "sign error")
	defer errTS.Close()
	rs.endpoint = errTS.URL

	_, err = rs.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Error("expected error from 500 response")
	}
}

func TestSign_InvalidSignatureJSON(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	// Mock sign endpoint returning invalid JSON
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"public_key": pubkeyB64})
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	badTS := httptest.NewServer(mux)
	defer badTS.Close()
	rs.endpoint = badTS.URL

	_, err = rs.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestSign_InvalidSignatureBase64(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"public_key": pubkeyB64})
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"signature": "!!!invalid!!!"})
	})
	badTS := httptest.NewServer(mux)
	defer badTS.Close()
	rs.endpoint = badTS.URL

	_, err = rs.Sign(rand.Reader, []byte("test"), nil)
	if err == nil {
		t.Error("expected error for invalid base64 signature")
	}
}

func TestAuthTransport_WithToken(t *testing.T) {
	var gotToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("Authorization")
		w.WriteHeader(200)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	at := &authTransport{
		inner:     http.DefaultTransport,
		authToken: "test-token-123",
	}
	client := &http.Client{Transport: at}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotToken != "Bearer test-token-123" {
		t.Errorf("got token %q, want 'Bearer test-token-123'", gotToken)
	}
}

func TestAuthTransport_EmptyToken(t *testing.T) {
	var gotToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("Authorization")
		w.WriteHeader(200)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	at := &authTransport{
		inner:     http.DefaultTransport,
		authToken: "",
	}
	client := &http.Client{Transport: at}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotToken != "" {
		t.Errorf("empty token should not set Authorization header, got %q", gotToken)
	}
}

func TestNew_WithAuthToken(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	cfg := newMockHSMProxyConfig(t, ts)
	cfg.AuthToken = "my-token"
	rs, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rs == nil {
		t.Fatal("rs is nil")
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		Endpoint:  "https://hsm:8445",
		KeyAlias:  "alias1",
		TLSCert:   "/path/cert.pem",
		TLSKey:    "/path/key.pem",
		AuthToken: "token123",
	}
	if cfg.Endpoint != "https://hsm:8445" {
		t.Error("wrong endpoint")
	}
	if cfg.KeyAlias != "alias1" {
		t.Error("wrong key alias")
	}
	if cfg.AuthToken != "token123" {
		t.Error("wrong auth token")
	}
}

// --- Tier 3: mTLS with CA cert verification ---

func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)
	return cert, key
}

func startTLSMockSigner(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (addr string, cleanup func()) {
	t.Helper()
	// Generate server certificate signed by CA
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pki-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER, caCert.Raw},
		PrivateKey:  serverKey,
	}

	pubkeyB64 := generateTestPubKeyPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"public_key": pubkeyB64})
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeyAlias string `json:"key_alias"`
			Hash     string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		sig := base64.StdEncoding.EncodeToString([]byte("signed-" + req.Hash))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"signature": sig})
	})

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)

	return listener.Addr().String(), func() {
		srv.Close()
		listener.Close()
	}
}

func TestNew_WithCACert_VerifiesServer(t *testing.T) {
	caCert, caKey := generateCA(t)
	addr, cleanup := startTLSMockSigner(t, caCert, caKey)
	defer cleanup()

	// Write CA cert to temp file
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := New(Config{
		Endpoint: fmt.Sprintf("https://%s", addr),
		KeyAlias: "my-key",
		CACert:   caFile,
	})
	if err != nil {
		t.Fatalf("expected success with valid CA cert, got: %v", err)
	}
	if rs.Public() == nil {
		t.Error("Public() returned nil")
	}

	sig, err := rs.Sign(rand.Reader, []byte("test-digest"), nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("empty signature")
	}
}

func TestNew_WithCACert_WrongCA_RejectsServer(t *testing.T) {
	// Server is signed by ca1
	ca1Cert, ca1Key := generateCA(t)
	addr, cleanup := startTLSMockSigner(t, ca1Cert, ca1Key)
	defer cleanup()

	// Client trusts ca2 (different CA)
	ca2Cert, _ := generateCA(t)
	ca2PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca2Cert.Raw})
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, ca2PEM, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := New(Config{
		Endpoint: fmt.Sprintf("https://%s", addr),
		KeyAlias: "my-key",
		CACert:   caFile,
	})
	if err == nil {
		t.Fatal("expected error with wrong CA cert, got nil")
	}
	if !strings.Contains(err.Error(), "fetch public key") && !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "handshake") {
		t.Errorf("expected TLS/CA error, got: %v", err)
	}
}

func TestNew_WithCACert_FileNotFound(t *testing.T) {
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	_, err := New(Config{
		Endpoint: ts.URL,
		KeyAlias: "my-key",
		CACert:   "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent CA cert file")
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Errorf("expected 'read CA cert' error, got: %v", err)
	}
}

func TestNew_NoCACert_SkipsVerification(t *testing.T) {
	// Without CACert, the client should not require RootCAs
	pubkeyB64 := generateTestPubKeyPEM(t)
	ts := newMockHSMProxy(t, pubkeyB64)
	defer ts.Close()

	rs, err := New(newMockHSMProxyConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Public() == nil {
		t.Error("Public() returned nil")
	}
}

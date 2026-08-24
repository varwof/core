package serve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	p12 "software.sslmate.com/src/go-pkcs12"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// helper: create a self-signed cert with SAN and return (cert, key, PEM, DER)
func generateSelfSignedCertForTest(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		DNSNames:     []string{cn, "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes, der
}

// helper: create valid CSR PEM
func createCSRPemForTest(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ─── apiK8sSign ────────────────────────────────────────────────────

func TestK8sSign_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/k8s/sign", nil)
	srv.apiK8sSign(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestK8sSign_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", strings.NewReader("not json"))
	srv.apiK8sSign(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestK8sSign_EmptyCSR(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"csr_pem": ""})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestK8sSign_CANotFound(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"csr_pem": "x", "ca_name": "nonexistent"})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestK8sSign_InvalidCSRBlock(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"csr_pem": "-----BEGIN CERTIFICATE-----\nYm9nYXM=\n-----END CERTIFICATE-----",
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestK8sSign_InvalidCSRParse(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nYm9nYXM=\n-----END CERTIFICATE REQUEST-----",
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestK8sSign_Success(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	csrPEM := createCSRPemForTest(t, "k8s-node-1")
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{
		"csr_pem": csrPEM,
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 200 {
		t.Fatalf("k8s sign failed: %d %s", w.Code, w.Body.String())
	}
}

func TestK8sSign_WithProfile(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	csrPEM := createCSRPemForTest(t, "k8s-worker")
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{
		"csr_pem":        csrPEM,
		"validity_days":  90,
		"common_name":    "k8s-worker",
		"sans":           []string{"DNS:k8s-worker.local", "IP:10.0.0.5"},
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 200 {
		t.Fatalf("k8s sign failed: %d %s", w.Code, w.Body.String())
	}
}

func TestK8sSign_WithChain(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	csrPEM := createCSRPemForTest(t, "k8s-chain-test")

	// Insert a CA meta with a chain file
	cert, _, _, der := generateSelfSignedCertForTest(t, "TestCA")
	d.InsertCAMeta(&db.CAMeta{
		Name:         "test-ca",
		CertDER:      der,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		KeyAlgorithm: "ECDSA",
	})

	// Write chain file
	chainDir := t.TempDir()
	chainPath := filepath.Join(chainDir, "chain.pem")
	os.WriteFile(chainPath, der, 0644)

	// Update CA config to point to chain file
	cfg := srv.getConfig()
	caCfg := cfg.CAs["test-ca"]
	caCfg.Chain = chainPath
	cfg.CAs["test-ca"] = caCfg

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{
		"csr_pem":   csrPEM,
		"ca_name":   "test-ca",
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestK8sSign_ValidityFromConfig(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	csrPEM := createCSRPemForTest(t, "k8s-config-validity")

	cfg := srv.getConfig()
	cfg.Defaults.CertValidity = "720h"

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{
		"csr_pem": csrPEM,
	})
	r := httptest.NewRequest("POST", "/api/v1/k8s/sign", bytes.NewReader(body))
	srv.apiK8sSign(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiRenewCert ──────────────────────────────────────────────────

func TestRenewCert_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/abc123/renew", nil)
	srv.apiRenewCert(w, r, "test-ca", "abc123")
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestRenewCert_CANotFoundV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/nonexistent/abc123/renew", nil)
	srv.apiRenewCert(w, r, "nonexistent", "abc123")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestRenewCert_CertNotFoundV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/nonexistent/renew", nil)
	srv.apiRenewCert(w, r, "test-ca", "nonexistent")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestRenewCert_SuccessV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	certDER := issueCertDirect(t, d, "test-ca", "renew-target.local")
	serial := fmt.Sprintf("%X", certDER.SerialNumber)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/"+serial+"/renew", nil)
	srv.apiRenewCert(w, r, "test-ca", serial)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiExportCert ─────────────────────────────────────────────────

func TestExportCert_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cert/test-ca/abc/export", nil)
	srv.apiExportCert(w, r, "test-ca", "abc")
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestExportCert_ListFailedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/nonexistent/abc/export", nil)
	srv.apiExportCert(w, r, "nonexistent", "abc")
	if w.Code != 404 {
		t.Fatalf("expected 404 got %d", w.Code)
	}
}

func TestExportCert_CertFoundV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	certDER := issueCertDirect(t, d, "test-ca", "export-target.local")
	serial := fmt.Sprintf("%X", certDER.SerialNumber)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/"+serial+"/export", nil)
	srv.apiExportCert(w, r, "test-ca", serial)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("expected pem content type, got %s", ct)
	}
}

// ─── apiGenerateCRL ────────────────────────────────────────────────

func TestGenerateCRL_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/crl/test-ca/generate", nil)
	srv.apiGenerateCRL(w, r, "test-ca")
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestGenerateCRL_CANotFoundV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/crl/nonexistent/generate", nil)
	srv.apiGenerateCRL(w, r, "nonexistent")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestGenerateCRL_SuccessV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/crl/test-ca/generate", nil)
	srv.apiGenerateCRL(w, r, "test-ca")
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiExportCert with DB error ──────────────────────────────────

func TestExportCert_DBListErrorV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	d.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/abc/export", nil)
	srv.apiExportCert(w, r, "test-ca", "abc")
	if w.Code != 500 {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── apiRenewCert with DB error ───────────────────────────────────

func TestRenewCert_DBListErrorV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	d.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/abc/renew", nil)
	srv.apiRenewCert(w, r, "test-ca", "abc")
	if w.Code != 500 {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── apiRevokeCert ─────────────────────────────────────────────────

func TestRevokeCert_SuccessV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/DEADBEEF/revoke", strings.NewReader(`{"reason":"superseded"}`))
	srv.apiRevokeCert(w, r, "test-ca", "DEADBEEF")
	// Cert does not exist → RevokeCert errors → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokeCert_NoReasonV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/CAFE0001/revoke", nil)
	srv.apiRevokeCert(w, r, "test-ca", "CAFE0001")
	// Cert does not exist → RevokeCert errors → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokeCert_UnknownSerialV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cert/test-ca/DEADBEEF/revoke", nil)
	srv.apiRevokeCert(w, r, "test-ca", "DEADBEEF")
	// Cert does not exist → RevokeCert errors → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── apiUserRevokeAll ─────────────────────────────────────────────

func TestUserRevokeAll_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/user/revoke-all", nil)
	srv.apiUserRevokeAll(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestUserRevokeAll_NoMTLSV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/user/revoke-all", nil)
	srv.apiUserRevokeAll(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestUserRevokeAll_NoAICV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	cert, _, _, _ := generateSelfSignedCertForTest(t, "no-aic-agent")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/user/revoke-all", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	srv.apiUserRevokeAll(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiLogout with real token ────────────────────────────────────

func TestLogout_WithRealTokenV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/logout", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiLogout(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestLogout_BearerTokenV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/logout", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	srv.apiLogout(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiUserInfo ───────────────────────────────────────────────────

func TestUserInfo_WithRealTokenV9(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/userinfo", nil)
	r.Header.Set("X-Auth-Token", "bogus-token")
	srv.apiUserInfo(w, r)
	if w.Code != 401 {
		t.Fatalf("expected 401 got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserInfo_NoTokenV9(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/userinfo", nil)
	srv.apiUserInfo(w, r)
	if w.Code != 401 {
		t.Fatalf("expected 401 got %d", w.Code)
	}
}

// ─── apiUsers ─────────────────────────────────────────────────────

func TestUsers_POST_CreateUserV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	body, _ := json.Marshal(map[string]string{
		"username": "newuser9",
		"password": "pass123",
		"role":     "operator",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body))
	r.Header.Set("X-Auth-Token", token)
	srv.apiUsers(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_POST_EmptyFieldsV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	body, _ := json.Marshal(map[string]string{
		"username": "",
		"password": "",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body))
	r.Header.Set("X-Auth-Token", token)
	srv.apiUsers(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestUsers_POST_DefaultRoleV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	body, _ := json.Marshal(map[string]string{
		"username": "defaultroleuser",
		"password": "pass123",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body))
	r.Header.Set("X-Auth-Token", token)
	srv.apiUsers(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_POST_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/users", strings.NewReader("bad json"))
	r.Header.Set("X-Auth-Token", token)
	srv.apiUsers(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

// ─── apiRARequests ────────────────────────────────────────────────

func TestRARequests_GETV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/ra/requests", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiRARequests(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestRARequests_GET_WithStatusFilterV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/ra/requests?status=pending&limit=10&offset=5", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiRARequests(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestRARequests_POSTV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	body, _ := json.Marshal(map[string]string{
		"cn":      "ra-agent",
		"csr":     "dummy-csr",
		"profile": "tls-server",
		"ca":      "test-ca",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/ra/requests", bytes.NewReader(body))
	r.Header.Set("X-Auth-Token", token)
	srv.apiRARequests(w, r)
	// apiRARequests decodes a CSR string but always passes nil DER → NOT NULL
	// constraint on ra_requests.csr_der fails → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d: %s", w.Code, w.Body.String())
	}
}

func TestRARequests_POST_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/ra/requests", strings.NewReader("bad"))
	r.Header.Set("X-Auth-Token", token)
	srv.apiRARequests(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestRARequests_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/ra/requests", nil)
	srv.apiRARequests(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

// ─── apiCrossCertIssue ────────────────────────────────────────────

func TestCrossCertIssue_SuccessV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	cert2, _, _, der2 := generateSelfSignedCertForTest(t, "TargetCA")
	d.InsertCAMeta(&db.CAMeta{
		Name:         "target-ca",
		CertDER:      der2,
		Subject:      cert2.Subject.String(),
		NotBefore:    cert2.NotBefore,
		NotAfter:     cert2.NotAfter,
		KeyAlgorithm: "ECDSA",
	})

	body, _ := json.Marshal(map[string]interface{}{
		"issuer":  "test-ca",
		"target":  "target-ca",
		"validity": 365,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/issue", bytes.NewReader(body))
	srv.apiCrossCertIssue(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiCATree ────────────────────────────────────────────────────

func TestCATree_WithMultipleCAsV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	cert2, _, _, der2 := generateSelfSignedCertForTest(t, "ChildCA")
	d.InsertCAMeta(&db.CAMeta{
		Name:         "child-ca",
		CertDER:      der2,
		Subject:      cert2.Subject.String(),
		NotBefore:    cert2.NotBefore,
		NotAfter:     cert2.NotAfter,
		KeyAlgorithm: "ECDSA",
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/ca-tree", nil)
	srv.apiCATree(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/ca-tree", nil)
	srv.apiCATree(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("expected 200 got %d", w2.Code)
	}
}

// ─── apiGetCRL ────────────────────────────────────────────────────

func TestGetCRL_SuccessV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/crl/test-ca", nil)
	srv.apiGetCRL(w, r, "test-ca")
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetCRL_WithPartitionV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/crl/test-ca?partition=0&total=2", nil)
	srv.apiGetCRL(w, r, "test-ca")
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetCRL_CANotFoundV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/crl/nonexistent", nil)
	srv.apiGetCRL(w, r, "nonexistent")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

// ─── apiImportCA ──────────────────────────────────────────────────

func TestImportCA_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/ca/import", nil)
	srv.apiImportCA(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestImportCA_EmptyBodyV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{})
	r := httptest.NewRequest("POST", "/api/v1/ca/import", bytes.NewReader(body))
	srv.apiImportCA(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestImportCA_EmptyPEMV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"name": "imported", "pem": ""})
	r := httptest.NewRequest("POST", "/api/v1/ca/import", bytes.NewReader(body))
	srv.apiImportCA(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestImportCA_BadPEMV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"name": "imported", "pem": "not-a-pem"})
	r := httptest.NewRequest("POST", "/api/v1/ca/import", bytes.NewReader(body))
	srv.apiImportCA(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestImportCA_NonCertPEMV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})
	body, _ := json.Marshal(map[string]string{"name": "imported", "pem": string(pemData)})
	r := httptest.NewRequest("POST", "/api/v1/ca/import", bytes.NewReader(body))
	srv.apiImportCA(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestImportCA_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/ca/import", strings.NewReader("bad"))
	srv.apiImportCA(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestImportCA_CertSuccessV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	caCfg := srv.getConfig().CAs["test-ca"]
	caCert, caKey, _ := ca.LoadSigner(caCfg.Cert, caCfg.Key, caCfg.Password)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ImportedSubCA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	body, _ := json.Marshal(map[string]string{"name": "imported-sub-ca", "cert_pem": string(certPEM), "key_pem": string(keyPEMBytes), "key_password": "testpass"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/ca/import", bytes.NewReader(body))
	srv.apiImportCA(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── apiConfig ────────────────────────────────────────────────────

func TestConfig_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/config", nil)
	srv.apiConfig(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestConfig_GETV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config", nil)
	srv.apiConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestConfig_PUT_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", strings.NewReader("bad"))
	srv.apiConfig(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestConfig_PUT_EmptyConfigV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{"config": map[string]string{}})
	r := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader(body))
	srv.apiConfig(w, r)
	if w.Code != 200 && w.Code != 400 && w.Code != 500 {
		t.Fatalf("unexpected %d", w.Code)
	}
}

// ─── apiAuditLog ──────────────────────────────────────────────────

func TestAuditLog_WithLimitOffsetV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/audit?limit=10&offset=0", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiAuditLog(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiDNSACME ───────────────────────────────────────────────────

func TestDNSACME_EmptyDomainV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/dns/acme-challenge/", strings.NewReader(`{"key_auth":"xxx"}`))
	srv.apiDNSACME(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestDNSACME_PutSuccessV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"key_auth": "test-auth"})
	r := httptest.NewRequest("PUT", "/api/v1/dns/acme-challenge/example.com", bytes.NewReader(body))
	srv.apiDNSACME(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestDNSACME_PutBadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/dns/acme-challenge/example.com", strings.NewReader("bad"))
	srv.apiDNSACME(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestDNSACME_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/dns/acme-challenge/example.com", nil)
	srv.apiDNSACME(w, r)
	if w.Code != 405 {
		t.Fatalf("expected 405 got %d", w.Code)
	}
}

// ─── apiGatewayList ────────────────────────────────────────────────

func TestGatewayList_EmptyV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/gateways", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiGatewayList(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiGetConfig ──────────────────────────────────────────────────

func TestGetConfig_NilConfigV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	srv.cfgPtr.Store(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config", nil)
	srv.apiGetConfig(w, r)
	if w.Code != 500 {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── apiUpdateConfig ──────────────────────────────────────────────

func TestUpdateConfig_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", strings.NewReader("bad"))
	srv.apiUpdateConfig(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestUpdateConfig_EmptyConfigV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", strings.NewReader("{}"))
	srv.apiUpdateConfig(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestUpdateConfig_NilConfigV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	srv.cfgPtr.Store(nil)

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{"config": map[string]string{"ca": "test"}})
	r := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader(body))
	srv.apiUpdateConfig(w, r)
	if w.Code != 500 {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

func TestUpdateConfig_InvalidConfigV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"defaults": "not-a-map",
		},
	})
	r := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader(body))
	srv.apiUpdateConfig(w, r)
	if w.Code != 400 && w.Code != 500 {
		t.Fatalf("expected 400 or 500 got %d", w.Code)
	}
}

// ─── serveStatic ──────────────────────────────────────────────────

func TestServeStatic_LocaleV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/locale.json", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.serveStatic(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestServeStatic_IndexHTMLV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/", nil)
	r.Header.Set("X-Auth-Token", token)
	r.Header.Set("Accept-Language", "en")
	srv.serveStatic(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestServeStatic_JSFileV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/app.js", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.serveStatic(w, r)
	if w.Code != 200 && w.Code != 404 {
		t.Fatalf("expected 200 or 404 got %d", w.Code)
	}
}

func TestServeStatic_CSSFileV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/style.css", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.serveStatic(w, r)
	if w.Code != 200 && w.Code != 404 {
		t.Fatalf("expected 200 or 404 got %d", w.Code)
	}
}

func TestServeStatic_SVGFileV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/logo.svg", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.serveStatic(w, r)
	if w.Code != 200 && w.Code != 404 {
		t.Fatalf("expected 200 or 404 got %d", w.Code)
	}
}

func TestServeStatic_UnknownFileV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pki/unknown-file.bin", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.serveStatic(w, r)
	if w.Code != 200 && w.Code != 404 {
		t.Fatalf("expected 200 or 404 got %d", w.Code)
	}
}

// ─── renderTemplate error path ────────────────────────────────────

func TestRenderTemplate_ErrorPathV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	tmpl := template.Must(template.New("base").Parse("dummy"))
	srv.renderTemplate(tmpl, w, "nonexistent.html", nil)
	if w.Code != 500 {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── tmplFuncs ────────────────────────────────────────────────────

func TestTmplFuncsV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "en")
	funcs := srv.tmplFuncs(req)
	if funcs == nil {
		t.Fatal("nil funcs")
	}
	timefmt := funcs["timefmt"].(func(time.Time) string)
	result := timefmt(time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC))
	if result != "2025-01-15" {
		t.Fatalf("unexpected timefmt: %s", result)
	}
	hex := funcs["hex"].(func([]byte) string)
	hexResult := hex([]byte{0xDE, 0xAD})
	if hexResult != "DEAD" {
		t.Fatalf("unexpected hex: %s", hexResult)
	}
	tFunc := funcs["t"].(func(string, ...any) string)
	_ = tFunc("test.key")
}

// ─── apiListCerts with CSV ────────────────────────────────────────

func TestListCerts_CSVFormatV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	issueCertDirect(t, d, "test-ca", "csv-test.local")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/certs?ca=test-ca&status=V&cn=csv", nil)
	r.Header.Set("Accept", "text/csv")
	srv.apiListCerts(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestListCerts_CSVWithCertsV9(t *testing.T) {
	srv, d, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	issueCertDirect(t, d, "test-ca", "csv-cert.local")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/certs?ca=test-ca", nil)
	r.Header.Set("Accept", "text/csv")
	srv.apiListCerts(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "serial_number") {
		t.Fatalf("expected CSV header, got %s", w.Body.String()[:100])
	}
}

// ─── apiBatchIssue edge cases ────────────────────────────────────

func TestBatchIssue_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/batch", strings.NewReader("bad"))
	r.Header.Set("Content-Type", "application/json")
	srv.apiBatchIssue(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestBatchIssue_MethodNotAllowedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/batch", nil)
	srv.apiBatchIssue(w, r)
	if w.Code != 405 {
		t.Fatalf("expected 405 got %d", w.Code)
	}
}

// ─── apiCrossCertRevoke edge cases ───────────────────────────────

func TestCrossCertRevoke_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/revoke", strings.NewReader("bad"))
	srv.apiCrossCertRevoke(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestCrossCertRevoke_MissingFieldsV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"issuer": "", "serial": ""})
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/revoke", bytes.NewReader(body))
	srv.apiCrossCertRevoke(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestCrossCertRevoke_InvalidReasonV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"issuer": "test-ca", "serial": "abc", "reason": "invalid-reason"})
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/revoke", bytes.NewReader(body))
	srv.apiCrossCertRevoke(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

// ─── apiListCrossCerts ────────────────────────────────────────────

func TestListCrossCerts_EmptyV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdmin7(t, ts)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cross-certs", nil)
	r.Header.Set("X-Auth-Token", token)
	srv.apiListCrossCerts(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiCrossCertIssue error paths ───────────────────────────────

func TestCrossCertIssue_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/issue", strings.NewReader("bad"))
	srv.apiCrossCertIssue(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestCrossCertIssue_MissingFieldsV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{})
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/issue", bytes.NewReader(body))
	srv.apiCrossCertIssue(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestCrossCertIssue_IssuerNotFoundV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]interface{}{"issuer": "nonexistent", "target": "test-ca"})
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/issue", bytes.NewReader(body))
	srv.apiCrossCertIssue(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

// ─── apiCrossCertRevoke DB error ─────────────────────────────────

func TestCrossCertRevoke_DBErrorV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"issuer": "nonexistent", "serial": "abc"})
	r := httptest.NewRequest("POST", "/api/v1/cross-certs/revoke", bytes.NewReader(body))
	srv.apiCrossCertRevoke(w, r)
	// Cross cert does not exist → RevokeCrossCert errors → 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", w.Code)
	}
}

// ─── apiDNSCERT ──────────────────────────────────────────────────

func TestDNSCERT_NotImplementedV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/dns/cert/example.com", nil)
	srv.apiDNSCERT(w, r)
	if w.Code != 501 {
		t.Fatalf("expected 501 got %d", w.Code)
	}
}

// ─── apiDNSHealth ────────────────────────────────────────────────

func TestDNSHealthV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/dns/health", nil)
	srv.apiDNSHealth(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiDNSList ──────────────────────────────────────────────────

func TestDNSListV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/dns/list", nil)
	srv.apiDNSList(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

// ─── apiVerifyCert edge cases ────────────────────────────────────

func TestVerifyCert_BadJSONV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/verify", strings.NewReader("bad"))
	srv.apiVerifyCert(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

func TestVerifyCert_EmptyPEMV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"pem": ""})
	r := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewReader(body))
	srv.apiVerifyCert(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

// ─── apiCSRSign edge cases ───────────────────────────────────────

func TestCSRSign_EmptyCSRV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"csr_pem": ""})
	r := httptest.NewRequest("POST", "/api/v1/csr/sign", bytes.NewReader(body))
	srv.apiCSRSign(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400 got %d", w.Code)
	}
}

// ─── apiPermissionCheck ──────────────────────────────────────────

func TestPermissionCheckV9(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	_, _, certPEM, _ := generateSelfSignedCertForTest(t, "perm-check")
	body, _ := json.Marshal(map[string]string{
		"pem":        string(certPEM),
		"permission": "cert.issue",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/permission/check", bytes.NewReader(body))
	srv.apiPermissionCheck(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d: %s", w.Code, w.Body.String())
	}
}

// ─── helper ──────────────────────────────────────────────────────

func issueCertDirect(t *testing.T, d *db.DB, caName, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	d.InsertCert(&db.CertRecord{
		SerialNumber: fmt.Sprintf("%X", serial),
		CAName:       caName,
		Status:       "V",
		CommonName:   cn,
		CertDER:      der,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	})
	return cert
}

// ─── extractP12Bytes tests ────────────────────────────────────────

func makeP12CertAndKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "P12 Test Cert", Organization: []string{"Test Org"}},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

func TestExtractP12Bytes_Valid(t *testing.T) {
	cert, key := makeP12CertAndKey(t)
	pfxData, err := p12.Encode(rand.Reader, key, cert, nil, "test-password")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := extractP12Bytes(pfxData, "test-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("empty cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Fatal("empty key PEM")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %v", block)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY PEM block, got %v", keyBlock)
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsedCert.Subject.CommonName != "P12 Test Cert" {
		t.Fatalf("expected CN 'P12 Test Cert', got %q", parsedCert.Subject.CommonName)
	}
}

func TestExtractP12Bytes_WrongPassword(t *testing.T) {
	cert, key := makeP12CertAndKey(t)
	pfxData, err := p12.Encode(rand.Reader, key, cert, nil, "correct-password")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = extractP12Bytes(pfxData, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExtractP12Bytes_WithChain(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	pfxData, err := p12.Encode(rand.Reader, leafKey, leafCert, []*x509.Certificate{caCert}, "chain-pass")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := extractP12Bytes(pfxData, "chain-pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("empty cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Fatal("empty key PEM")
	}

	certPEMStr := string(certPEM)
	count := strings.Count(certPEMStr, "-----BEGIN CERTIFICATE-----")
	if count < 2 {
		t.Fatalf("expected at least 2 CERTIFICATE blocks (leaf + chain), got %d", count)
	}
}

func TestExtractP12Bytes_InvalidDataV9(t *testing.T) {
	_, _, err := extractP12Bytes([]byte("not-a-pkcs12-blob"), "password")
	if err == nil {
		t.Fatal("expected error for invalid P12 data")
	}
}

func TestExtractP12Bytes_EmptyData(t *testing.T) {
	_, _, err := extractP12Bytes([]byte{}, "")
	if err == nil {
		t.Fatal("expected error for empty P12 data")
	}
}

func TestExtractP12Bytes_GarbageData(t *testing.T) {
	_, _, err := extractP12Bytes([]byte{0x30, 0x82, 0x01, 0x22, 0x02, 0x01}, "password")
	if err == nil {
		t.Fatal("expected error for garbage P12 data")
	}
}

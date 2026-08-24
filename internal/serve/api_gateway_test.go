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
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/i18n"
)

var testBundleGateway = i18n.NewBundle()

func newGatewayTestDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newGatewayTestServer(t *testing.T, d *db.DB) *Server {
	t.Helper()
	cfg := &internal.Config{}
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return NewFull(cfg, d, testBundleGateway, dummyHandler, dummyHandler)
}

func genTestTLSCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	return genTestTLSCertWithOU(t, cn, "")
}

func genTestTLSCertWithOU(t *testing.T, cn, ou string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	// Add a PA extension so authFromCert passes cert-first check (fail-closed without PA).
	paExt, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{
		Grants: []ca.Capability{{SchemeId: "admin", CapabilityId: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tmpl.ExtraExtensions = []pkix.Extension{paExt}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func TestAPIGatewayRegister_RequiresMTLS(t *testing.T) {
	d := newGatewayTestDB(t)
	s := newGatewayTestServer(t, d)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/register",
		bytes.NewReader([]byte(`{"address":"gw1:8443"}`)))
	w := httptest.NewRecorder()
	s.apiGatewayRegister(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIGatewayRegister_Success(t *testing.T) {
	d := newGatewayTestDB(t)
	s := newGatewayTestServer(t, d)
	tlsCert := genTestTLSCertWithOU(t, "gateway-bot", "SuperAdmin")
	caPool := x509.NewCertPool()
	caPool.AddCert(tlsCert.Leaf)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	ts.StartTLS()
	defer ts.Close()

	addr := ts.URL[len("https://"):]

	body := bytes.NewReader([]byte(`{"address":"` + addr + `","ca_name":"test-ca"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/register", body)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{tlsCert.Leaf},
	}
	w := httptest.NewRecorder()
	s.apiGatewayRegister(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	gw, err := d.GetGateway(addr)
	if err != nil {
		t.Fatalf("GetGateway: %v", err)
	}
	if gw.CaName != "test-ca" {
		t.Fatalf("expected ca_name test-ca, got %s", gw.CaName)
	}
}

func TestAPIGatewayRegister_EmptyAddress(t *testing.T) {
	d := newGatewayTestDB(t)
	s := newGatewayTestServer(t, d)
	tlsCert := genTestTLSCertWithOU(t, "gw", "SuperAdmin")
	body := bytes.NewReader([]byte(`{}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/register", body)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tlsCert.Leaf}}
	w := httptest.NewRecorder()
	s.apiGatewayRegister(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAPIGatewayHeartbeat_Success(t *testing.T) {
	d := newGatewayTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	s := newGatewayTestServer(t, d)
	tlsCert := genTestTLSCertWithOU(t, "gw", "SuperAdmin")
	body := bytes.NewReader([]byte(`{"address":"gw1:8443"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/heartbeat", body)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tlsCert.Leaf}}
	w := httptest.NewRecorder()
	s.apiGatewayHeartbeat(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIGatewayHeartbeat_NotFound(t *testing.T) {
	d := newGatewayTestDB(t)
	s := newGatewayTestServer(t, d)
	tlsCert := genTestTLSCertWithOU(t, "gw", "SuperAdmin")
	body := bytes.NewReader([]byte(`{"address":"nonexistent:8443"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/heartbeat", body)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tlsCert.Leaf}}
	w := httptest.NewRecorder()
	s.apiGatewayHeartbeat(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAPIGatewayList_Success(t *testing.T) {
	d := newGatewayTestDB(t)
	d.RegisterGateway("gw1:8443", "ca-a")
	d.RegisterGateway("gw2:8443", "ca-b")
	s := newGatewayTestServer(t, d)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/list", nil)
	w := httptest.NewRecorder()
	s.apiGatewayList(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 2 {
		t.Fatalf("expected count 2, got %v", resp["count"])
	}
}

func TestAPIGatewayDisconnectUser_MethodCheck(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/disconnect-user", nil)
	w := httptest.NewRecorder()
	s.apiGatewayDisconnectUser(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAPIGatewayDisconnectAgent_MethodCheck(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/disconnect-agent", nil)
	w := httptest.NewRecorder()
	s.apiGatewayDisconnectAgent(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

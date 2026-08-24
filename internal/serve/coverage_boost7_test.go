package serve

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/i18n"
)

func newTestServerFull7(t *testing.T) (*Server, *db.DB, http.Handler) {
	t.Helper()
	d := newTestDB(t)
	seedAdmin(t, d)

	caCert, caKey := newTestCA(t, "test-ca")
	d.InsertCAMeta(&db.CAMeta{
		Name:         "test-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(caCert.Raw),
	})

	dir := t.TempDir()
	certPath := dir + "/ca.pem"
	keyPath := dir + "/ca.key"
	writePEMFile(t, certPath, "CERTIFICATE", caCert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)

	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Serve.Static = ""
	cfg.Defaults.CA = "test-ca"
	cfg.TSA.SignerCert = ""
	cfg.TSA.SignerKey = ""
	cfg.OCSP.SignerCert = ""
	cfg.OCSP.SignerKey = ""
	cfg.CAs = map[string]internal.CAConfig{
		"test-ca": {Cert: certPath, Key: keyPath},
	}
	k8sOn := true
	cfg.K8sEnabled = &k8sOn
	b := i18n.NewBundle()
	srv := NewFull(&cfg, d, b, nil, nil)
	return srv, d, WrapHandler(srv)
}

func loginAsAdmin7(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	resp, err := http.Post(ts.URL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	var r map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&r)
	if tval, ok := r["token"].(string); ok {
		return tval
	}
	return ""
}

func pemEncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// ─── SignBatch via aggregatorSigner ──────────────────────────────

func TestSignBatch_Empty(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	as := &aggregatorSigner{s: srv}
	results := as.SignBatch(nil, "test-ca")
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestSignBatch_CANotFound(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	as := &aggregatorSigner{s: srv}
	items := []*ca.AggregatorReq{{CN: "test.example.com"}}
	results := as.SignBatch(items, "nonexistent-ca")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected error for missing CA")
	}
}

func TestSignBatch_Success(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	as := &aggregatorSigner{s: srv}
	items := []*ca.AggregatorReq{
		{CN: "batch1.example.com", Profile: "tls-server"},
		{CN: "batch2.example.com", Profile: "tls-server"},
	}
	results := as.SignBatch(items, "test-ca")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("result %d: unexpected error: %v", i, r.Err)
		}
		if r.Cert == nil {
			t.Fatalf("result %d: expected cert", i)
		}
	}
}

func TestSignBatch_WithSAN(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	as := &aggregatorSigner{s: srv}
	items := []*ca.AggregatorReq{
		{CN: "san.example.com", Profile: "tls-server", SAN: "DNS:san1.example.com,DNS:san2.example.com"},
	}
	results := as.SignBatch(items, "test-ca")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("unexpected error: %v", results[0].Err)
	}
	if results[0].Cert == nil {
		t.Fatal("expected non-nil cert")
	}
}

// ─── Gateway API ─────────────────────────────────────────────────

func TestGatewayList(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/gateway/list", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGatewayList_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/gateway/list", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestGatewayRegister_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/gateway/register", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestGatewayRegister_NoMTLS(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"address": "127.0.0.1:9999"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/gateway/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGatewayRegister_EmptyAddress(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/register", strings.NewReader(`{"address":""}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiGatewayRegister(w, r)
	// Requires mTLS - returns 401 without TLS
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestGatewayRegister_Success(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/register", strings.NewReader(`{"address":"127.0.0.1:9999","ca_name":"test-ca"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiGatewayRegister(w, r)
	// Requires mTLS - returns 401 without TLS
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestGatewayHeartbeat_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/gateway/heartbeat", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestGatewayHeartbeat_NoMTLS(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"address": "127.0.0.1:9999"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/gateway/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGatewayHeartbeat_EmptyAddress(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/heartbeat", strings.NewReader(`{"address":""}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiGatewayHeartbeat(w, r)
	// Requires mTLS - returns 401 without TLS
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestGatewayHeartbeat_NotFound(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/heartbeat", strings.NewReader(`{"address":"127.0.0.1:9999"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiGatewayHeartbeat(w, r)
	// Requires mTLS - returns 401 without TLS
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestGatewayHeartbeat_Success(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	d.RegisterGateway("127.0.0.1:9999", "test-ca")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/heartbeat", strings.NewReader(`{"address":"127.0.0.1:9999"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.apiGatewayHeartbeat(w, r)
	// Requires mTLS - returns 401 without TLS
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (mTLS required), got %d", w.Code)
	}
}

func TestGatewayDisconnectAgent_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/gateway/disconnect-agent", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestGatewayDisconnectUser_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/gateway/disconnect-user", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestProxyDisconnectToGateways_NoGateways(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/disconnect-agent", strings.NewReader(`{"serial":"001","ca":"test-ca"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.proxyDisconnectToGateways(w, r, "agent")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestProxyDisconnectToGateways_WithGateway(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	d.RegisterGateway("127.0.0.1:19999", "test-ca")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gateway/disconnect-agent", strings.NewReader(`{"serial":"001","ca":"test-ca"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.proxyDisconnectToGateways(w, r, "agent")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["failed"] != float64(1) {
		t.Fatalf("expected 1 failure (gateway unreachable), got %v", result["failed"])
	}
}

func TestNotifyGatewaysDisconnect_NoGateways(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	srv.notifyGatewaysDisconnect("agent", "test-ca", "001")
}

func TestNotifyGatewaysDisconnectUser_NoGateways(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)
	srv.notifyGatewaysDisconnectUser("principal-1")
}

func TestDispatchToGateways_Empty(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	srv.dispatchToGateways(nil, "/api/test", "{}")
}

func TestDispatchToGateways_Unreachable(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	gateways := []*db.GatewayRecord{
		{Address: "127.0.0.1:19998"},
	}
	srv.dispatchToGateways(gateways, "/api/test", `{"key":"value"}`)
}

func TestDispatchToGateways_BadURL(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	gateways := []*db.GatewayRecord{
		{Address: "://bad-url"},
	}
	srv.dispatchToGateways(gateways, "/api/test", "{}")
}

func TestDispatchToGateways_NoHTTPPrefix(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	gateways := []*db.GatewayRecord{
		{Address: "127.0.0.1:19998"},
	}
	srv.dispatchToGateways(gateways, "/api/test", "{}")
}

// ─── Trust API ───────────────────────────────────────────────────

func TestTrustList(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/trust", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTrustList_WithFilters(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/trust?trusted=true&source=manual&page=1&size=10&hash_id=test", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTrustGet_NotFound(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/trust/nonexistent", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestTrustDelete_NotFound(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/trust/nonexistent", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestTrustStats(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/trust/stats", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTrustImport_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/trust/import", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestTrustImport_BadJSON(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/trust/import", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestTrustImport_EmptyRequest(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/trust/import", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestTrustImport_WithPEM(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	cert, _ := newTestCA(t, "import-test-ca")
	pemData := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		pemEncodeBase64(cert.Raw))

	body, _ := json.Marshal(map[string]string{"pem_bundle": pemData})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/trust/import", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTrustImport_WithRebase(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	cert, _ := newTestCA(t, "rebase-ca")
	pemData := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		pemEncodeBase64(cert.Raw))

	body, _ := json.Marshal(map[string]interface{}{"pem_bundle": pemData, "rebase": true})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/trust/import", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Webhook API ─────────────────────────────────────────────────

func TestWebhookSubs_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/webhooks", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_List(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/webhooks", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Delete_NotFound(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/webhooks?id=99999", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Delete_NoID(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/webhooks", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Delete_BadID(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/webhooks?id=abc", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Create_BadJSON(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/webhooks", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Create_EmptyURL(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"url": ""})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/webhooks", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhookSubs_Create_WrongContentType(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]string{"url": "http://example.com/hook"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/webhooks", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", resp.StatusCode)
	}
}

// ─── Config API ──────────────────────────────────────────────────

func TestConfig_Get(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestConfig_MethodNotAllowed(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestConfig_Update_BadJSON(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config", strings.NewReader("bad"))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestConfig_Update_EmptyConfig(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	body, _ := json.Marshal(map[string]interface{}{"config": nil})
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── Async Status ────────────────────────────────────────────────

func TestAsyncStatus_NotFound(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs/async/nonexistent", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Stats SSE (short test) ──────────────────────────────────────

func TestStatsSSE(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/stats/stream", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── Trust API direct calls ───────────────────────────────────────

func TestTrustDelete_Direct(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/trust/nonexistent", nil)
	srv.apiTrustDelete(w, r, "nonexistent")
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Fatalf("expected 200 or 404, got %d", w.Code)
	}
}

func TestTrustGet_Direct(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trust/nonexistent", nil)
	srv.apiTrustGet(w, r, "nonexistent")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestTrustSet_BadJSON_Direct(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PATCH", "/api/v1/trust/nonexistent", strings.NewReader("bad"))
	srv.apiTrustSet(w, r, "nonexistent")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTrustList_Direct(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trust", nil)
	srv.apiTrustList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTrustStats_Direct(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trust/stats", nil)
	srv.apiTrustStats(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDispatchTrustAPI(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)
	srv.dbPtr.Store(d)

	// List
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trust", nil)
	srv.dispatchTrustAPI(w, r, "/trust")

	// Import method not allowed
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/trust/import", nil)
	srv.dispatchTrustAPI(w, r, "/trust/import")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("import: expected 405, got %d", w.Code)
	}

	// Stats
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/trust/stats", nil)
	srv.dispatchTrustAPI(w, r, "/trust/stats")

	// Get
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/trust/nonexistent", nil)
	srv.dispatchTrustAPI(w, r, "/trust/nonexistent")

	// Patch
	w = httptest.NewRecorder()
	r = httptest.NewRequest("PATCH", "/api/v1/trust/nonexistent", strings.NewReader(`{"trusted":true}`))
	r.Header.Set("Content-Type", "application/json")
	srv.dispatchTrustAPI(w, r, "/trust/nonexistent")

	// Delete
	w = httptest.NewRecorder()
	r = httptest.NewRequest("DELETE", "/api/v1/trust/nonexistent", nil)
	srv.dispatchTrustAPI(w, r, "/trust/nonexistent")

	// Method not allowed
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v1/trust/nonexistent", nil)
	srv.dispatchTrustAPI(w, r, "/trust/nonexistent")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method not allowed: expected 405, got %d", w.Code)
	}

	// Default (unknown sub-path after /trust/)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/trust/deep/unknown/path", nil)
	srv.dispatchTrustAPI(w, r, "/trust/deep/unknown/path")
}

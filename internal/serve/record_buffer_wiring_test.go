package serve

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func TestRecordWALPath(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
	}{
		{"/var/lib/pki/pki.db", "/var/lib/pki/pki-records.wal"},
		{"/etc/varwof/core/pki.db", "/etc/varwof/core/pki-records.wal"},
		{"/tmp/db", "/tmp/db-records.wal"},
		{"", ""},
		{":memory:", ""},
		{"file:test.db?cache=shared", ""},
		{"postgres://user@host/db", ""},
		{"mysql://user@host/db", ""},
		{"/data/PKI.DB", "/data/PKI-records.wal"},
	}
	for _, c := range cases {
		if got := recordWALPath(c.dsn); got != c.want {
			t.Errorf("recordWALPath(%q) = %q, want %q", c.dsn, got, c.want)
		}
	}
}

func newTestServerWithBuffer(t *testing.T) (*Server, *db.DB, http.Handler) {
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
	keyDER, _ := x509MarshalPKCS8PrivateKey(caKey)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)

	cfg := internal.DefaultConfig()
	cfg.DB = filepath.Join(t.TempDir(), "pki.db")
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
	srv := NewFull(&cfg, d, testBundle, nil, nil)
	if err := srv.EnableRecordBuffer(&cfg); err != nil {
		t.Fatalf("EnableRecordBuffer: %v", err)
	}
	t.Cleanup(srv.StopRecordBuffer)
	return srv, d, WrapHandler(srv)
}

func loginAsAdminWiring(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r map[string]any
	json.NewDecoder(resp.Body).Decode(&r)
	if tok, ok := r["token"].(string); ok {
		return tok
	}
	return ""
}

// TestIssueCertBuffered verifies single issuance API in RecordBuffer mode:
//  1. Request returns immediately (does not wait for fsync DB write)
//  2. Cert record is flushed to DB in background (≤500ms latency)
//  3. Before flush, record does not exist in DB (proving SkipDB buffered path)
func TestIssueCertBuffered(t *testing.T) {
	srv, d, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	body, _ := json.Marshal(map[string]any{
		"cn":      "buffered.example.com",
		"ca":      "test-ca",
		"profile": "tls-server",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue failed: %d", resp.StatusCode)
	}

	// Request succeeded immediately; record is still in buffer, not yet synced to DB.
	if srv.recordBuffer == nil {
		t.Fatal("recordBuffer not enabled")
	}
	if got := srv.recordBuffer.pending.Load(); got != 1 {
		t.Fatalf("pending = %d, want 1 (record should be buffered, not in DB yet)", got)
	}
	n, _ := d.CountCertsByCA("test-ca", "")
	if n != 0 {
		t.Fatalf("record written synchronously (%d) despite buffered mode", n)
	}

	// Background flusher should flush to DB within maxLatency (500ms).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := d.CountCertsByCA("test-ca", ""); n == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("buffered record never flushed to DB within 3s")
}

// TestCSRSignBuffered verifies POST /api/v1/csr/sign also uses the SkipDB buffered
// path in RecordBuffer mode: request returns immediately, record enters buffer
// (no synchronous DB write), background flush.
func TestCSRSignBuffered(t *testing.T) {
	srv, d, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	body, _ := json.Marshal(map[string]any{
		"ca":       "test-ca",
		"profile":  "tls-server",
		"csr_pem":  createCSRPemForTest(t, "buffered-csr.example.com"),
		"validity": 1,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/csr/sign", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("csr/sign failed: %d", resp.StatusCode)
	}

	if srv.recordBuffer == nil {
		t.Fatal("recordBuffer not enabled")
	}
	if got := srv.recordBuffer.pending.Load(); got != 1 {
		t.Fatalf("pending = %d, want 1 (record should be buffered, not in DB yet)", got)
	}
	n, _ := d.CountCertsByCA("test-ca", "")
	if n != 0 {
		t.Fatalf("record written synchronously (%d) despite buffered mode", n)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := d.CountCertsByCA("test-ca", ""); n == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("buffered record never flushed to DB within 3s")
}

// TestRevokeFlushesBufferBeforeUpdate verifies the revoke API can succeed even when
// the issued record is still buffered (not persisted): revoke flushes the buffer
// first, ensuring the record is in DB before UPDATE, preventing the ≤500ms
// visibility window from causing "not found".
func TestRevokeFlushesBufferBeforeUpdate(t *testing.T) {
	srv, d, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	// 1. Issue one cert (enters buffer, not persisted to DB)
	body, _ := json.Marshal(map[string]any{
		"cn":      "revoke-buffered.example.com",
		"ca":      "test-ca",
		"profile": "tls-server",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var issue struct {
		SerialNumber string `json:"serial_number"`
		CommonName   string `json:"common_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue failed: %d", resp.StatusCode)
	}
	if issue.SerialNumber == "" {
		t.Fatal("no serial returned")
	}
	// Confirm still buffered, not visible in DB
	if got := srv.recordBuffer.pending.Load(); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}
	if n, _ := d.CountCertsByCA("test-ca", ""); n != 0 {
		t.Fatalf("record should still be buffered, DB count = %d", n)
	}

	// 2. Revoke immediately (without waiting for buffer auto-flush)
	revReq, _ := http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+issue.SerialNumber+"/revoke", nil)
	revReq.Header.Set("X-Auth-Token", token)
	revResp, err := http.DefaultClient.Do(revReq)
	if err != nil {
		t.Fatal(err)
	}
	revBody, _ := io.ReadAll(revResp.Body)
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke failed: %d body=%s", revResp.StatusCode, string(revBody))
	}

	// 3. Revocation should persist record to DB with status R
	rec, err := d.GetCert("test-ca", issue.SerialNumber)
	if err != nil {
		t.Fatalf("cert not in DB after revoke flush: %v", err)
	}
	if rec.Status != "R" {
		t.Fatalf("status = %q, want R", rec.Status)
	}
}

// TestRenewFlushesBufferBeforeLookup verifies the renew API can find the source cert
// even when the issued record is still buffered (not persisted): renew flushes the
// buffer first, preventing the ≤500ms visibility window from causing
// "Certificate not found".
func TestRenewFlushesBufferBeforeLookup(t *testing.T) {
	srv, d, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	// 1. Issue one cert (enters buffer, not persisted to DB)
	body, _ := json.Marshal(map[string]any{
		"cn":      "renew-buffered.example.com",
		"ca":      "test-ca",
		"profile": "tls-server",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var issue struct {
		SerialNumber string `json:"serial_number"`
		CommonName   string `json:"common_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue failed: %d", resp.StatusCode)
	}
	if issue.SerialNumber == "" {
		t.Fatal("no serial returned")
	}
	if got := srv.recordBuffer.pending.Load(); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}

	// 2. Renew immediately (without waiting for buffer auto-flush) — renew should find source cert after internal flush
	renReq, _ := http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+issue.SerialNumber+"/renew", nil)
	renReq.Header.Set("X-Auth-Token", token)
	renResp, err := http.DefaultClient.Do(renReq)
	if err != nil {
		t.Fatal(err)
	}
	renBody, _ := io.ReadAll(renResp.Body)
	renResp.Body.Close()
	if renResp.StatusCode != http.StatusOK {
		t.Fatalf("renew failed: %d body=%s", renResp.StatusCode, string(renBody))
	}
	var renewed struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := json.Unmarshal(renBody, &renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.SerialNumber == "" || renewed.SerialNumber == issue.SerialNumber {
		t.Fatalf("renew should return a new serial, got %q", renewed.SerialNumber)
	}

	// 3. Source cert has been persisted
	if _, err := d.GetCert("test-ca", issue.SerialNumber); err != nil {
		t.Fatalf("source cert not in DB after renew flush: %v", err)
	}
}
func TestRecordBufferBackpressure(t *testing.T) {
	d := newTestDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 10, 1, 50*time.Millisecond, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if !rb.Add(&db.CertRecord{SerialNumber: "1"}) {
		t.Fatal("first Add should succeed")
	}
	if rb.Add(&db.CertRecord{SerialNumber: "2"}) {
		t.Fatal("second Add should be rejected when maxPending is reached")
	}
	if !rb.IsFull() {
		t.Fatal("IsFull should report full")
	}
}

func TestRecordBufferBackpressureDisabled(t *testing.T) {
	d := newTestDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 10, 0, 50*time.Millisecond, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if !rb.Add(&db.CertRecord{SerialNumber: "1"}) {
		t.Fatal("first Add should succeed with maxPending=0")
	}
	if !rb.Add(&db.CertRecord{SerialNumber: "2"}) {
		t.Fatal("second Add should succeed with maxPending=0 (backpressure disabled)")
	}
	if rb.IsFull() {
		t.Fatal("IsFull should report not-full with maxPending=0")
	}
}

func TestEnableRecordBufferFromConfig(t *testing.T) {
	srv, _, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	defer srv.StopRecordBuffer()

	if srv.recordBuffer == nil {
		t.Fatal("recordBuffer should be enabled")
	}
	if srv.recordBuffer.maxPending != defaultMaxPending {
		t.Fatalf("maxPending = %d, want default %d (config not set should use default)",
			srv.recordBuffer.maxPending, defaultMaxPending)
	}
}

func TestEnableRecordBufferMaxPendingZeroDisablesBackpressure(t *testing.T) {
	srv, _, h := newTestServerWithBuffer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	defer srv.StopRecordBuffer()

	cfg := internal.DefaultConfig()
	cfg.DB = filepath.Join(t.TempDir(), "pki.db")
	zero := 0
	cfg.RecordBuffer.MaxPending = &zero
	if err := srv.EnableRecordBuffer(&cfg); err != nil {
		t.Fatalf("EnableRecordBuffer: %v", err)
	}

	if srv.recordBuffer.maxPending != 0 {
		t.Fatalf("maxPending = %d, want 0 (backpressure disabled)", srv.recordBuffer.maxPending)
	}
	if srv.recordBuffer.IsFull() {
		t.Fatal("IsFull should report not-full when backpressure disabled")
	}
	if !srv.recordBuffer.Add(&db.CertRecord{SerialNumber: "1"}) {
		t.Fatal("Add should succeed with backpressure disabled")
	}
}


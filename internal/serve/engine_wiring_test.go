// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

func loginAsWiring(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
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

func loginAsSuperadminWiring(t *testing.T, ts *httptest.Server) string {
	return loginAsWiring(t, ts, "superadmin", "superadmin")
}

// newTestServerWithEngine builds a full server with the memory engine enabled
// (and the standalone recordBuffer stopped, since the engine owns the write
// pipeline).
func newTestServerWithEngine(t *testing.T) (*Server, *db.DB, http.Handler) {
	t.Helper()
	srv, d, _ := newTestServerWithBuffer(t) // sets up CA + admin seed
	if err := srv.EnableEngine(defaultEngineConfig(t)); err != nil {
		t.Fatalf("EnableEngine: %v", err)
	}
	t.Cleanup(srv.StopEngine)
	if srv.recordBuffer != nil {
		t.Fatal("recordBuffer should be stopped when the engine is enabled")
	}
	return srv, d, WrapHandler(srv)
}

// newTestServerWithEngineCA returns an in-memory engine test server with its CA cert/key
// (used by C3 real-signature agent-proxy issuance requests).
func newTestServerWithEngineCA(t *testing.T) (*Server, http.Handler, *x509.Certificate, crypto.Signer) {
	t.Helper()
	srv, h, caCert, caKey := newTestServerWithCA(t)
	if err := srv.EnableEngine(defaultEngineConfig(t)); err != nil {
		t.Fatalf("EnableEngine: %v", err)
	}
	t.Cleanup(srv.StopEngine)
	return srv, h, caCert, caKey
}

func defaultEngineConfig(t *testing.T) *internal.Config {
	t.Helper()
	cfg := internal.DefaultConfig()
	cfg.DB = filepath.Join(t.TempDir(), "pki.db")
	cfg.Engine = &internal.EngineConfig{
		MaxCerts: 10000,
	}
	return &cfg
}

// TestEngineIssueCertInMemory verifies single issuance in in-memory engine mode:
//  1. Issuance is immediately visible in the engine index (memory authoritative)
//  2. Background async DB write (record appears in DB within write pipeline maxLatency)
func TestEngineIssueCertInMemory(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	body, _ := json.Marshal(map[string]any{
		"cn":      "engine.example.com",
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
	defer resp.Body.Close()
	var issueResp struct {
		SerialNumber string `json:"serial_number"`
	}
	json.NewDecoder(resp.Body).Decode(&issueResp)
	if resp.StatusCode != http.StatusOK || issueResp.SerialNumber == "" {
		t.Fatalf("issue failed: %d serial=%q", resp.StatusCode, issueResp.SerialNumber)
	}

	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}
	st, err := e.GetCertStatus("test-ca", issueResp.SerialNumber)
	if err != nil {
		t.Fatalf("engine status lookup: %v", err)
	}
	if st.Status != "V" {
		t.Fatalf("engine status = %q, want V (memory-authoritative before DB flush)", st.Status)
	}

	// Async DB write: the write pipeline should flush the record to DB within ~writeMaxLatency.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := d.CountCertsByCA("test-ca", ""); n == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("engine-issued record never flushed to DB within 5s")
}

// TestEngineRevokeCascadeInMemory verifies revocation in engine mode:
//  1. Revocation is immediately visible in the engine index
//  2. Main cert + agent cert with same PrincipalUid are cascade-revoked
func TestEngineRevokeCascadeInMemory(t *testing.T) {
	srv, _, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}

	// Insert two records directly via engine (simulating agent issuance path writing to engine index).
	recs := []*db.CertRecord{
		{
			SerialNumber: "AAAA00000000000000000000000000000000000001",
			CAName:       "test-ca",
			Status:       "V",
			CommonName:   "zhangsan",
			PrincipalUid: "zhangsan@example.com",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			CertDER:      []byte("cert1"),
		},
		{
			SerialNumber: "AAAA00000000000000000000000000000000000002",
			CAName:       "test-ca",
			Status:       "V",
			CommonName:   "zhangsan-agent",
			PrincipalUid: "zhangsan@example.com",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			CertDER:      []byte("cert2"),
		},
	}
	for _, rec := range recs {
		if err := e.IssueCert(rec); err != nil {
			t.Fatalf("engine issue: %v", err)
		}
	}

	// Revoke main cert via API (engine mode uses engine + cascade).
	body, _ := json.Marshal(map[string]any{"reason": "superseded"})
	req, _ := http.NewRequest("POST",
		ts.URL+"/api/v1/cert/test-ca/"+recs[0].SerialNumber+"/revoke",
		bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke failed: %d", resp.StatusCode)
	}

	// Both main cert and agent cert should be immediately set to R in the engine index.
	st1, err := e.GetCertStatus("test-ca", recs[0].SerialNumber)
	if err != nil {
		t.Fatalf("engine status main: %v", err)
	}
	if st1.Status != "R" {
		t.Fatalf("main cert status = %q, want R", st1.Status)
	}
	st2, err := e.GetCertStatus("test-ca", recs[1].SerialNumber)
	if err != nil {
		t.Fatalf("engine status cascade: %v", err)
	}
	if st2.Status != "R" {
		t.Fatalf("cascade cert status = %q, want R", st2.Status)
	}
}

// TestEngineRevokeByPrincipal verifies batch revocation by PrincipalUid in engine mode.
func TestEngineRevokeByPrincipal(t *testing.T) {
	srv, _, h := newTestServerWithEngine(t)
	fx := newMTLSSuperAdminFixture(t, h, "user:revoke-all")

	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}

	for i := 0; i < 3; i++ {
		serial := "BBBB0000000000000000000000000000000000000" + string(rune('1'+i))
		if err := e.IssueCert(&db.CertRecord{
			SerialNumber: serial,
			CAName:       "test-ca",
			Status:       "V",
			CommonName:   "lisi",
			PrincipalUid: "lisi@example.com",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			CertDER:      []byte("cert"),
		}); err != nil {
			t.Fatalf("engine issue: %v", err)
		}
	}

	body, _ := json.Marshal(map[string]any{"principal_uid": "lisi@example.com", "reason": "keyCompromise"})
	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/certs/revoke-by-principal", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	var revokeResp struct {
		RevokedCount int `json:"revoked_count"`
	}
	json.NewDecoder(resp.Body).Decode(&revokeResp)
	if resp.StatusCode != http.StatusOK || revokeResp.RevokedCount != 3 {
		t.Fatalf("revoke-by-principal: status=%d count=%d, want 200/3", resp.StatusCode, revokeResp.RevokedCount)
	}

	if m := e.Metrics(); m.RevokedSetSize != 3 {
		t.Fatalf("engine revoked set = %d, want 3", m.RevokedSetSize)
	}
}

// TestEngineRevokeDBOnlyCertFallback verifies the E01 fix: revoking a cert not in
// the in-memory index (e.g. issued by CLI while engine was stopped, or directly
// written by external tools) must succeed via DB fallback instead of returning 500.
func TestEngineRevokeDBOnlyCertFallback(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}

	// Simulate out-of-band write: bypass engine and write directly to DB (e.g. CLI direct write, external tool).
	serial := "CCCC00000000000000000000000000000000000042"
	rec := &db.CertRecord{
		SerialNumber: serial,
		CAName:       "test-ca",
		Status:       "V",
		CommonName:   "oob.example.com",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		CertDER:      []byte("oob-cert"),
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatalf("db insert (out-of-band): %v", err)
	}

	// The engine in-memory index should not contain this record.
	if _, err := e.GetCert("test-ca", serial); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("engine should not have out-of-band cert, got err=%v", err)
	}

	body, _ := json.Marshal(map[string]any{"reason": "keyCompromise"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+serial+"/revoke",
		bytes.NewReader(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke of DB-only cert failed: %d (want 200 via DB fallback)", resp.StatusCode)
	}

	st, err := d.GetCertStatus("test-ca", serial)
	if err != nil {
		t.Fatalf("db status: %v", err)
	}
	if st.Status != "R" {
		t.Fatalf("DB status = %q, want R after fallback revoke", st.Status)
	}
}

// TestEngineRenewCertEntersEngine verifies the E01 fix: when the engine is enabled,
// renewed certs must enter the engine index (memory authoritative) so subsequent
// revocations hit the engine instead of falling back to DB.
func TestEngineRenewCertEntersEngine(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}

	// First issue a source cert (memory authoritative, async DB write).
	body, _ := json.Marshal(map[string]any{
		"cn":      "renew-source.example.com",
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
	var src struct {
		SerialNumber string `json:"serial_number"`
	}
	json.NewDecoder(resp.Body).Decode(&src)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || src.SerialNumber == "" {
		t.Fatalf("source issue failed: %d", resp.StatusCode)
	}
	// Wait for source cert to be persisted (renew's ListCerts reads from DB).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := d.CountCertsByCA("test-ca", ""); n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Renew: should enter the engine index via addCertRecord.
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+src.SerialNumber+"/renew",
		strings.NewReader(`{}`))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var rn struct {
		SerialNumber string `json:"serial_number"`
	}
	json.NewDecoder(resp.Body).Decode(&rn)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rn.SerialNumber == "" {
		t.Fatalf("renew failed: %d serial=%q", resp.StatusCode, rn.SerialNumber)
	}

	// The new cert must be visible in the engine index (previously renew bypassed engine → revocation would miss).
	if _, err := e.GetCert("test-ca", rn.SerialNumber); err != nil {
		t.Fatalf("renewed cert not in engine index: %v", err)
	}

	// Revoke the renewed cert: must hit the engine, must not fallback.
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+rn.SerialNumber+"/revoke",
		strings.NewReader(`{"reason":"superseded"}`))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke of renewed cert failed: %d (engine should hit in memory)", resp.StatusCode)
	}
	st, err := e.GetCertStatus("test-ca", rn.SerialNumber)
	if err != nil {
		t.Fatalf("engine status of renewed cert: %v", err)
	}
	if st.Status != "R" {
		t.Fatalf("renewed cert engine status = %q, want R", st.Status)
	}
}

// TestDANonceReplayEngineBacked verifies DA nonce replay prevention in in-memory
// engine mode: a second issuance with the same nonce returns 403, and the engine
// index records the nonce.
func TestDANonceReplayEngineBacked(t *testing.T) {
	srv, h, caCert, caKey := newTestServerWithEngineCA(t)
	d := srv.getDB()
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	fixedNonce := []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0}
	body, _ := agentProxyC3BodyAt(t, caCert, caKey, "engine-replay-agent", "engine-replay-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now(), fixedNonce)

	do := func() *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := do()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first issue: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}
	nonce := fixedNonce
	used, err := e.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsDANonceUsed: %v", err)
	}
	if !used {
		t.Fatal("engine should record the DA nonce after issuance")
	}

	resp2 := do()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("replay: expected 403, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Backend convergence: the nonce must eventually reach the da_nonces table.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		du, err := d.IsDANonceUsed(nonce)
		if err == nil && du {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("DA nonce did not converge to backend da_nonces table")
}

// TestEngineCRLGenerationInMemory verifies CRL generation in in-memory engine mode:
//  1. Engine-internal revocations are immediately included in the CRL (memory authoritative, no DB flush needed)
//  2. Engine index has no cross_certs, so generation falls back to DB for cross-revocations
func TestEngineCRLGenerationInMemory(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}

	// 1. Issue a main cert (memory authoritative, async DB write).
	body, _ := json.Marshal(map[string]any{
		"cn":      "crl-engine.example.com",
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
	var issueResp struct {
		SerialNumber string `json:"serial_number"`
	}
	json.NewDecoder(resp.Body).Decode(&issueResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || issueResp.SerialNumber == "" {
		t.Fatalf("issue failed: %d serial=%q", resp.StatusCode, issueResp.SerialNumber)
	}

	// Wait for main cert to persist (CRL test uses API GET path which also checks CA metadata via DB).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := d.CountCertsByCA("test-ca", ""); n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 2. Revoke main cert → engine revoked set is immediately visible (no DB flush dependency).
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/cert/test-ca/"+issueResp.SerialNumber+"/revoke",
		strings.NewReader(`{"reason":"superseded"}`))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke failed: %d", resp.StatusCode)
	}

	// 3. Engine revoked entries should immediately contain this serial.
	entries, err := e.GetRevokedCertEntries("test-ca")
	if err != nil {
		t.Fatalf("engine revoked entries: %v", err)
	}
	if len(entries) != 1 || entries[0].SerialNumber != issueResp.SerialNumber {
		t.Fatalf("engine revoked entries = %v, want [%s]", entries, issueResp.SerialNumber)
	}

	// 4. Generate CRL using the engine source injected at serve layer, decode and verify revocation entries.
	caCert, caKey := newTestCA(t, "test-ca")
	crlDER, err := ca.GenerateCRL(&ca.CRLConfig{
		DB:                   d,
		RevokedEntriesSource: srv.revokedEntriesSource(),
		CACert:               caCert,
		CAKey:                caKey,
		CAName:               "test-ca",
		ValidityDays:         30,
	})
	if err != nil {
		t.Fatalf("generate CRL via engine source: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	wantSerial := new(big.Int)
	if _, ok := wantSerial.SetString(issueResp.SerialNumber, 16); !ok {
		t.Fatalf("parse serial %q", issueResp.SerialNumber)
	}
	found := false
	for _, rc := range crl.RevokedCertificateEntries {
		if rc.SerialNumber.Cmp(wantSerial) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CRL missing engine-revoked serial %s (entries=%d)", issueResp.SerialNumber, len(crl.RevokedCertificateEntries))
	}

	// 5. API endpoint should also succeed (same engine source wiring).
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/crl/test-ca/generate", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("crl generate via API failed: %d", resp.StatusCode)
	}
}

// TestEngineAndRecordBufferMutualExclusion verifies the mutual exclusion semantics
// (E08): EnableEngine silently stops recordBuffer (engine owns the write pipeline),
// and after StopEngine, re-enabling RecordBuffer restores the batch write path —
// exactly the behavior fixed in serve.go when reload removes the engine.
func TestEngineAndRecordBufferMutualExclusion(t *testing.T) {
	srv, _, _ := newTestServerWithBuffer(t)
	t.Cleanup(srv.StopEngine)

	if srv.recordBuffer == nil {
		t.Fatal("recordBuffer should be enabled before the engine is enabled")
	}

	cfg := defaultEngineConfig(t)
	if err := srv.EnableEngine(cfg); err != nil {
		t.Fatalf("EnableEngine: %v", err)
	}
	if srv.recordBuffer != nil {
		t.Fatal("recordBuffer should be stopped when the engine owns the write pipeline")
	}
	if srv.getEngine() == nil {
		t.Fatal("engine should be enabled")
	}

	srv.StopEngine()
	if srv.getEngine() != nil {
		t.Fatal("engine should remain disabled")
	}
	if srv.recordBuffer != nil {
		t.Fatal("recordBuffer should stay stopped after StopEngine until re-enabled")
	}

	// After reload removes engine: re-enable RecordBuffer to restore batch write path.
	if err := srv.EnableRecordBuffer(&internal.Config{DB: filepath.Join(t.TempDir(), "pki.db")}); err != nil {
		t.Fatalf("EnableRecordBuffer after StopEngine: %v", err)
	}
	defer srv.StopRecordBuffer()
	if srv.recordBuffer == nil {
		t.Fatal("recordBuffer should be restored after engine is removed")
	}
	if srv.getEngine() != nil {
		t.Fatal("engine should remain disabled")
	}
}

// TestEngineMetricsEndpoint verifies that /metrics outputs varwof_engine_* metrics when
// the engine is enabled, and omits them when not (keeping the metrics surface
// clean for DB-only deployments).
func TestEngineMetricsEndpoint(t *testing.T) {
	srv, _, h := newTestServerWithBuffer(t)

	// Engine not enabled: /metrics must not contain varwof_engine_certindex_size
	body := getMetricsBody(t, h)
	if strings.Contains(body, "varwof_engine_certindex_size") {
		t.Fatal("engine metrics present before engine is enabled")
	}

	// After enabling engine: /metrics contains all engine metrics
	if err := srv.EnableEngine(defaultEngineConfig(t)); err != nil {
		t.Fatalf("EnableEngine: %v", err)
	}
	t.Cleanup(srv.StopEngine)
	body = getMetricsBody(t, h)
	for _, name := range []string{
		"varwof_engine_certindex_size",
		"varwof_engine_revokedset_size",
		"varwof_engine_nonceset_size",
		"varwof_engine_danonceset_size",
		"varwof_engine_subca_size",
		"varwof_engine_trustanchor_size",
		"varwof_engine_aic_size",
		"varwof_engine_pipeline_pending",
		"varwof_engine_window_evictions_total",
		"varwof_engine_read_hit_total",
		"varwof_engine_read_miss_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("engine metric %s missing from /metrics", name)
		}
	}
}

func getMetricsBody(t *testing.T, h http.Handler) string {
	t.Helper()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d", rec.Code)
	}
	return rec.Body.String()
}

// TestKeepEngineRepointsDB verifies the E04 reload-keep-engine path: a config
// reload that points at the same underlying store keeps the resident engine
// running and merely repoints its write path at the new DB handle. The
// in-memory index is preserved (no full rebuild), and writes issued after the
// swap converge through the new handle.
func TestKeepEngineRepointsDB(t *testing.T) {
	srv, d, h := newTestServerWithBuffer(t)
	if err := srv.EnableEngine(defaultEngineConfig(t)); err != nil {
		t.Fatalf("EnableEngine: %v", err)
	}
	t.Cleanup(srv.StopEngine)

	e := srv.Engine()
	if e == nil || !srv.EngineEnabled() {
		t.Fatal("engine should be enabled")
	}
	enginePtrBefore := e
	oldDB := d

	// A new handle over the same store simulates the reload's fresh connection.
	newDB, err := db.Open(oldDB.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { newDB.Close() })

	// Swap: keep the resident engine, repoint the write path.
	srv.KeepEngine(newDB)
	if !srv.EngineEnabled() {
		t.Fatal("engine should stay enabled after KeepEngine")
	}
	if srv.Engine() != enginePtrBefore {
		t.Fatal("KeepEngine must not rebuild the engine (same pointer expected)")
	}
	if e.DB() != newDB {
		t.Fatalf("engine write path should point at newDB, got %v", e.DB().Path())
	}

	// Reads keep being served from the resident in-memory index.
	ts := httptest.NewServer(h)
	defer ts.Close()
	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	issue := func(cn string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"cn":      cn,
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
		defer resp.Body.Close()
		var r struct {
			SerialNumber string `json:"serial_number"`
		}
		json.NewDecoder(resp.Body).Decode(&r)
		if resp.StatusCode != http.StatusOK || r.SerialNumber == "" {
			t.Fatalf("issue failed: %d", resp.StatusCode)
		}
		return r.SerialNumber
	}

	serial := issue("keep-before.example.com")
	st, err := e.GetCertStatus("test-ca", serial)
	if err != nil || st.Status != "V" {
		t.Fatalf("memory-authoritative read after KeepEngine failed: %v", err)
	}

	// A write after the swap must converge through the new handle.
	serial2 := issue("keep-after.example.com")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := newDB.GetCert("test-ca", serial2); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := newDB.GetCert("test-ca", serial2); err != nil {
		t.Fatalf("post-swap issued record never reached newDB handle: %v", err)
	}
}

// TestKeepEngineNoopWhenDisabled verifies KeepEngine is a safe no-op when the
// engine is not enabled (e.g. a reload that first enables the engine must not
// skip the full rebuild).
func TestKeepEngineNoopWhenDisabled(t *testing.T) {
	srv, _, _ := newTestServerWithBuffer(t)
	newDB, err := db.Open(t.TempDir() + "/noop.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { newDB.Close() })
	srv.KeepEngine(newDB)
	if srv.EngineEnabled() {
		t.Fatal("KeepEngine must not enable a disabled engine")
	}
}

// postJSON posts a JSON body to the test server with the admin token and
// returns the recorder.
func postJSON(t *testing.T, ts *httptest.Server, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	rr := httptest.NewRecorder()
	rr.Code = resp.StatusCode
	rr.Body = bytes.NewBuffer(buf.Bytes())
	return rr
}

// TestEngineRevokeCertsBatchMemoryTruth verifies batch revocation in in-memory
// engine mode:
//  1. Batch revocation is immediately visible in memory (memory is truth, DB may not yet be flushed)
//  2. Non-resident (out-of-band) entries fall back to DB
//  3. Persistence eventually converges in DB
func TestEngineRevokeCertsBatchMemoryTruth(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}

	// Issue 3 certs through the API (engine path).
	serials := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(map[string]any{
			"cn":      fmt.Sprintf("batch-engine-%d.example.com", i),
			"ca":      "test-ca",
			"profile": "tls-server",
		})
		rr := postJSON(t, ts, "/api/v1/certs", string(body), token)
		if rr.Code != http.StatusOK {
			t.Fatalf("issue %d: %d %s", i, rr.Code, rr.Body.String())
		}
		var resp struct {
			SerialNumber string `json:"serial_number"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		serials = append(serials, resp.SerialNumber)
	}
	// Wait for the engine write pipeline to persist the issues.
	waitForDBRows(t, d, 3)

	// Batch-revoke all 3 + one out-of-band serial not in engine memory.
	entries := make([]map[string]string, 0, 4)
	for _, s := range serials {
		entries = append(entries, map[string]string{"ca": "test-ca", "serial": s})
	}
	entries = append(entries, map[string]string{"ca": "test-ca", "serial": "DEADBEEF"})
	body, _ := json.Marshal(map[string]any{"entries": entries})

	rr := postJSON(t, ts, "/api/v1/certs/revoke-batch", string(body), token)
	if rr.Code != http.StatusOK {
		t.Fatalf("batch revoke: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		RevokedCount int `json:"revoked_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RevokedCount != 3 {
		t.Fatalf("expected 3 revoked (engine path), got %d", resp.RevokedCount)
	}

	// Memory is truth immediately: engine reports R even if DB async pending.
	eng := srv.getEngine()
	for _, s := range serials {
		st, err := eng.GetCertStatus("test-ca", s)
		if err != nil || st.Status != "R" {
			t.Fatalf("engine status for %s = %+v err=%v", s, st, err)
		}
	}

	// DB eventually converges.
	waitForRevoked(t, d, serials)
}

func waitForDBRows(t *testing.T, d *db.DB, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		certs, err := d.ListCerts("test-ca")
		if err == nil && len(certs) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d DB rows", want)
}

func waitForRevoked(t *testing.T, d *db.DB, serials []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allR := true
		for _, s := range serials {
			st, err := d.GetCertStatus("test-ca", s)
			if err != nil || st.Status != "R" {
				allR = false
				break
			}
		}
		if allR {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for DB revocation of %v", serials)
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/routing"
	"github.com/varwof/core/internal/tsa"
	"github.com/varwof/engine/db"
)

// ─── Pure functions ───────────────────────────────────────────────

func TestPemEncode(t *testing.T) {
	got := pemEncode("CERTIFICATE", []byte{0x30, 0x00})
	if !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatal("expected PEM block")
	}
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("expected equal")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatal("expected unequal lengths")
	}
	if bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Fatal("expected unequal content")
	}
}

func TestSelectSigAlgo(t *testing.T) {
	if selectSigAlgo("RSA-SHA256").String() != ca.OIDSigRSAWithSHA256.String() {
		t.Fatal("RSA-SHA256 mismatch")
	}
	if selectSigAlgo("RSA-PSS-SHA256").String() != ca.OIDSigRSAPSSWithSHA256.String() {
		t.Fatal("RSA-PSS-SHA256 mismatch")
	}
	if selectSigAlgo("whatever").String() != ca.OIDSigECDSAWithSHA256.String() {
		t.Fatal("default should be ECDSA-SHA256")
	}
}

func TestVerifySignatureAlgorithms(t *testing.T) {
	// ECDSA success
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: mustName(t, "ec"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	ecDER, _ := x509.CreateCertificate(rand.Reader, ecTmpl, ecTmpl, &ecKey.PublicKey, ecKey)
	ecCert, _ := x509.ParseCertificate(ecDER)
	digest := make([]byte, 32)
	rand.Read(digest)
	sig, _ := ecKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err := verifyECDSASignature(ecCert, digest, sig); err != nil {
		t.Fatalf("ecdsa verify: %v", err)
	}
	if err := verifyECDSASignature(ecCert, digest, []byte("bad")); err == nil {
		t.Fatal("expected ecdsa failure")
	}
	if err := verifyECDSASignature(ecCert, make([]byte, 48), sig); err == nil {
		t.Fatal("expected ecdsa bad-digest failure")
	}

	// ECDSA with RSA cert → wrong key type
	rsaKey, _ := newTestRSAKey(t)
	rsaTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: mustName(t, "rsa"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	rsaDER, _ := x509.CreateCertificate(rand.Reader, rsaTmpl, rsaTmpl, &rsaKey.PublicKey, rsaKey)
	rsaCert, _ := x509.ParseCertificate(rsaDER)
	if err := verifyECDSASignature(rsaCert, digest, sig); err == nil {
		t.Fatal("expected not-ECDSA error")
	}

	// RSA success
	rsaDigest := make([]byte, 32)
	rand.Read(rsaDigest)
	rsaSig, _ := rsaKey.Sign(rand.Reader, rsaDigest, crypto.SHA256)
	if err := verifyRSASignature(rsaCert, rsaDigest, rsaSig); err != nil {
		t.Fatalf("rsa verify: %v", err)
	}
	if err := verifyRSASignature(ecCert, rsaDigest, rsaSig); err == nil {
		t.Fatal("expected not-RSA error")
	}
	if err := verifyRSASignature(rsaCert, rsaDigest, []byte("bad")); err == nil {
		t.Fatal("expected rsa signature failure")
	}
}

func TestParseOIDStr(t *testing.T) {
	oid, err := parseOIDStr("1.2.3.4")
	if err != nil || oid.String() != "1.2.3.4" {
		t.Fatalf("parse failed: %v %v", oid, err)
	}
	if _, err := parseOIDStr("1.2.x.4"); err == nil {
		t.Fatal("expected error for non-numeric segment")
	}
	if _, err := parseOIDStr("1.2.3."); err == nil {
		t.Fatal("expected error for empty segment")
	}
}

func TestAPIConstraintsToCA(t *testing.T) {
	cs := []struct {
		SchemeId     string `json:"scheme_id"`
		CapabilityId string `json:"capability_id"`
		Parameters   []byte `json:"parameters,omitempty"`
	}{
		{SchemeId: "scheme-a", CapabilityId: "cap-1", Parameters: []byte{1}},
	}
	out := apiConstraintsToCA(cs)
	if len(out) != 1 || out[0].SchemeId != "scheme-a" {
		t.Fatalf("unexpected: %+v", out)
	}
	if apiConstraintsToCA(nil) != nil {
		t.Fatal("expected nil for empty constraints")
	}
}

// ─── mux helpers ──────────────────────────────────────────────────

func TestServerSetters(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)

	reg := provisioner.NewRegistry()
	srv.SetProvisioners(reg)
	if srv.provs != reg {
		t.Fatal("SetProvisioners failed")
	}

	rr, err := routing.LoadData([]byte(`{"version":"1","rules":[{"method":"GET","path":"/api/v1/version","permission":"ca:list"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRouteRules(rr)
	if srv.getRouteRules() != rr {
		t.Fatal("SetRouteRules failed")
	}

	srv.SetConfigPath("/tmp/config.json")
	if srv.configPath != "/tmp/config.json" {
		t.Fatal("SetConfigPath failed")
	}

	rc := tsa.NewRuntimeConfig(&tsa.TSAConfig{})
	srv.SetTSAConfig(rc)
	if srv.GetTSAConfig() != rc {
		t.Fatal("SetTSAConfig/GetTSAConfig roundtrip failed")
	}
}

func TestRecordOCSPResponse(t *testing.T) {
	RecordOCSPResponse("test-ca", "good")
}

func TestTSAX509LoadCertFile(t *testing.T) {
	cert, _ := newTestCA(t, "tsa-ca")
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	writePEMFile(t, p, "CERTIFICATE", cert.Raw)

	got, err := tsax509LoadCertFile(p)
	if err != nil || got == nil {
		t.Fatalf("load failed: %v", err)
	}
	if _, err := tsax509LoadCertFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("nope"), 0644)
	if _, err := tsax509LoadCertFile(bad); err == nil {
		t.Fatal("expected error for non-PEM file")
	}
}

// ─── RateLimiter AllowCA ──────────────────────────────────────────

func TestRateLimiterAllowCA(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	if !rl.AllowCA("1.2.3.4", "") {
		t.Fatal("expected allow for empty ca")
	}
	if !rl.AllowCA("1.2.3.4", "issuing") {
		t.Fatal("expected allow for new ca scope")
	}
	if rl.AllowCA("1.2.3.4", "issuing") {
		t.Fatal("expected deny for exhausted burst")
	}
	// Different CA should have its own bucket
	if !rl.AllowCA("1.2.3.4", "other-ca") {
		t.Fatal("expected allow for different ca")
	}
}

// ─── getRolePerms ─────────────────────────────────────────────────

func TestGetRolePerms(t *testing.T) {
	// Without policy: falls back to hardcoded table
	perms := getRolePerms("admin")
	if len(perms) == 0 {
		t.Fatal("expected admin perms")
	}
}

// ─── AIC API (direct calls, not through routing) ────────────────

func TestAICAPIDirect(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)

	// No extension: list returns empty
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/aic", nil)
	srv.apiAICList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("aic list: %d", w.Code)
	}

	// Insert one extension
	a := &db.AICExtension{
		CAName: "test-ca", SerialNumber: "SER1", AgentID: "agent-1",
		PrincipalUID: "puid-1", CapabilitiesJSON: `[{"scheme_id":"a"}]`,
		AICJSON: `{"version":1}`,
	}
	if err := d.InsertAICExtension(a); err != nil {
		t.Fatalf("insert aic: %v", err)
	}

	// Get
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/aic/test-ca/SER1", nil)
	srv.apiAIGet(w2, r2, "test-ca", "SER1")
	if w2.Code != http.StatusOK {
		t.Fatalf("aic get: %d", w2.Code)
	}
	w3 := httptest.NewRecorder()
	srv.apiAIGet(w3, r3(), "test-ca", "NOPE")
	if w3.Code != http.StatusNotFound {
		t.Fatalf("aic get missing: %d", w3.Code)
	}

	// Search by agent / principal / capability
	w4 := httptest.NewRecorder()
	srv.apiAISearchByAgent(w4, r4("agent-1"), "agent-1")
	if w4.Code != http.StatusOK {
		t.Fatalf("search agent: %d", w4.Code)
	}
	w5 := httptest.NewRecorder()
	srv.apiAISearchByPrincipal(w5, r5("puid-1"), "puid-1")
	if w5.Code != http.StatusOK {
		t.Fatalf("search principal: %d", w5.Code)
	}
	w6 := httptest.NewRecorder()
	r6 := httptest.NewRequest("GET", "/api/v1/aic/search?scheme=a", nil)
	srv.apiAISearchByCapability(w6, r6)
	if w6.Code != http.StatusOK {
		t.Fatalf("search capability: %d", w6.Code)
	}
	// capability without scheme
	w6b := httptest.NewRecorder()
	r6b := httptest.NewRequest("GET", "/api/v1/aic/search", nil)
	srv.apiAISearchByCapability(w6b, r6b)
	if w6b.Code != http.StatusBadRequest {
		t.Fatalf("search capability missing scheme: %d", w6b.Code)
	}

	// apiAICSearch (q empty → list)
	w7 := httptest.NewRecorder()
	srv.apiAICSearch(w7, httptest.NewRequest("GET", "/api/v1/aic/search", nil))
	if w7.Code != http.StatusOK {
		t.Fatalf("aic search default: %d", w7.Code)
	}
	// apiAICSearch with principal_uid
	w7b := httptest.NewRecorder()
	srv.apiAICSearch(w7b, httptest.NewRequest("GET", "/api/v1/aic/search?q=x&principal_uid=puid-1", nil))
	if w7b.Code != http.StatusOK {
		t.Fatalf("aic search puid: %d", w7b.Code)
	}
	// with agent_id
	w7c := httptest.NewRecorder()
	srv.apiAICSearch(w7c, httptest.NewRequest("GET", "/api/v1/aic/search?q=x&agent_id=agent-1", nil))
	if w7c.Code != http.StatusOK {
		t.Fatalf("aic search agent: %d", w7c.Code)
	}
	// with scheme
	w7d := httptest.NewRecorder()
	srv.apiAICSearch(w7d, httptest.NewRequest("GET", "/api/v1/aic/search?q=x&scheme=a", nil))
	if w7d.Code != http.StatusOK {
		t.Fatalf("aic search scheme: %d", w7d.Code)
	}
	// with q but no filters → default list
	w7e := httptest.NewRecorder()
	srv.apiAICSearch(w7e, httptest.NewRequest("GET", "/api/v1/aic/search?q=x", nil))
	if w7e.Code != http.StatusOK {
		t.Fatalf("aic search q-only: %d", w7e.Code)
	}

	// Update
	w8 := httptest.NewRecorder()
	body := `{"agent_id":"agent-2","principal_uid":"puid-2"}`
	r8 := httptest.NewRequest("POST", "/api/v1/aic/test-ca/SER1", strings.NewReader(body))
	r8.SetBasicAuth("admin", "admin")
	srv.apiAICUpdate(w8, r8, "test-ca", "SER1")
	if w8.Code != http.StatusOK {
		t.Fatalf("aic update: %d", w8.Code)
	}
	// Update bad JSON
	w8b := httptest.NewRecorder()
	r8b := httptest.NewRequest("POST", "/api/v1/aic/test-ca/SER1", strings.NewReader("{bad"))
	r8b.SetBasicAuth("admin", "admin")
	srv.apiAICUpdate(w8b, r8b, "test-ca", "SER1")
	if w8b.Code != http.StatusBadRequest {
		t.Fatalf("aic update bad json: %d", w8b.Code)
	}
	// Update missing
	w8c := httptest.NewRecorder()
	r8c := httptest.NewRequest("POST", "/api/v1/aic/test-ca/MISS", strings.NewReader(body))
	r8c.SetBasicAuth("admin", "admin")
	srv.apiAICUpdate(w8c, r8c, "test-ca", "MISS")
	if w8c.Code != http.StatusNotFound {
		t.Fatalf("aic update missing: %d", w8c.Code)
	}
	// Update unauthenticated → 401
	w8d := httptest.NewRecorder()
	srv.apiAICUpdate(w8d, httptest.NewRequest("POST", "/api/v1/aic/test-ca/SER1", strings.NewReader(body)), "test-ca", "SER1")
	if w8d.Code != http.StatusUnauthorized {
		t.Fatalf("aic update unauth: %d", w8d.Code)
	}

	// Delete
	w9 := httptest.NewRecorder()
	r9 := httptest.NewRequest("DELETE", "/api/v1/aic/test-ca/SER1", nil)
	r9.SetBasicAuth("admin", "admin")
	srv.apiAICDelete(w9, r9, "test-ca", "SER1")
	if w9.Code != http.StatusOK {
		t.Fatalf("aic delete: %d", w9.Code)
	}
	w9b := httptest.NewRecorder()
	r9b := httptest.NewRequest("DELETE", "/api/v1/aic/test-ca/MISS", nil)
	r9b.SetBasicAuth("admin", "admin")
	srv.apiAICDelete(w9b, r9b, "test-ca", "MISS")
	if w9b.Code != http.StatusOK {
		t.Fatalf("aic delete missing (idempotent): %d", w9b.Code)
	}

	// Backfill
	w10 := httptest.NewRecorder()
	r10 := httptest.NewRequest("POST", "/api/v1/aic/backfill", nil)
	r10.SetBasicAuth("admin", "admin")
	srv.apiAICBackfill(w10, r10)
	if w10.Code != http.StatusOK {
		t.Fatalf("aic backfill: %d", w10.Code)
	}
}

func r3() *http.Request { return httptest.NewRequest("GET", "/api/v1/aic/test-ca/NOPE", nil) }
func r4(s string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/aic/agent/"+s, nil)
	return r
}
func r5(s string) *http.Request {
	return httptest.NewRequest("GET", "/api/v1/aic/principal/"+s, nil)
}

// ─── replayWAL ────────────────────────────────────────────────────

func TestReplayWAL(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)

	dir := t.TempDir()
	// Missing WAL → nil
	if err := replayWAL(srv.getDB, filepath.Join(dir, "no.wal")); err != nil {
		t.Fatalf("missing wal: %v", err)
	}
	// Empty WAL → nil
	p := filepath.Join(dir, "empty.wal")
	os.WriteFile(p, nil, 0644)
	if err := replayWAL(srv.getDB, p); err != nil {
		t.Fatalf("empty wal: %v", err)
	}
	// Valid records
	rec := db.CertRecord{
		SerialNumber: "WAL1", CAName: "test-ca", Status: "V",
		Subject: "CN=wal-cert", CommonName: "wal-cert",
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		CertDER: []byte{0x30, 0x00}, Fingerprint: "fp-wal1",
	}
	recJSON, _ := json.Marshal(rec)
	p2 := filepath.Join(dir, "data.wal")
	os.WriteFile(p2, append([]byte("# comment\n"), recJSON...), 0644)
	if err := replayWAL(srv.getDB, p2); err != nil {
		t.Fatalf("replay: %v", err)
	}
	got, err := d.GetCert("test-ca", "WAL1")
	if err != nil || got == nil {
		t.Fatalf("expected replayed cert, got %v", err)
	}
	// Corrupt line → skipped, no error
	p3 := filepath.Join(dir, "corrupt.wal")
	os.WriteFile(p3, []byte("not-json\n"+string(recJSON)), 0644)
	if err := replayWAL(srv.getDB, p3); err != nil {
		t.Fatalf("corrupt wal: %v", err)
	}
}

// ─── checkCRLFreshness ────────────────────────────────────────────

func TestCheckCRLFreshness(t *testing.T) {
	if got := checkCRLFreshness(""); got != "ok" {
		t.Fatalf("empty dir should be ok, got %s", got)
	}
	if got := checkCRLFreshness("/nonexistent-dir-xyz"); !strings.HasPrefix(got, "error") {
		t.Fatalf("missing dir should error, got %s", got)
	}

	// Create a real CRL
	caCert, caKey := newTestCA(t, "crl-ca")
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("create crl: %v", err)
	}

	dir := t.TempDir()
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(filepath.Join(dir, "ca.crl"), crlPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if got := checkCRLFreshness(dir); got != "ok" {
		t.Fatalf("fresh crl should be ok, got %s", got)
	}

	// Expired CRL
	crlTemplate2 := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}
	crlDER2, _ := x509.CreateRevocationList(rand.Reader, crlTemplate2, caCert, caKey)
	crlPEM2 := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER2})
	os.Remove(filepath.Join(dir, "ca.crl"))
	os.WriteFile(filepath.Join(dir, "expired.crl"), crlPEM2, 0644)
	if got := checkCRLFreshness(dir); !strings.HasPrefix(got, "expired") {
		t.Fatalf("expired crl should say expired, got %s", got)
	}

	// Parse-error CRL (garbage)
	os.Remove(filepath.Join(dir, "expired.crl"))
	os.WriteFile(filepath.Join(dir, "garbage.crl"), []byte("not-a-crl"), 0644)
	if got := checkCRLFreshness(dir); !strings.HasPrefix(got, "parse error") {
		t.Fatalf("garbage crl should parse-error, got %s", got)
	}

	// Empty dir → no CRL found
	empty := t.TempDir()
	if got := checkCRLFreshness(empty); !strings.HasPrefix(got, "error") {
		t.Fatalf("empty dir should error, got %s", got)
	}
}

// ─── Helper functions ────────────────────────────────────────────

func newTestRSAKey(t *testing.T) (*rsa.PrivateKey, error) {
	t.Helper()
	return rsa.GenerateKey(rand.Reader, 2048)
}

func mustName(t *testing.T, cn string) pkix.Name {
	t.Helper()
	return pkix.Name{CommonName: cn}
}

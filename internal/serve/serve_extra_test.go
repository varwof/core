// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"github.com/varwof/core/internal/ca"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAsyncProcessorProcess covers asyncJobProcessor.Process: empty input,
// an unknown CA (all items fail with the same error), and a successful batch
// whose certificates are persisted to the DB.
func TestAsyncProcessorProcess(t *testing.T) {
	srv, _ := newTestServerWithDB(t)

	p := newAsyncJobProcessor(srv, 4)

	if res := p.Process(nil); res != nil {
		t.Fatalf("empty input must return nil, got %v", res)
	}

	res := p.Process([]ca.JobRequestItem{{CA: "nope-ca", CN: "a"}})
	if len(res) != 1 || res[0].Status != "error" {
		t.Fatalf("unknown CA: expected single error item, got %+v", res)
	}

	res = p.Process([]ca.JobRequestItem{{CA: "test-ca", CN: "batch-ok.example.com", KeyType: "ecdsa-p256"}})
	if len(res) != 1 || res[0].Status != "ok" || res[0].Serial == "" {
		t.Fatalf("successful batch: expected ok item with serial, got %+v", res)
	}

	rec, err := srv.getDB().GetCert("test-ca", res[0].Serial)
	if err != nil || rec == nil {
		t.Fatalf("expected persisted record: %v (%v)", rec, err)
	}
}

// TestGenerateCRL_DeltaWithoutSince drives the delta-CRL request without a
// "since" query parameter against a fresh DB (no recorded last thisUpdate):
// it must fail closed with 400 instead of generating a delta from nothing.
func TestGenerateCRL_DeltaWithoutSince(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/crl/test-ca/generate?delta=1", nil)
	srv.apiGenerateCRL(w, r, "test-ca")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for delta without since, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGenerateCRL_DeltaInvalidSince verifies an unparseable RFC3339 "since"
// value is rejected with 400.
func TestGenerateCRL_DeltaInvalidSince(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/crl/test-ca/generate?delta=1&since=not-a-time", nil)
	srv.apiGenerateCRL(w, r, "test-ca")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad since, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGenerateCRL_DeltaWithSince drives the delta path with an explicit since
// value; it must get past the since parsing (i.e. not a 400 despite an empty
// last-thisUpdate store).
func TestGenerateCRL_DeltaWithSince(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	w := httptest.NewRecorder()
	since := url.QueryEscape(time.Now().Add(-24 * time.Hour).Format(time.RFC3339))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/crl/test-ca/generate?delta=1&since="+since, nil)
	srv.apiGenerateCRL(w, r, "test-ca")
	if w.Code == http.StatusBadRequest {
		t.Fatalf("delta with valid since must not be 400: %s", w.Body.String())
	}
}

// TestDNSQuery_ErrorBranches covers the deterministic failure paths of
// apiDNSQuery: a missing name and a non-GET method (the live-resolver path
// is non-deterministic offline, so only its guard branches are exercised).
func TestDNSQuery_ErrorBranches(t *testing.T) {
	srv, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/api/v1/dns/query", nil)
	srv.apiDNSQuery(w1, r1)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("missing name: expected 400, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/dns/query", nil)
	srv.apiDNSQuery(w2, r2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non-GET: expected 405, got %d", w2.Code)
	}
}

// TestIssueCert_MissingCN covers the api.cn_required guard after the
// management gate: a superadmin certificate may pass the gate, but a missing
// CN for a profile that requires one must be rejected with 400.
func TestIssueCert_MissingCN(t *testing.T) {
	handler := newTestServer(t)
	fx := newMTLSCertFixture(t, handler, "SuperAdmin", "cert:issue")

	req, _ := http.NewRequest(http.MethodPost, fx.Server.URL+"/api/v1/certs", strings.NewReader(`{"profile":"m-superadmin","ca":"test-ca"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := fx.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing CN: expected 400, got %d: %s", resp.StatusCode, string(raw))
	}
}

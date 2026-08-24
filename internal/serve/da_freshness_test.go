// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
)

// newTestServerWithSkewC3 builds a test server with customizable da_max_timestamp_skew
// that returns CA cert/key (for C3 real signature construction).
func newTestServerWithSkewC3(t *testing.T, skew string) (*Server, http.Handler, *x509.Certificate, crypto.Signer) {
	t.Helper()
	srv, h, caCert, caKey := newTestServerWithCA(t)
	cfg := srv.getConfig()
	cfg.Serve.DAMaxTimestampSkew = skew
	srv.cfgPtr.Store(cfg)
	return srv, h, caCert, caKey
}

// TestServeDATimestampFreshness_Default default 30s window:
// fresh timestamp (now) → 200; stale (>30s) → 403 api.da_timestamp_stale.
func TestServeDATimestampFreshness_Default(t *testing.T) {
	_, h, caCert, caKey := newTestServerWithSkewC3(t, "30s")
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Fresh: current time → 200.
	fresh, _ := agentProxyC3BodyAt(t, caCert, caKey, "fresh-agent", "fresh-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now(), nil)
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(fresh)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh timestamp: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Stale: 61 seconds ago → 403.
	stale, _ := agentProxyC3BodyAt(t, caCert, caKey, "stale-agent", "stale-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now().Add(-61*time.Second), nil)
	resp2 := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(stale)))
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("stale timestamp: expected 403, got %d", resp2.StatusCode)
	}
	body := make([]byte, 512)
	n, _ := resp2.Body.Read(body)
	if !strings.Contains(string(body[:n]), "da_timestamp_stale") {
		t.Fatalf("expected api.da_timestamp_stale error, got: %s", string(body[:n]))
	}
	resp2.Body.Close()

	// Future time: beyond window → 403 (anti-clock-prep attack).
	future, _ := agentProxyC3BodyAt(t, caCert, caKey, "future-agent", "future-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now().Add(61*time.Second), nil)
	resp3 := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(future)))
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("future timestamp: expected 403, got %d", resp3.StatusCode)
	}
	resp3.Body.Close()
}

// TestServeDATimestampFreshness_Disabled skew="0" skips freshness check:
// any stale timestamp is allowed.
func TestServeDATimestampFreshness_Disabled(t *testing.T) {
	_, h, caCert, caKey := newTestServerWithSkewC3(t, "0")
	ts := httptest.NewServer(h)
	defer ts.Close()

	stale, _ := agentProxyC3BodyAt(t, caCert, caKey, "stale-agent", "stale-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now().Add(-1*time.Hour), nil)
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(stale)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("skew disabled: expected 200 for stale ts, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestServeDATimestampFreshness_CustomWindow custom window:
// 40s ago within 60s window → 200; outside 10s window → 403.
func TestServeDATimestampFreshness_CustomWindow(t *testing.T) {
	_, h, caCert, caKey := newTestServerWithSkewC3(t, "60s")
	ts := httptest.NewServer(h)
	defer ts.Close()

	fresh, _ := agentProxyC3BodyAt(t, caCert, caKey, "fresh-agent", "fresh-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now().Add(-40*time.Second), nil)
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(fresh)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("40s ago within 60s window: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	_, h2, caCert2, caKey2 := newTestServerWithSkewC3(t, "10s")
	ts2 := httptest.NewServer(h2)
	defer ts2.Close()
	outside, _ := agentProxyC3BodyAt(t, caCert2, caKey2, "outside-agent", "outside-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now().Add(-40*time.Second), nil)
	resp2 := authedPost(t, ts2, "/api/v1/certs", "application/json", strings.NewReader(string(outside)))
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("40s ago outside 10s window: expected 403, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// TestServeDATimestampFreshness_Missing missing timestamp falls back to now (200),
// compatible with existing API behavior (daTS = time.Now() when not provided).
func TestServeDATimestampFreshness_Missing(t *testing.T) {
	_, h, caCert, caKey := newTestServerWithSkewC3(t, "30s")
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Sign with current time but don't include the user_auth_timestamp field.
	body, _ := agentProxyC3BodyAt(t, caCert, caKey, "missing-ts-agent", "missing-ts-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil,
		time.Now(), nil)
	// Remove timestamp field (CA side falls back to now, differs from signing now by
	// a few milliseconds — passes within 30s window). Note: freshness uses the
	// fallback now, signing uses the ts at time of writing, they must agree for
	// signature verification: here ts was passed as now, after removing the field
	// CA rebuilds with current now, time diff < 1s, both verification and freshness pass.
	body = stripField(body, "user_auth_timestamp")
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing timestamp (defaults to now): expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// stripField removes a specified top-level field from a JSON body.
func stripField(body []byte, field string) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	delete(m, field)
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

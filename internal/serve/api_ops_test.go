// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/varwof/core/internal/ca"
)

func TestServeIssueAgentProxy(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "agent-proxy-test", "agent-proxy-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}

	var result struct {
		SerialNumber string `json:"serial_number"`
		CertPEM      string `json:"cert_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.SerialNumber == "" {
		t.Fatal("empty serial number")
	}

	block, _ := pem.Decode([]byte(result.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	aic, err := ca.ParseAIC(cert)
	if err != nil {
		t.Fatalf("ParseAIC: %v", err)
	}
	if aic == nil {
		t.Fatal("expected AIC extension")
	}
	if aic.AgentId != "agent-proxy-1" {
		t.Fatalf("AgentId: expected agent-proxy-1, got %s", aic.AgentId)
	}
}

func TestServeIssueAgentProxyImpersonation(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "agent-imp", "agent-imp-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 1, nil)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}

	var result struct {
		CertPEM string `json:"cert_pem"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	block, _ := pem.Decode([]byte(result.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	aic, _ := ca.ParseAIC(cert)
	if aic == nil {
		t.Fatal("expected AIC extension")
	}
	if aic.DelegationMode != 1 {
		t.Fatalf("AIC.DelegationMode: expected 1 (representative), got %d", aic.DelegationMode)
	}
	pa, _ := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
	if pa == nil || pa.DelegationPolicy.AllowedMode != 1 {
		t.Fatalf("PrincipalAuthorization.DelegationPolicy.AllowedMode: expected 1 (representative)")
	}
}

func TestServeIssueImpersonationWithoutAuth(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{
		"ca": "test-ca",
		"cn": "agent-noauth-imp",
		"profile": "agent-proxy",
		"subject": "/CN=agent-noauth-imp/OU=gateway:admin",
		"agent_id": "agent-noauth-1",
		"delegation_mode": 1
	}`

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for representative without user auth, got %d", resp.StatusCode)
	}
}

func TestServeIssueAgentProxyWithoutAgentId(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{
		"ca": "test-ca",
		"cn": "no-agent-id",
		"profile": "agent-proxy",
		"subject": "/CN=no-agent-id/OU=gateway:read"
	}`

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	// Without agent_id, no AIC extension is added, but cert should still be issued
	// (agent-proxy profile only conditionally adds AIC when req.AgentId != "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 even without agent_id, got %d", resp.StatusCode)
	}

	var result struct {
		CertPEM string `json:"cert_pem"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	block, _ := pem.Decode([]byte(result.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	aic, _ := ca.ParseAIC(cert)
	if aic != nil {
		t.Fatal("expected no AIC extension when agent_id is empty")
	}
}

func TestServeIssueWithPrincipalAuthorization(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "pa-test", "pa-agent",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:ops"}}, 0, nil)
	// Override subject OU and PA grants as the original test intended.
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["subject"] = "/CN=pa-test/OU=gateway:ops"
	m["principal_authorization"] = map[string]any{
		"grants": []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:ops"}},
	}
	okBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(okBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(bb[:n]))
	}

	var result struct {
		CertPEM string `json:"cert_pem"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	block, _ := pem.Decode([]byte(result.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	pa, err := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
	if err != nil {
		t.Fatalf("ParsePrincipalAuthorizationExtension: %v", err)
	}
	if pa == nil {
		t.Fatal("expected PrincipalAuthorization extension")
	}
	if len(pa.Grants) != 1 || pa.Grants[0].CapabilityId != "gateway:ops" {
		t.Fatalf("Grants: expected [gateway:ops], got %v", pa.Grants)
	}
}

func TestServeIssueWithoutAuth(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{"ca": "test-ca", "cn": "unauth"}`
	resp, err := http.Post(ts.URL+"/api/v1/certs", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", resp.StatusCode)
	}
}

// TestServeDANonceReplay verifies DA nonce anti-replay: the same nonce used a second time
// to issue an agent-proxy AIC must be rejected (403), preventing the same authorization
// signature from being replayed to mint multiple certificates.
func TestServeDANonceReplay(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "replay-agent", "replay-agent-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)

	// First issuance: same nonce, valid → 200.
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	if resp.StatusCode != http.StatusOK {
		bodyBytes := make([]byte, 512)
		n, _ := resp.Body.Read(bodyBytes)
		t.Fatalf("first issue: expected 200, got %d: %s", resp.StatusCode, string(bodyBytes[:n]))
	}
	resp.Body.Close()

	// Replay: same DA nonce → 403.
	resp2 := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	if resp2.StatusCode != http.StatusForbidden {
		bodyBytes := make([]byte, 512)
		n, _ := resp2.Body.Read(bodyBytes)
		t.Fatalf("replay: expected 403, got %d: %s", resp2.StatusCode, string(bodyBytes[:n]))
	}
	resp2.Body.Close()
}

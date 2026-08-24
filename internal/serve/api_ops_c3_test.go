// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	pki "github.com/varwof/types"
)

// agentProxyC3Body builds an agent-proxy issuance request body with a real user
// signature. It signs a user certificate (same CA as newTestServer), computes
// principal_uid.keyHash, signs DelegationAuthTBS with the user private key
// (consistent with pki-client fillDelegationAuthEvidence and CA-side
// verifyDelegationAuthTBS reconstruction), and includes user_cert_pem.
// delegationMode determines TBS and the request's delegation_mode (default 0).
// Returns the body JSON bytes and the user private key.
func agentProxyC3Body(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, cn, agentID string, caps []ca.Capability, delegationMode int, constraints []ca.Capability) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	return agentProxyC3BodyAt(t, caCert, caKey, cn, agentID, caps, delegationMode, constraints, time.Now().UTC().Truncate(time.Second), nil)
}

// agentProxyC3BodyAt is the same as agentProxyC3Body but allows injecting a
// signing timestamp ts (for freshness tests needing stale/future timestamps)
// and nonce (for replay tests). ts is nil to use current time; nonce is nil
// to generate randomly.
func agentProxyC3BodyAt(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, cn, agentID string, caps []ca.Capability, delegationMode int, constraints []ca.Capability, ts time.Time, nonce []byte) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	return agentProxyC3BodyWithKey(t, caCert, caKey, cn, agentID, caps, delegationMode, constraints, ts, nonce, nil, "")
}

// agentProxyC3BodyWithKey is the underlying implementation of agentProxyC3BodyAt,
// allowing injection of a fixed user cert/private key and principal_uid
// (B2 concurrent delegation limit tests need multiple agents sharing the same
// principal identity). When userKey/puid are non-nil/non-empty, injected values
// are used; otherwise new ones are generated.
func agentProxyC3BodyWithKey(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, cn, agentID string, caps []ca.Capability, delegationMode int, constraints []ca.Capability, ts time.Time, nonce []byte, userKey *ecdsa.PrivateKey, puid string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	var userCert *x509.Certificate
	var ukey *ecdsa.PrivateKey
	if userKey != nil {
		ukey = userKey
		userCert = buildUserCertForTest(t, caCert, caKey, ukey, cn)
	} else {
		userCert, ukey = newUserCert(t, caCert, caKey, cn)
	}

	// principal_uid: realm varwof, keyHash = SPKI SHA-256 of user cert.
	if puid == "" {
		pubBytes, err := x509.MarshalPKIXPublicKey(userCert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keyHash := sha256.Sum256(pubBytes)
		puid = "varwof:" + cn + ":" + base64.RawURLEncoding.EncodeToString(keyHash[:])
	}

	pu, err := pki.ParsePrincipalUid(puid)
	if err != nil {
		t.Fatal(err)
	}

	// Sign DelegationAuthTBS (same construction as pki-client / CA verification).
	if ts.IsZero() {
		ts = time.Now().UTC().Truncate(time.Second)
	}
	if nonce == nil {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
	}
	tbs := &pki.DelegationAuthTBS{
		Version:                  1,
		AgentId:                  agentID,
		PrincipalUid:             pu,
		Reason:                   pki.Reason{ReasonCode: "API_ISSUE", Description: "user-authorized AIC issuance"},
		Capabilities:             toPKITestCaps(caps),
		DelegationMode:           pki.DelegationMode(delegationMode),
		AuthorizationConstraints: toPKITestCaps(constraints),
		RequestedLifetime:        3600,
		Timestamp:                ts,
		Nonce:                    nonce,
	}
	tbsDER, err := asn1.Marshal(*tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ukey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	req := map[string]any{
		"ca":                           "test-ca",
		"cn":                           cn,
		"profile":                      "agent-proxy",
		"subject":                      "/CN=" + cn + "/OU=gateway:admin",
		"validity":                     1,
		"agent_id":                     agentID,
		"principal_uid":                puid,
		"user_auth_signature":          base64.StdEncoding.EncodeToString(sig),
		"user_auth_signature_algo":     "ECDSA-SHA256",
		"user_auth_nonce":              base64.StdEncoding.EncodeToString(nonce),
		"user_auth_lifetime":           3600,
		"user_auth_timestamp":          ts.Format(time.RFC3339),
		"user_auth_reason_code":        "API_ISSUE",
		"user_auth_reason_description": "user-authorized AIC issuance",
		"delegation_mode":              delegationMode,
		"capabilities":                 capJSON(caps),
		"user_cert_pem":                string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw})),
	}
	if len(constraints) > 0 {
		req["authorization_constraints"] = capJSON(constraints)
	}
	// Matching PrincipalAuthorization grants (AIC caps ⊆ PA grants):
	// Consistent with pki-client behavior, avoids false positives from sign.go subset check.
	grants := make([]map[string]any, 0, len(caps))
	for _, c := range caps {
		grants = append(grants, map[string]any{"scheme_id": c.SchemeId, "capability_id": c.CapabilityId})
	}
	req["principal_authorization"] = map[string]any{
		"grants":            grants,
		"delegation_policy": map[string]any{"allowed_mode": delegationMode},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body, ukey
}

// capJSON converts ca.Capability slice to a structure with API json tags for request body serialization.
func capJSON(cs []ca.Capability) []map[string]any {
	if len(cs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		m := map[string]any{"scheme_id": c.SchemeId, "capability_id": c.CapabilityId}
		if len(c.Parameters) > 0 {
			m["parameters"] = c.Parameters
		}
		out = append(out, m)
	}
	return out
}

// toPKITestCaps converts ca.Capability slice to pki.Capability slice.
func toPKITestCaps(cs []ca.Capability) []pki.Capability {
	if len(cs) == 0 {
		return nil
	}
	out := make([]pki.Capability, 0, len(cs))
	for _, c := range cs {
		out = append(out, pki.Capability{SchemeId: c.SchemeId, CapabilityId: c.CapabilityId, Parameters: c.Parameters})
	}
	return out
}

// TestServeIssueAgentProxyC3Valid verifies C3: agent-proxy issuance with real user signature succeeds.
func TestServeIssueAgentProxyC3Valid(t *testing.T) {
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
}

// TestServeIssueAgentProxyC3Tampered verifies C3: tampered signature → 403.
func TestServeIssueAgentProxyC3Tampered(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "tampered-agent", "tampered-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)
	// Corrupt the signature in the JSON body.
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["user_auth_signature"] = base64.StdEncoding.EncodeToString([]byte("AAAA"))
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered signature, got %d", resp.StatusCode)
	}
	bb := make([]byte, 512)
	n, _ := resp.Body.Read(bb)
	if !strings.Contains(string(bb[:n]), "delegation_signature_invalid") {
		t.Fatalf("expected api.delegation_signature_invalid, got: %s", string(bb[:n]))
	}
}

// TestServeIssueAgentProxyC3WrongCert verifies C3: user_cert_pem SPKI does not
// match principal_uid.keyHash → 403 (prevents forged user certificates).
func TestServeIssueAgentProxyC3WrongCert(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "wrong-cert-agent", "wrong-cert-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)

	// Swap in a different user cert whose SPKI does NOT match the keyHash.
	otherCert, _ := newUserCert(t, caCert, caKey, "other-user")
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["user_cert_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCert.Raw}))
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for mismatched user cert, got %d", resp.StatusCode)
	}
}

// TestServeIssueAgentProxyC3RepresentativePolicy verifies B6: delegation_mode=1
// but principal_authorization does not declare allowed_mode=1 → 403.
func TestServeIssueAgentProxyC3RepresentativePolicy(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "rep-agent", "rep-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 1, nil)

	// Override PA: allowed_mode=0 (representative not permitted) → B6 rejects.
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["principal_authorization"] = map[string]any{
		"grants":            []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
		"delegation_policy": map[string]any{"allowed_mode": 0},
	}
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 403 for representative without allowed policy, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
	bb := make([]byte, 512)
	n, _ := resp.Body.Read(bb)
	if !strings.Contains(string(bb[:n]), "representative_policy_denied") {
		t.Fatalf("expected api.representative_policy_denied, got: %s", string(bb[:n]))
	}
}

// TestServeIssueAgentProxyC3RepresentativeAllowed verifies B6: delegation_mode=1
// with principal_authorization allowed_mode=1 → 200.
func TestServeIssueAgentProxyC3RepresentativeAllowed(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "rep-ok-agent", "rep-ok-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 1, nil)

	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["principal_authorization"] = map[string]any{
		"grants":            []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
		"delegation_policy": map[string]any{"allowed_mode": 1},
	}
	okBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(okBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200 for representative with allowed policy, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

// TestServeIssueAgentProxyC3ModeMismatch verifies: TBS signed with mode=0 but
// request has delegation_mode=1 → signature verification failure (mode participates in signing).
func TestServeIssueAgentProxyC3ModeMismatch(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Sign with mode 0 but request delegation_mode=1.
	body, _ := agentProxyC3Body(t, caCert, caKey, "mismatch-agent", "mismatch-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["delegation_mode"] = 1
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 403 for mode mismatch, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}

// TestServeIssueAgentProxyC3NoCert verifies: no user_cert_pem and no mTLS → 403.
func TestServeIssueAgentProxyC3NoCert(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body := `{
		"ca": "test-ca",
		"cn": "nocert-agent",
		"profile": "agent-proxy",
		"subject": "/CN=nocert-agent/OU=gateway:admin",
		"agent_id": "nocert-1",
		"principal_uid": "varwof:nocert-agent:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"user_auth_signature": "AwQFBg==",
		"user_auth_signature_algo": "ECDSA-SHA256",
		"user_auth_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"user_auth_lifetime": 3600,
		"capabilities": [{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}]
	}`
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without user cert, got %d", resp.StatusCode)
	}
}

// TestServeIssueAgentProxyC3MTLSFallback verifies: no user_cert_pem but mTLS peer
// cert SPKI == keyHash → signature verification passes (fallback path).
func TestServeIssueAgentProxyC3MTLSFallback(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	// Peer cert doubles as both the auth credential (OU role) and the DA
	// signer (SPKI == keyHash), matching a single-user mTLS deployment.
	// Grants must include cert:issue (admin role permission for POST /api/v1/certs).
	userCert, userKey := newUserCertOU(t, caCert, caKey, "mtls-agent", []string{"admin"}, "cert:issue", "cert:list")

	// Build principal_uid with keyHash of the mTLS cert.
	pubBytes, err := x509.MarshalPKIXPublicKey(userCert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(pubBytes)
	puid := "varwof:mtls-agent:" + base64.RawURLEncoding.EncodeToString(keyHash[:])

	pu, err := pki.ParsePrincipalUid(puid)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Truncate(time.Second)
	tbs := &pki.DelegationAuthTBS{
		Version:           1,
		AgentId:           "mtls-1",
		PrincipalUid:      pu,
		Reason:            pki.Reason{ReasonCode: "API_ISSUE", Description: "user-authorized AIC issuance"},
		Capabilities:      toPKITestCaps([]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}),
		DelegationMode:    0,
		RequestedLifetime: 3600,
		Timestamp:         ts,
		Nonce:             nonce,
	}
	tbsDER, _ := asn1.Marshal(*tbs)
	digest := sha256.Sum256(tbsDER)
	sig, _ := ecdsa.SignASN1(rand.Reader, userKey, digest[:])

	req := map[string]any{
		"ca":                           "test-ca",
		"cn":                           "mtls-agent",
		"profile":                      "agent-proxy",
		"subject":                      "/CN=mtls-agent/OU=gateway:admin",
		"agent_id":                     "mtls-1",
		"principal_uid":                puid,
		"user_auth_signature":          base64.StdEncoding.EncodeToString(sig),
		"user_auth_signature_algo":     "ECDSA-SHA256",
		"user_auth_nonce":              base64.StdEncoding.EncodeToString(nonce),
		"user_auth_lifetime":           3600,
		"user_auth_timestamp":          ts.Format(time.RFC3339),
		"user_auth_reason_code":        "API_ISSUE",
		"user_auth_reason_description": "user-authorized AIC issuance",
		"capabilities":                 []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
	}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest("POST", "/api/v1/certs", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.SetBasicAuth("admin", "admin")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{userCert}}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 via mTLS fallback, got %d: %s", rec.Code, rec.Body.String())
	}
}

// buildUserCertForTest issues a user certificate with an injected private key
// (for B2 tests reusing the same principal identity across multiple agent certs).
// Certificate structure is identical to newUserCert.
func buildUserCertForTest(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	grants := []ca.Capability{{SchemeId: "cert", CapabilityId: "issue"}}
	paExt, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{paExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestServeIssueAgentProxyB2MaxAgents verifies B2: when DelegationPolicy.MaxAgents=1,
// a second active AIC cert for the same principal is rejected (403).
func TestServeIssueAgentProxyB2MaxAgents(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Issue two agent certs for the same user identity (principal).
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caps := []ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}

	// First agent: shares the same user key and principal (puid auto-derived from keyHash).
	body1, _ := agentProxyC3BodyWithKey(t, caCert, caKey, "same-user", "agent-A", caps, 0, nil,
		time.Now().UTC().Truncate(time.Second), nil, userKey, "")
	var m1 map[string]any
	if err := json.Unmarshal(body1, &m1); err != nil {
		t.Fatal(err)
	}
	puid, _ := m1["principal_uid"].(string)
	m1["principal_authorization"] = map[string]any{
		"grants":            []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
		"delegation_policy": map[string]any{"allowed_mode": 0, "max_agents": 1},
	}
	okBody, _ := json.Marshal(m1)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(okBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200 for first agent, got %d: %s", resp.StatusCode, string(bb[:n]))
	}

	// Second agent: same principal, MaxAgents=1 already full → 403.
	body2, _ := agentProxyC3BodyWithKey(t, caCert, caKey, "same-user", "agent-B", caps, 0, nil,
		time.Now().UTC().Truncate(time.Second), nil, userKey, puid)
	var m2 map[string]any
	if err := json.Unmarshal(body2, &m2); err != nil {
		t.Fatal(err)
	}
	m2["principal_authorization"] = map[string]any{
		"grants":            []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
		"delegation_policy": map[string]any{"allowed_mode": 0, "max_agents": 1},
	}
	badBody, _ := json.Marshal(m2)

	resp2 := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		bb := make([]byte, 512)
		n, _ := resp2.Body.Read(bb)
		t.Fatalf("expected 403 for second agent (max_agents=1), got %d: %s", resp2.StatusCode, string(bb[:n]))
	}
}

// TestServeIssueAgentProxyB2MaxAgentsUnset verifies B2 disabled semantics: when
// MaxAgents is unset (0 = unlimited), the same principal can issue multiple agent certs.
func TestServeIssueAgentProxyB2MaxAgentsUnset(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caps := []ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}

	body1, _ := agentProxyC3BodyWithKey(t, caCert, caKey, "multi-user", "agent-1", caps, 0, nil,
		time.Now().UTC().Truncate(time.Second), nil, userKey, "")
	var m1 map[string]any
	if err := json.Unmarshal(body1, &m1); err != nil {
		t.Fatal(err)
	}
	puid, _ := m1["principal_uid"].(string)
	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body1)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200 for first agent, got %d: %s", resp.StatusCode, string(bb[:n]))
	}

	// Issue a second cert for the same principal (MaxAgents unset → unlimited) → 200.
	body2, _ := agentProxyC3BodyWithKey(t, caCert, caKey, "multi-user", "agent-2", caps, 0, nil,
		time.Now().UTC().Truncate(time.Second), nil, userKey, puid)
	resp2 := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body2)))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp2.Body.Read(bb)
		t.Fatalf("expected 200 for second agent without max_agents, got %d: %s", resp2.StatusCode, string(bb[:n]))
	}
}

// TestServeIssueAgentProxyB3MaxSessionHours verifies B3: DelegationPolicy.
// MaxSessionHours limits agent-proxy AIC cert validity. After relaxing
// agent_proxy_max_validity, MaxSessionHours=2 (2h) trims issued cert validity to 2h.
func TestServeIssueAgentProxyB3MaxSessionHours(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	// Relax agent_proxy_max_validity to 24h (default 1h cannot distinguish trimming effects).
	srv.getConfig().Defaults.AgentProxyMaxValidity = "24h"
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "session-agent", "session-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["principal_authorization"] = map[string]any{
		"grants":            []map[string]any{{"scheme_id": "varwof-gateway-v1", "capability_id": "gateway:read"}},
		"delegation_policy": map[string]any{"allowed_mode": 0, "max_session_hours": 2},
	}
	okBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(okBody)))
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		resp.Body.Close()
		t.Fatalf("expected 200 with max_session_hours, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
	// Issued cert validity should be trimmed to ~2h (not 24h upper limit).
	var rr issueResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	blk, _ := pem.Decode([]byte(rr.CertPEM))
	if blk == nil {
		t.Fatal("no cert PEM in response")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got := cert.NotAfter.Sub(cert.NotBefore)
	if got > 3*time.Hour || got < 1*time.Hour {
		t.Fatalf("expected session-limited validity ~2h, got %s", got)
	}
}

// TestServeIssueAgentProxyC2ReasonRequired verifies C2: DA reason must be explicitly
// provided by the authorizer — missing user_auth_reason_code → 400
// api.reason_required (CA does not fabricate audit reasons for users).
func TestServeIssueAgentProxyC2ReasonRequired(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "no-reason-agent", "no-reason-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "user_auth_reason_code")
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 400 for missing reason_code, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
	bb := make([]byte, 512)
	n, _ := resp.Body.Read(bb)
	if !strings.Contains(string(bb[:n]), "reason_required") {
		t.Fatalf("expected api.reason_required, got: %s", string(bb[:n]))
	}
}

// TestServeIssueAgentProxyH10CrossSchemeGrantRejected verifies H10: a PA grant
// in a different scheme family must NOT cover an AIC capability (previously a
// bare CapabilityId match let "mysql-v1" grants cover "redis-v1" capabilities
// and vice versa — cross-scheme escalation).
func TestServeIssueAgentProxyH10CrossSchemeGrantRejected(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := agentProxyC3Body(t, caCert, caKey, "xs-agent", "xs-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["principal_authorization"] = map[string]any{
		"grants": []map[string]any{{"scheme_id": "database", "capability_id": "gateway:read"}},
	}
	badBody, _ := json.Marshal(m)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(badBody)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 500 (cross-scheme grant rejected), got %d: %s", resp.StatusCode, string(bb[:n]))
	}
	bb := make([]byte, 512)
	n, _ := resp.Body.Read(bb)
	if !strings.Contains(string(bb[:n]), "not covered") {
		t.Fatalf("expected 'not covered' rejection, got: %s", string(bb[:n]))
	}
}

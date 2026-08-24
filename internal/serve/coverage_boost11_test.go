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
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/i18n"
)

// newTestServerWithCA builds a full server with a known CA key (for signing
// user certs and issuing certs directly through ca.Sign).
func newTestServerWithCA(t *testing.T) (*Server, http.Handler, *x509.Certificate, crypto.Signer) {
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
	tsaDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("tsa-ok"))
	})
	ocspDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write([]byte("ocsp-ok"))
	})
	b := i18n.NewBundle()
	srv := NewFull(&cfg, d, b, tsaDummy, ocspDummy)
	return srv, WrapHandler(srv), caCert, caKey
}

// issueTestCert signs an end-entity certificate under the given CA key and
// stores it in the DB, returning the record.
func issueTestCert(t *testing.T, srv *Server, caCert *x509.Certificate, caKey crypto.Signer, cn string) (*db.CertRecord, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sc := &ca.SignConfig{
		DB:             srv.getDB(),
		CAKey:          caKey,
		CACert:         caCert,
		CAName:         "test-ca",
		SubjectPubKey:  &key.PublicKey,
		CommonName:     cn,
		Subject:        &pkix.Name{CommonName: cn},
		Validity:       24 * time.Hour,
		DefaultCountry: "CN",
		DefaultOrg:     "Test Org",
		Profile:        ca.ProfileTLSServer,
	}
	res, err := ca.Sign(sc)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec, err := srv.getDB().GetCert("test-ca", res.SerialHex)
	if err != nil || rec == nil {
		t.Fatalf("get record: %v", err)
	}
	return rec, key
}

// ─── apiFindCertByKey ─────────────────────────────────────────────

func TestFindCertByKey(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// 405
	w := httptest.NewRecorder()
	srv.apiFindCertByKey(w, httptest.NewRequest("POST", "/api/v1/cert/by-key", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// missing hash → 400
	w2 := httptest.NewRecorder()
	srv.apiFindCertByKey(w2, httptest.NewRequest("GET", "/api/v1/cert/by-key", nil))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w2.Code)
	}
	// success with a real cert
	rec, key := issueTestCert(t, srv, caCert, caKey, "by-key-cert")
	_ = rec
	hash := ca.SPKIHash(&key.PublicKey)
	hexHash := strings.ToLower(hexEncode(hash))
	w3 := httptest.NewRecorder()
	srv.apiFindCertByKey(w3, httptest.NewRequest("GET", "/api/v1/cert/by-key?hash="+hexHash, nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	// with ca + status filters
	w4 := httptest.NewRecorder()
	srv.apiFindCertByKey(w4, httptest.NewRequest("GET", "/api/v1/cert/by-key?hash="+hexHash+"&ca=test-ca&status=V", nil))
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200 w/ filters, got %d", w4.Code)
	}
	// no match → empty list, still 200
	w5 := httptest.NewRecorder()
	srv.apiFindCertByKey(w5, httptest.NewRequest("GET", "/api/v1/cert/by-key?hash=deadbeef", nil))
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200 empty, got %d", w5.Code)
	}
}

// ─── apiReSignCert ────────────────────────────────────────────────

func TestReSignCert(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// 405
	w := httptest.NewRecorder()
	srv.apiReSignCert(w, httptest.NewRequest("GET", "/api/v1/cert/test-ca/1/re-sign", nil), "test-ca", "1")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// missing cert → 404
	w2 := httptest.NewRecorder()
	srv.apiReSignCert(w2, httptest.NewRequest("POST", "/api/v1/cert/test-ca/zzz/re-sign", strings.NewReader(`{}`)), "test-ca", "zzz")
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w2.Code)
	}
	// success
	rec, _ := issueTestCert(t, srv, caCert, caKey, "resign-me")
	w3 := httptest.NewRecorder()
	srv.apiReSignCert(w3, httptest.NewRequest("POST", "/api/v1/cert/test-ca/"+rec.SerialNumber+"/re-sign", strings.NewReader(`{"validity":30}`)), "test-ca", rec.SerialNumber)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	// unknown target CA → 404
	w4 := httptest.NewRecorder()
	srv.apiReSignCert(w4, httptest.NewRequest("POST", "/api/v1/cert/test-ca/"+rec.SerialNumber+"/re-sign", strings.NewReader(`{"target_ca":"nope"}`)), "test-ca", rec.SerialNumber)
	if w4.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing target CA, got %d", w4.Code)
	}
}

// ─── apiRevokeByPrincipal ─────────────────────────────────────────

func TestRevokeByPrincipal(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// 405
	w := httptest.NewRecorder()
	srv.apiRevokeByPrincipal(w, httptest.NewRequest("GET", "/api/v1/certs/revoke-by-principal", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// bad json → 400
	w2 := httptest.NewRecorder()
	srv.apiRevokeByPrincipal(w2, httptest.NewRequest("POST", "/api/v1/certs/revoke-by-principal", strings.NewReader("{bad")))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w2.Code)
	}
	// empty principal → 400
	w3 := httptest.NewRecorder()
	srv.apiRevokeByPrincipal(w3, httptest.NewRequest("POST", "/api/v1/certs/revoke-by-principal", strings.NewReader(`{}`)))
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3.Code)
	}
	// success — no matching certs → 0 revoked
	w4 := httptest.NewRecorder()
	srv.apiRevokeByPrincipal(w4, httptest.NewRequest("POST", "/api/v1/certs/revoke-by-principal", strings.NewReader(`{"principal_uid":"nobody@example.com"}`)))
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w4.Code, w4.Body.String())
	}
	// success — revoke an actual cert
	_, key := issueTestCert(t, srv, caCert, caKey, "revoke-by-principal-cert")
	_ = key
	// Sign an AIC-profile cert with principal_uid so the SQL path matches
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pu := ca.PrincipalUid{Realm: "pki", Identifier: "victim@example.com", KeyHash: ca.SPKIHash(&agentKey.PublicKey)}
	sc := &ca.SignConfig{
		DB:            srv.getDB(),
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &agentKey.PublicKey,
		CommonName:    "agent-1",
		Subject:       &pkix.Name{CommonName: "agent-1", OrganizationalUnit: []string{"gateway:ops"}},
		Validity:      time.Hour,
		Profile:       ca.ProfileAgentProxy,
		AIC: &ca.AICConfig{
			AgentId:      "agent-1",
			PrincipalUid: pu,
			Capabilities: []ca.Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT"}},
			DelegationAuthorization: &ca.DelegationAuthorization{
				Reason:             ca.Reason{ReasonCode: "TEST", Description: "test"},
				SignatureValue:     []byte{1},
				SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
				Timestamp:          time.Now(),
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
			},
		},
	}
	if _, err := ca.Sign(sc); err != nil {
		t.Fatalf("sign aic: %v", err)
	}
	w5 := httptest.NewRecorder()
	srv.apiRevokeByPrincipal(w5, httptest.NewRequest("POST", "/api/v1/certs/revoke-by-principal", strings.NewReader(`{"principal_uid":"`+pu.String()+`"}`)))
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w5.Code, w5.Body.String())
	}
	var resp struct {
		RevokedCount int `json:"revoked_count"`
	}
	if err := json.Unmarshal(w5.Body.Bytes(), &resp); err != nil || resp.RevokedCount < 1 {
		t.Fatalf("expected ≥1 revoked, got %+v (err %v)", resp, err)
	}
}

// ─── apiListSubCAs / apiRevokeSubCA / apiRevokeSubCAAll ───────────

func TestSubCAHandlers(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	superCert := scopedAdminCert(t, srv.getDB(), "SuperAdmin", "Management CA")
	hdr := func(r *http.Request) {
		r.Header.Set("X-Admin-Cert", pemCert(superCert))
	}

	// List: no admin cert → 401
	w := httptest.NewRecorder()
	srv.apiListSubCAs(w, httptest.NewRequest("GET", "/api/v1/sub-cas", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// List: wrong method → 405
	w0 := httptest.NewRecorder()
	r0 := httptest.NewRequest("POST", "/api/v1/sub-cas", nil)
	hdr(r0)
	srv.apiListSubCAs(w0, r0)
	if w0.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w0.Code)
	}
	// List: with admin cert → 200 empty
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/sub-cas?protocol=est", nil)
	hdr(r2)
	srv.apiListSubCAs(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// Revoke: wrong method → 405
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/api/v1/sub-ca/test-ca/revoke", nil)
	hdr(r3)
	srv.apiRevokeSubCA(w3, r3, "test-ca")
	if w3.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w3.Code)
	}
	// Revoke: no admin cert → 401
	w4 := httptest.NewRecorder()
	srv.apiRevokeSubCA(w4, httptest.NewRequest("POST", "/api/v1/sub-ca/test-ca/revoke", strings.NewReader(`{}`)), "test-ca")
	if w4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w4.Code)
	}
	// Create a real sub-CA (superadmin) so revoke has a target.
	createBody := `{"name":"test-sub","parent_ca":"test-ca","validity":"3650h"}`
	wc := httptest.NewRecorder()
	rc := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(createBody))
	rc.Header.Set("Content-Type", "application/json")
	rc.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(wc, rc)
	if wc.Code != http.StatusOK {
		t.Fatalf("create sub-ca: got %d: %s", wc.Code, wc.Body.String())
	}
	// Revoke: success (superadmin scope-exempt)
	w5 := httptest.NewRecorder()
	r5 := httptest.NewRequest("POST", "/api/v1/sub-ca/test-sub/revoke", strings.NewReader(`{"reason":1}`))
	hdr(r5)
	srv.apiRevokeSubCA(w5, r5, "test-sub")
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w5.Code, w5.Body.String())
	}

	// RevokeAll: success (create another sub-CA first)
	createBody2 := `{"name":"test-sub2","parent_ca":"test-ca","validity":"3650h"}`
	wc2 := httptest.NewRecorder()
	rc2 := httptest.NewRequest("POST", "/api/v1/sub-cas", strings.NewReader(createBody2))
	rc2.Header.Set("Content-Type", "application/json")
	rc2.Header.Set("X-Admin-Cert", pemCert(superCert))
	srv.apiCreateSubCA(wc2, rc2)
	if wc2.Code != http.StatusOK {
		t.Fatalf("create sub-ca2: got %d: %s", wc2.Code, wc2.Body.String())
	}
	w6 := httptest.NewRecorder()
	r6 := httptest.NewRequest("POST", "/api/v1/sub-ca/test-sub2/revoke-all", strings.NewReader(`{"reason":"keyCompromise"}`))
	hdr(r6)
	srv.apiRevokeSubCAAll(w6, r6, "test-sub2")
	if w6.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w6.Code, w6.Body.String())
	}
	// RevokeAll: wrong method → 405
	w7 := httptest.NewRecorder()
	r7 := httptest.NewRequest("GET", "/api/v1/sub-ca/test-ca/revoke-all", nil)
	hdr(r7)
	srv.apiRevokeSubCAAll(w7, r7, "test-ca")
	if w7.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w7.Code)
	}
	// RevokeAll: no admin cert → 401
	w8 := httptest.NewRecorder()
	srv.apiRevokeSubCAAll(w8, httptest.NewRequest("POST", "/api/v1/sub-ca/test-ca/revoke-all", nil), "test-ca")
	if w8.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w8.Code)
	}

	_ = caCert
	_ = caKey
}

// ─── apiIssueAIC (with full mTLS success path) ────────────────────

func TestIssueAIC(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// 405
	w := httptest.NewRecorder()
	srv.apiIssueAIC(w, httptest.NewRequest("GET", "/api/v1/aic/issue", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// no mTLS → 401
	w2 := httptest.NewRecorder()
	srv.apiIssueAIC(w2, httptest.NewRequest("POST", "/api/v1/aic/issue", strings.NewReader(`{}`)))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w2.Code)
	}
	// bad json → 400
	userCert, userKey := newUserCert(t, caCert, caKey, "user@example.com")
	w3 := httptest.NewRecorder()
	r3 := mtlsRequest(t, userCert, "{bad")
	srv.apiIssueAIC(w3, r3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3.Code)
	}
	// missing agent_id → 400
	w4 := httptest.NewRecorder()
	r4 := mtlsRequest(t, userCert, `{"principal_uid":"u","capabilities":[{"scheme_id":"a","capability_id":"b"}]}`)
	srv.apiIssueAIC(w4, r4)
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w4.Code)
	}
	// no capabilities → 400
	w5 := httptest.NewRecorder()
	r5 := mtlsRequest(t, userCert, `{"agent_id":"a","principal_uid":"u"}`)
	srv.apiIssueAIC(w5, r5)
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w5.Code)
	}
	// missing delegation → 403
	w6 := httptest.NewRecorder()
	r6 := mtlsRequest(t, userCert, `{"agent_id":"a","principal_uid":"u","capabilities":[{"scheme_id":"a","capability_id":"b"}]}`)
	srv.apiIssueAIC(w6, r6)
	if w6.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w6.Code)
	}

	// ── full success path ──
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ts := time.Now().Unix()
	caps := []ca.Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT"}}
	msg := delegationMessageJSON{
		AgentID:      "agent-1",
		PrincipalUID: "user@example.com",
		Capabilities: caps,
		Timestamp:    ts,
		Nonce:        nonce,
		LifetimeSec:  3600,
	}
	msgBytes, _ := json.Marshal(msg)
	hash := sha256.Sum256(msgBytes)
	sig, err := userKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"agent_id":      "agent-1",
		"principal_uid": "user@example.com",
		"capabilities":  caps,
		"duration":      "5m",
		"key_type":      "ecdsa-p256",
		"delegation": delegationSigJSON{
			Signature:   sig,
			Algo:        "ECDSA-SHA256",
			Nonce:       nonce,
			Timestamp:   ts,
			LifetimeSec: 3600,
		},
	}
	bodyJSON, _ := json.Marshal(body)
	w7 := httptest.NewRecorder()
	r7 := mtlsRequest(t, userCert, string(bodyJSON))
	srv.apiIssueAIC(w7, r7)
	if w7.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w7.Code, w7.Body.String())
	}

	// ── issuer CA mismatch → 403 ──
	otherCert, otherKey := newTestCA(t, "other-ca")
	badUser, _ := newUserCert(t, otherCert, otherKey, "elsewhere@example.com")
	w8 := httptest.NewRecorder()
	r8 := mtlsRequest(t, badUser, string(bodyJSON))
	srv.apiIssueAIC(w8, r8)
	if w8.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (issuer mismatch), got %d: %s", w8.Code, w8.Body.String())
	}
}

// newUserCert builds an end-entity cert signed by the given CA.
func newUserCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return newUserCertOU(t, caCert, caKey, cn, nil, "core:cert:list")
}

// newUserCertOU builds an end-entity cert with the given OUs.
func newUserCertOU(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, cn string, ous []string, caps ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var grants []ca.Capability
	for _, c := range caps {
		scheme, action := c, c
		if i := strings.Index(c, ":"); i > 0 {
			scheme, action = c[:i], c[i+1:]
		}
		grants = append(grants, ca.Capability{SchemeId: scheme, CapabilityId: action})
	}
	paExt, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:     big.NewInt(time.Now().UnixNano()),
		Subject:          pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		KeyUsage:         x509.KeyUsageDigitalSignature,
		ExtKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions:  []pkix.Extension{paExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mtlsRequest(t *testing.T, peer *x509.Certificate, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/aic/issue", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	return r
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0xf]
	}
	return string(out)
}

// ─── apiRevokeCertsBatch ──────────────────────────────────────────

func TestRevokeCertsBatch(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// 405
	w := httptest.NewRecorder()
	srv.apiRevokeCertsBatch(w, httptest.NewRequest("GET", "/api/v1/certs/revoke-batch", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	// bad json → 400
	w2 := httptest.NewRecorder()
	srv.apiRevokeCertsBatch(w2, httptest.NewRequest("POST", "/api/v1/certs/revoke-batch", strings.NewReader("{bad")))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w2.Code)
	}
	// empty entries → 400
	w3 := httptest.NewRecorder()
	srv.apiRevokeCertsBatch(w3, httptest.NewRequest("POST", "/api/v1/certs/revoke-batch", strings.NewReader(`{"entries":[]}`)))
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3.Code)
	}
	// missing ca/serial → 400
	w3b := httptest.NewRecorder()
	srv.apiRevokeCertsBatch(w3b, httptest.NewRequest("POST", "/api/v1/certs/revoke-batch", strings.NewReader(`{"entries":[{"ca":"test-ca"}]}`)))
	if w3b.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3b.Code)
	}

	// Issue two certs, then batch-revoke both.
	rec1, _ := issueTestCert(t, srv, caCert, caKey, "batch-revoke-1")
	rec2, _ := issueTestCert(t, srv, caCert, caKey, "batch-revoke-2")

	body := `{"entries":[{"ca":"test-ca","serial":"` + rec1.SerialNumber + `","reason":"keyCompromise"},{"ca":"test-ca","serial":"` + rec2.SerialNumber + `"}]}`
	w4 := httptest.NewRecorder()
	srv.apiRevokeCertsBatch(w4, httptest.NewRequest("POST", "/api/v1/certs/revoke-batch", strings.NewReader(body)))
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w4.Code, w4.Body.String())
	}
	var resp struct {
		RevokedCount int `json:"revoked_count"`
	}
	if err := json.Unmarshal(w4.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RevokedCount != 2 {
		t.Fatalf("expected 2 revoked, got %d", resp.RevokedCount)
	}
	// Both now revoked in DB.
	for _, rec := range []*db.CertRecord{rec1, rec2} {
		st, err := srv.getDB().GetCertStatus("test-ca", rec.SerialNumber)
		if err != nil || st.Status != "R" {
			t.Fatalf("serial %s status = %+v err=%v", rec.SerialNumber, st, err)
		}
	}
	// Non-target cert still valid.
	rec3, _ := issueTestCert(t, srv, caCert, caKey, "batch-revoke-keep")
	st, err := srv.getDB().GetCertStatus("test-ca", rec3.SerialNumber)
	if err != nil || st.Status != "V" {
		t.Fatalf("control serial should stay V: %+v err=%v", st, err)
	}
}

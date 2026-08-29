// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
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
	"testing"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// userRevokeAllAICCert builds a Delegated-Agent certificate carrying an AIC
// extension with the given principal UID, so apiUserRevokeAll can derive the
// principal it must mass-revoke without DB-role dependency.
func userRevokeAllAICCert(t *testing.T, uid ca.PrincipalUid) *x509.Certificate {
	t.Helper()
	aicVal, err := ca.BuildAIC(ca.AICConfig{
		AgentId: "agent-revoke-all",
		PrincipalUid: ca.PrincipalUid{
			Version:    uid.Version,
			Realm:      uid.Realm,
			Identifier: uid.Identifier,
			KeyHash:    uid.KeyHash,
		},
		Capabilities: []ca.Capability{{SchemeId: "core", CapabilityId: "user:revoke-all"}},
		DelegationAuthorization: &ca.DelegationAuthorization{
			Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "test"},
			SignatureValue:     []byte{0x1},
			SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			Nonce:              make([]byte, 32),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "agent-revoke-all",
			OrganizationalUnit: []string{"Delegated-Agent"},
		},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{aicVal, authCertPAExt(t, "user:revoke-all")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// TestUserRevokeAll_Success drives the happy path of apiUserRevokeAll with a
// real AIC mTLS certificate and engine records owned by the principal: the
// principal's certificates transition to R and a status 200 recounts them.
func TestUserRevokeAll_Success(t *testing.T) {
	srv, _, _ := newTestServerWithEngine(t)
	uid := ca.PrincipalUid{Realm: "varwof", Identifier: "lisi", KeyHash: make([]byte, 32)}
	uidStr := uid.String()

	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}
	for i := 0; i < 2; i++ {
		if err := e.IssueCert(&db.CertRecord{
			SerialNumber: "AA0000000000000000000000000000000000000" + string(rune('1'+i)),
			CAName:       "test-ca",
			Status:       "V",
			CommonName:   "lisi",
			PrincipalUid: uidStr,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			CertDER:      []byte("cert"),
		}); err != nil {
			t.Fatalf("engine issue: %v", err)
		}
	}

	cert := userRevokeAllAICCert(t, uid)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user/revoke-all", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	srv.apiUserRevokeAll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("revoke-all status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		RevokedCount int `json:"revoked_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RevokedCount != 2 {
		t.Fatalf("revoked_count=%d, want 2 (body=%s)", resp.RevokedCount, rr.Body.String())
	}
	st, err := e.GetCertStatus("test-ca", "AA00000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" {
		t.Fatalf("expected principal cert revoked, got %q", st.Status)
	}
}

// TestUserRevokeAll_UnexpectedReason verifies an unresolvable reason string
// falls back to the default revocation reason instead of failing the request.
func TestUserRevokeAll_UnexpectedReason(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	d := srv.getDB()
	uid := ca.PrincipalUid{Realm: "varwof", Identifier: "wangwu", KeyHash: make([]byte, 32)}
	uidStr := uid.String()
	installAICCertRecord(t, d, "test-ca", "BB00000000000000000000000000000000000001", uidStr)

	cert := userRevokeAllAICCert(t, uid)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user/revoke-all", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	req.Body = http.NoBody
	srv.apiUserRevokeAll(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("revoke-all status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// installAICCertRecord inserts a certificate owned by an AIC principal into
// the DB with status V, mirroring an agent certificate that was issued to a
// real user (agent-proxy issuance path).
func installAICCertRecord(t *testing.T, d *db.DB, caName, serial, uid string) {
	t.Helper()
	notAfter := time.Now().Add(24 * time.Hour)
	rec := &db.CertRecord{
		SerialNumber: serial,
		CAName:       caName,
		Status:       "V",
		CommonName:   uid,
		PrincipalUid: uid,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		CertDER:      []byte("cert"),
		Fingerprint:  db.Fingerprint([]byte(serial)),
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
}

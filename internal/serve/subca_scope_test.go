// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

var scopeExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1}

var scopedCertCounter int64

// scopedAdminCert builds a structurally-valid admin entity cert (DigitalSignature
// KU + ClientAuth EKU + role OU) with the given management scope (SAN URI +
// OID dual-write), self-signed, and registers its cert as a DB trust anchor so
// the H9 chain-verification path (ValidateAdminCertFromPEMWithPool) can verify
// it. The trust anchor registration models the production setup where admin
// certs chain to the PKI's trust roots.
func scopedAdminCert(t *testing.T, d *db.DB, ou, scope string) *x509.Certificate {
	t.Helper()
	id := atomic.AddInt64(&scopedCertCounter, 1)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(id),
		Subject: pkix.Name{
			CommonName:         ou + "@test",
			OrganizationalUnit: []string{ou},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if scope != "" {
		u, _ := url.Parse("urn:pki:ca:" + scope)
		tmpl.URIs = []*url.URL{u}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: scopeExtOID, Value: []byte(scope),
		})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if d != nil {
		if err := d.InsertTrustAnchor(&db.TrustAnchor{
			Name:            "admin-test-root",
			HashID:          "admin-test-" + fmt.Sprintf("%d", id),
			CertDER:         cert.Raw,
			Subject:         cert.Subject.String(),
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
			Issuer:          cert.Issuer.String(),
			Trusted:         true,
			Source:          "test",
			SHA1Fingerprint: db.Fingerprint(cert.Raw),
		}); err != nil {
			t.Fatalf("insert admin trust anchor: %v", err)
		}
	}
	return cert
}

func pemCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func pemKey(key crypto.Signer) string {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestVerifyAdminCertTargetScope(t *testing.T) {
	srv, _ := newTestServerWithDB(t)

	superCert := scopedAdminCert(t, srv.getDB(), "SuperAdmin", "Management CA")
	adminCert := scopedAdminCert(t, srv.getDB(), "admin", "Client CA")
	noScopeCert := scopedAdminCert(t, srv.getDB(), "admin", "")

	// superadmin is framework role (scope-exempt): can manage ANY sub-CA.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Client CA"), nil)
	r.Header.Set("X-Admin-Cert", pemCert(superCert))
	if err := srv.verifyAdminCert(r, "Client CA"); err != nil {
		t.Errorf("superadmin (scope-exempt) should manage any sub-CA: %v", err)
	}

	// superadmin can also manage its own scope (Management CA).
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Management CA"), nil)
	r2.Header.Set("X-Admin-Cert", pemCert(superCert))
	if err := srv.verifyAdminCert(r2, "Management CA"); err != nil {
		t.Errorf("superadmin should manage Management CA: %v", err)
	}

	// scoped admin: can manage Client CA, not other CAs.
	r3 := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Client CA"), nil)
	r3.Header.Set("X-Admin-Cert", pemCert(adminCert))
	if err := srv.verifyAdminCert(r3, "Client CA"); err != nil {
		t.Errorf("scoped admin should manage Client CA: %v", err)
	}
	r4 := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("VPN CA"), nil)
	r4.Header.Set("X-Admin-Cert", pemCert(adminCert))
	if err := srv.verifyAdminCert(r4, "VPN CA"); err == nil {
		t.Error("scoped admin must not manage VPN CA")
	}

	// No-scope cert: denied for any target CA.
	r5 := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Client CA"), nil)
	r5.Header.Set("X-Admin-Cert", pemCert(noScopeCert))
	if err := srv.verifyAdminCert(r5, "Client CA"); err == nil {
		t.Error("no-scope admin cert must be denied a target CA")
	}

	// List (empty target): structural validation only.
	if err := srv.verifyAdminCert(r3, ""); err != nil {
		t.Errorf("list should only require a valid admin cert: %v", err)
	}
}

func TestCreateSubCARequiresSuperadmin(t *testing.T) {
	srv, h := newTestServerWithDB(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	body := `{"name":"test-new-sub","parent_ca":"test-ca","validity":"3650h"}`
	adminCert := scopedAdminCert(t, srv.getDB(), "admin", "Client CA")
	superCert := scopedAdminCert(t, srv.getDB(), "SuperAdmin", "Management CA")

	post := func(pemC string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sub-cas", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Cert", pemC)
		rec := httptest.NewRecorder()
		srv.apiCreateSubCA(rec, req)
		return rec
	}

	// Non-superadmin admin → 403 even though cert is structurally valid.
	if rec := post(pemCert(adminCert)); rec.Code != http.StatusForbidden {
		t.Errorf("admin create sub-CA: got %d, want 403", rec.Code)
	}

	// superadmin → creates the sub-CA.
	rec := post(pemCert(superCert))
	if rec.Code != http.StatusOK {
		t.Errorf("superadmin create sub-CA: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// Scoped admin can then fetch/revoke only its own sub-CA.
	scoped := scopedAdminCert(t, srv.getDB(), "admin", "test-new-sub")
	get := func(name string, c *x509.Certificate) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape(name), nil)
		req.Header.Set("X-Admin-Cert", pemCert(c))
		rec2 := httptest.NewRecorder()
		srv.apiGetSubCA(rec2, req, name)
		return rec2.Code
	}
	if code := get("test-new-sub", scoped); code != http.StatusOK {
		t.Errorf("scoped admin get own sub-CA: got %d, want 200", code)
	}
	// superadmin (framework role, scope-exempt) can manage any sub-CA.
	if code := get("test-new-sub", superCert); code != http.StatusOK {
		t.Errorf("superadmin get business sub-CA: got %d, want 200 (scope-exempt)", code)
	}
}

func TestExtractCANameFromRequestBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/certs", strings.NewReader(`{"ca":"Client CA","cn":"x"}`))
	if got := extractCANameFromRequest(r); got != "Client CA" {
		t.Errorf("extract from body = %q, want %q", got, "Client CA")
	}
	// Body must be restored for the downstream handler.
	var m struct {
		CA string `json:"ca"`
		CN string `json:"cn"`
	}
	if err := jsonDecodeBody(r, &m); err != nil {
		t.Fatalf("body not restored: %v", err)
	}
	if m.CA != "Client CA" || m.CN != "x" {
		t.Errorf("restored body = %+v", m)
	}

	// Path takes precedence over body.
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/crl/"+url.PathEscape("VPN CA")+"/generate", strings.NewReader(`{"ca":"Other"}`))
	if got := extractCANameFromRequest(r2); got != "VPN CA" {
		t.Errorf("path should take precedence, got %q", got)
	}

	// Query param.
	r3 := httptest.NewRequest(http.MethodGet, "/api/v1/certs?ca="+url.PathEscape("ACME CA"), nil)
	if got := extractCANameFromRequest(r3); got != "ACME CA" {
		t.Errorf("query extract = %q", got)
	}

	// GET has no body scan.
	r4 := httptest.NewRequest(http.MethodGet, "/api/v1/certs", strings.NewReader(`{"ca":"x"}`))
	if got := extractCANameFromRequest(r4); got != "" {
		t.Errorf("GET should not scan body, got %q", got)
	}
}

func jsonDecodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// TestVerifyAdminCertRejectsUntrustedSelfSigned verifies the H9 fix: an admin
// certificate that is NOT chained to the PKI's trust pool (a self-signed cert
// not registered as a trust anchor) must be rejected, even if it is
// structurally valid (KU + EKU + role OU + scope). Previously the PEM header
// path skipped chain verification entirely (fail-open).
func TestVerifyAdminCertRejectsUntrustedSelfSigned(t *testing.T) {
	srv, _ := newTestServerWithDB(t)

	// Build a structurally-valid self-signed admin cert WITHOUT registering it
	// as a trust anchor (pass nil DB → no InsertTrustAnchor).
	rogue := scopedAdminCert(t, nil, "admin", "Client CA")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Client CA"), nil)
	r.Header.Set("X-Admin-Cert", pemCert(rogue))
	if err := srv.verifyAdminCert(r, "Client CA"); err == nil {
		t.Fatal("untrusted self-signed admin cert must be rejected (H9 chain verification)")
	}
}

// TestVerifyAdminCertTrustedByAnchor verifies a self-signed admin cert that IS
// registered as a DB trust anchor passes chain verification (models the
// production trust setup).
func TestVerifyAdminCertTrustedByAnchor(t *testing.T) {
	srv, _ := newTestServerWithDB(t)
	trusted := scopedAdminCert(t, srv.getDB(), "admin", "Client CA")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sub-ca/"+url.PathEscape("Client CA"), nil)
	r.Header.Set("X-Admin-Cert", pemCert(trusted))
	if err := srv.verifyAdminCert(r, "Client CA"); err != nil {
		t.Fatalf("trusted admin cert should verify: %v", err)
	}
}

// M11: the sub-CA create response must not serialize the private key; the key
// is retained encrypted server-side and must never leave the server via the API.
func TestCreateSubCAResponseOmitsPrivateKey(t *testing.T) {
	resp := createSubCAResponse{
		Name:        "sub",
		CertPEM:     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		SerialHex:   "0102",
		Fingerprint: "aa:bb",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"key_pem", "private_key", "key"} {
		if _, ok := m[key]; ok {
			t.Fatalf("create response must not expose private key via %q", key)
		}
	}
	if !strings.Contains(string(b), "cert_pem") {
		t.Fatal("cert_pem should still be present")
	}
}

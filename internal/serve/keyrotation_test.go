package serve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRotatingSignerRegistry(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	rs, err := srv.rotatingSigner("test-ca")
	if err != nil {
		t.Fatalf("rotatingSigner: %v", err)
	}
	if rs == nil || rs.Cert() == nil {
		t.Fatal("expected a rotating signer with active cert")
	}

	// Same instance on repeat call (cached).
	rs2, _ := srv.rotatingSigner("test-ca")
	if rs2 != rs {
		t.Fatal("rotating signer should be cached per CA")
	}

	// Unknown CA.
	if _, err := srv.rotatingSigner("nope"); err == nil {
		t.Fatal("expected error for unknown CA")
	}
}

func TestAPICARotationInfo(t *testing.T) {
	_, handler, _, _ := newTestServerWithCA(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/test-ca/rotation", nil)
	req.SetBasicAuth("admin", "admin")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotation info status: %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if body["ca"] != "test-ca" {
		t.Fatalf("unexpected ca field: %v", body["ca"])
	}
	if body["serial"] == "" {
		t.Fatal("expected serial in rotation info")
	}
	if _, ok := body["not_after"]; !ok {
		t.Fatal("expected not_after")
	}

	// Unknown CA.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/ca/nope/rotation", nil)
	req2.SetBasicAuth("admin", "admin")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	var body2 map[string]any
	json.Unmarshal(rr2.Body.Bytes(), &body2)
	if body2["error"] == "" {
		t.Fatal("expected error for unknown CA")
	}
}

func TestAPICARotate(t *testing.T) {
	srv, handler, caCert, _ := newTestServerWithCA(t)

	// Create a NEW CA certificate (same identity, new key) signed by a parent.
	parentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parentTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Parent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parentDER, _ := x509.CreateCertificate(rand.Reader, parentTmpl, parentTmpl, &parentKey.PublicKey, parentKey)
	parentCert, _ := x509.ParseCertificate(parentDER)

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               caCert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	newDER, err := x509.CreateCertificate(rand.Reader, newTmpl, parentCert, &newKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	newCert, _ := x509.ParseCertificate(newDER)
	_ = newCert

	// PEM encode.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(newKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	body := fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/test-ca/rotate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "admin")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "rotated" {
		t.Fatalf("expected rotated status, got %v", resp["status"])
	}

	// The rotating signer's active key must now be the new one.
	rs, _ := srv.rotatingSigner("test-ca")
	if rs.Cert() == nil || !bytes.Equal(rs.Cert().Raw, newDER) {
		t.Fatal("active cert should be the rotated one")
	}
	if lg := rs.Legacy(); lg == nil {
		t.Fatal("legacy cert should be retained after rotation")
	}

	// Sign with the rotating signer and verify against new cert.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "rotated-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rs.Cert(), &leafKey.PublicKey, rs)
	if err != nil {
		t.Fatalf("sign with rotated key: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	if err := leafCert.CheckSignatureFrom(rs.Cert()); err != nil {
		t.Fatalf("leaf verify: %v", err)
	}
}

func TestAPICARotateErrors(t *testing.T) {
	_, handler, _, _ := newTestServerWithCA(t)

	t.Run("missing body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/test-ca/rotate", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", "admin")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("bad cert pem", func(t *testing.T) {
		body := `{"cert_pem":"not-a-cert","key_pem":"not-a-key"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/test-ca/rotate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", "admin")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "Mismatch CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

		// Use a different key.
		key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key2)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

		body := fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/test-ca/rotate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", "admin")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for key mismatch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestStartCARotationMonitorStopsCleanly(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	stop := srv.StartCARotationMonitor(time.Hour)
	if stop == nil {
		t.Fatal("expected stop function")
	}
	stop()
	// Second stop is idempotent (no panic).
	stop()
}

func TestCheckCARotationsNoPanic(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)
	srv.checkCARotations() // must not panic
}

// TestLoadCAKeySnapshotConsistency (M8 fix): loadCAKey must return an issuer
// cert and a key from the same atomic snapshot. After rotation, a subsequent
// call must return the NEW pair together, never the old cert with the new key.
func TestLoadCAKeySnapshotConsistency(t *testing.T) {
	srv, handler, _, _ := newTestServerWithCA(t)

	// Create a new CA cert+key for rotation.
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Rotated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	newDER, _ := x509.CreateCertificate(rand.Reader, newTmpl, newTmpl, &newKey.PublicKey, newKey)
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER})
	newKeyDER, _ := x509.MarshalPKCS8PrivateKey(newKey)
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newKeyDER})

	body := fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, string(newCertPEM), string(newKeyPEM))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/test-ca/rotate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "admin")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate status: %d body=%s", rr.Code, rr.Body.String())
	}

	cert, key, err := srv.loadCAKey("test-ca")
	if err != nil {
		t.Fatalf("loadCAKey: %v", err)
	}
	// The snapshot cert and key must belong together: the cert's public key
	// must equal the returned signer's public key.
	if !bytes.Equal(cert.Raw, newDER) {
		t.Fatal("loadCAKey should return the rotated cert after rotation")
	}
	pubA, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	pubB, _ := x509.MarshalPKIXPublicKey(key.Public())
	if !bytes.Equal(pubA, pubB) {
		t.Fatal("loadCAKey cert and key are from different snapshots (M8 TOCTOU)")
	}
}

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func TestIssueSubCA(t *testing.T) {
	// Create a test database
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer database.Close()

	// Create a test root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSerial, _ := randomSerial()
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Country:      []string{"CN"},
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}

	rootCert, _ := x509.ParseCertificate(rootCertDER)

	// Store root CA in database
	err = database.InsertCAMeta(&db.CAMeta{
		Name:         "test-root-ca",
		CertDER:      rootCertDER,
		Subject:      rootCert.Subject.String(),
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(rootCertDER),
	})
	if err != nil {
		t.Fatalf("failed to store root CA: %v", err)
	}

	// Test creating a sub-CA
	cfg := &SubCAConfig{
		Name:       "test-sub-ca",
		ParentCA:   "test-root-ca",
		KeyType:    "ecdsa-p256",
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: 0,
		Protocol:   "scep",
		KeyUsage:   []string{"key_cert_sign", "crl_sign"},
	}

	result, err := IssueSubCA(database, cfg, rootCert, rootKey)
	if err != nil {
		t.Fatalf("failed to issue sub-CA: %v", err)
	}

	if result.Name != "test-sub-ca" {
		t.Errorf("expected name 'test-sub-ca', got '%s'", result.Name)
	}

	if result.Cert == nil {
		t.Error("expected certificate to be non-nil")
	}

	if result.CertPEM == nil {
		t.Error("expected certificate PEM to be non-nil")
	}

	if result.KeyPEM == nil {
		t.Error("expected key PEM to be non-nil")
	}

	if result.Fingerprint == "" {
		t.Error("expected fingerprint to be non-empty")
	}

	// Verify the certificate
	if !result.Cert.IsCA {
		t.Error("expected certificate to be a CA")
	}

	if result.Cert.MaxPathLen != 0 {
		t.Errorf("expected max path length 0, got %d", result.Cert.MaxPathLen)
	}

	// Verify the certificate chain
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	_, err = result.Cert.Verify(x509.VerifyOptions{
		Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Errorf("failed to verify sub-CA certificate: %v", err)
	}
}

func TestGetSubCA(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer database.Close()

	// Create and store a test sub-CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSerial, _ := randomSerial()
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	err = database.InsertCAMeta(&db.CAMeta{
		Name:         "test-root-ca",
		CertDER:      rootCertDER,
		Subject:      rootCert.Subject.String(),
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(rootCertDER),
	})
	if err != nil {
		t.Fatalf("failed to store root CA: %v", err)
	}

	// Create sub-CA
	cfg := &SubCAConfig{
		Name:       "test-sub-ca",
		ParentCA:   "test-root-ca",
		KeyType:    "ecdsa-p256",
		Validity:   5 * 365 * 24 * time.Hour,
		Protocol:   "scep",
	}

	_, err = IssueSubCA(database, cfg, rootCert, rootKey)
	if err != nil {
		t.Fatalf("failed to issue sub-CA: %v", err)
	}

	// Test getting sub-CA
	subCA, err := GetSubCA(database, "test-sub-ca")
	if err != nil {
		t.Fatalf("failed to get sub-CA: %v", err)
	}

	if subCA.Name != "test-sub-ca" {
		t.Errorf("expected name 'test-sub-ca', got '%s'", subCA.Name)
	}

	if subCA.ParentCA != "test-root-ca" {
		t.Errorf("expected parent CA 'test-root-ca', got '%s'", subCA.ParentCA)
	}

	if subCA.Protocol != "scep" {
		t.Errorf("expected protocol 'scep', got '%s'", subCA.Protocol)
	}

	if subCA.Status != "active" {
		t.Errorf("expected status 'active', got '%s'", subCA.Status)
	}
}

func TestListSubCAs(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer database.Close()

	// Create root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSerial, _ := randomSerial()
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	err = database.InsertCAMeta(&db.CAMeta{
		Name:         "test-root-ca",
		CertDER:      rootCertDER,
		Subject:      rootCert.Subject.String(),
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(rootCertDER),
	})
	if err != nil {
		t.Fatalf("failed to store root CA: %v", err)
	}

	// Create multiple sub-CAs
	for _, protocol := range []string{"scep", "cmp", "acme"} {
		cfg := &SubCAConfig{
			Name:       "test-" + protocol + "-ca",
			ParentCA:   "test-root-ca",
			KeyType:    "ecdsa-p256",
			Validity:   5 * 365 * 24 * time.Hour,
			Protocol:   protocol,
		}

		_, err := IssueSubCA(database, cfg, rootCert, rootKey)
		if err != nil {
			t.Fatalf("failed to issue sub-CA for %s: %v", protocol, err)
		}
	}

	// Test listing all sub-CAs
	allSubCAs, err := ListSubCAs(database, "")
	if err != nil {
		t.Fatalf("failed to list sub-CAs: %v", err)
	}

	if len(allSubCAs) != 3 {
		t.Errorf("expected 3 sub-CAs, got %d", len(allSubCAs))
	}

	// Test listing by protocol
	scepSubCAs, err := ListSubCAs(database, "scep")
	if err != nil {
		t.Fatalf("failed to list SCEP sub-CAs: %v", err)
	}

	if len(scepSubCAs) != 1 {
		t.Errorf("expected 1 SCEP sub-CA, got %d", len(scepSubCAs))
	}
}

func TestRevokeSubCA(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer database.Close()

	// Create root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSerial, _ := randomSerial()
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	err = database.InsertCAMeta(&db.CAMeta{
		Name:         "test-root-ca",
		CertDER:      rootCertDER,
		Subject:      rootCert.Subject.String(),
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(rootCertDER),
	})
	if err != nil {
		t.Fatalf("failed to store root CA: %v", err)
	}

	// Create sub-CA
	cfg := &SubCAConfig{
		Name:       "test-sub-ca",
		ParentCA:   "test-root-ca",
		KeyType:    "ecdsa-p256",
		Validity:   5 * 365 * 24 * time.Hour,
		Protocol:   "scep",
	}

	_, err = IssueSubCA(database, cfg, rootCert, rootKey)
	if err != nil {
		t.Fatalf("failed to issue sub-CA: %v", err)
	}

	// Test revoking sub-CA
	err = RevokeSubCA(database, "test-sub-ca", 1)
	if err != nil {
		t.Fatalf("failed to revoke sub-CA: %v", err)
	}

	// Verify revocation
	subCA, err := GetSubCA(database, "test-sub-ca")
	if err != nil {
		t.Fatalf("failed to get sub-CA: %v", err)
	}

	if subCA.Status != "revoked" {
		t.Errorf("expected status 'revoked', got '%s'", subCA.Status)
	}

	if subCA.RevokedAt == nil {
		t.Error("expected revoked_at to be set")
	}

	if subCA.RevokeReason == nil || *subCA.RevokeReason != 1 {
		t.Error("expected revoke_reason to be 1")
	}
}

func TestValidateAdminCert(t *testing.T) {
	// Create a test CA for signing
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial := new(big.Int).SetInt64(1)
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Test valid admin certificate (entity cert, not CA)
	adminKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adminSerial := new(big.Int).SetInt64(2)
	adminTemplate := &x509.Certificate{
		SerialNumber: adminSerial,
		Subject: pkix.Name{
			CommonName: "admin@test.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	adminCertDER, _ := x509.CreateCertificate(rand.Reader, adminTemplate, caCert, adminKey.Public(), caKey)
	adminCert, _ := x509.ParseCertificate(adminCertDER)

	err := ValidateAdminCert(adminCert)
	if err != nil {
		t.Errorf("expected valid admin cert (entity), got error: %v", err)
	}

	// Test CA certificate (should fail — admin is entity, not CA)
	err = ValidateAdminCert(caCert)
	if err != ErrAdminCertRequired {
		t.Errorf("expected ErrAdminCertRequired for CA cert, got: %v", err)
	}

	// Test nil certificate
	err = ValidateAdminCert(nil)
	if err != ErrAdminCertRequired {
		t.Errorf("expected ErrAdminCertRequired for nil cert, got: %v", err)
	}
}

func TestValidateAdminCertScope(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	makeAdmin := func(mut func(*x509.Certificate)) *x509.Certificate {
		adminKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: new(big.Int).SetInt64(2),
			Subject:      pkix.Name{CommonName: "admin@test.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if mut != nil {
			mut(tmpl)
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, adminKey.Public(), caKey)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}
	scopeOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1}

	// SAN URI scope
	uriCert := makeAdmin(func(t *x509.Certificate) {
		u, _ := url.Parse("urn:pki:ca:Client CA")
		t.URIs = []*url.URL{u}
	})
	if got := ExtractAdminScope(uriCert); got != "Client CA" {
		t.Errorf("ExtractAdminScope(URI) = %q, want %q", got, "Client CA")
	}
	if err := ValidateAdminCertWithTarget(uriCert, nil, "Client CA"); err != nil {
		t.Errorf("URI scope should match Client CA: %v", err)
	}
	if err := ValidateAdminCertWithTarget(uriCert, nil, "Other CA"); err == nil {
		t.Error("URI scope should reject Other CA")
	}

	// OID scope
	oidCert := makeAdmin(func(t *x509.Certificate) {
		t.ExtraExtensions = append(t.ExtraExtensions, pkix.Extension{Id: scopeOID, Value: []byte("Client CA")})
	})
	if got := ExtractAdminScope(oidCert); got != "Client CA" {
		t.Errorf("ExtractAdminScope(OID) = %q, want %q", got, "Client CA")
	}
	if err := ValidateAdminCertWithTarget(oidCert, nil, "Client CA"); err != nil {
		t.Errorf("OID scope should match Client CA: %v", err)
	}
	if err := ValidateAdminCertWithTarget(oidCert, nil, "Other CA"); err == nil {
		t.Error("OID scope should reject Other CA")
	}

	// Merged + de-duplicated
	both := makeAdmin(func(t *x509.Certificate) {
		u, _ := url.Parse("urn:pki:ca:Client CA")
		t.URIs = []*url.URL{u}
		t.ExtraExtensions = append(t.ExtraExtensions, pkix.Extension{Id: scopeOID, Value: []byte("Client CA,VPN CA")})
	})
	if got := ExtractAdminScope(both); got != "Client CA,VPN CA" {
		t.Errorf("ExtractAdminScope(merged) = %q, want %q", got, "Client CA,VPN CA")
	}
	if err := ValidateAdminCertWithTarget(both, nil, "VPN CA"); err != nil {
		t.Errorf("comma-separated scope should match VPN CA: %v", err)
	}

	// Wildcard scope
	wildCert := makeAdmin(func(t *x509.Certificate) {
		t.ExtraExtensions = append(t.ExtraExtensions, pkix.Extension{Id: scopeOID, Value: []byte("*")})
	})
	if err := ValidateAdminCertWithTarget(wildCert, nil, "Anything CA"); err != nil {
		t.Errorf("wildcard scope should match any CA: %v", err)
	}

	// No scope -> denied for a target
	noScope := makeAdmin(nil)
	if got := ExtractAdminScope(noScope); got != "" {
		t.Errorf("ExtractAdminScope(none) = %q, want empty", got)
	}
	if err := ValidateAdminCertWithTarget(noScope, nil, "Client CA"); err == nil {
		t.Error("no-scope cert should be rejected for a target CA")
	}
}

func TestParseSubCACert(t *testing.T) {
	// Create a test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := new(big.Int).SetInt64(1)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Test Sub-CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Test parsing
	cert, err := ParseSubCACert(certPEM)
	if err != nil {
		t.Fatalf("failed to parse sub-CA certificate: %v", err)
	}

	if cert.Subject.CommonName != "Test Sub-CA" {
		t.Errorf("expected CN 'Test Sub-CA', got '%s'", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("expected certificate to be a CA")
	}
}

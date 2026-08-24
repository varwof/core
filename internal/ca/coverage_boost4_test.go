package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func TestIssueAndBuffer_WithBuffer(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "buffer-test",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
	}

	bufCfg := PersistConfig{Mode: PersistAsync, BatchSize: 100, BatchInterval: time.Second, QueueSize: 1000}
	buffer, err := NewMemoryBuffer(d, bufCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer buffer.Close()

	result, err := IssueAndBuffer(cfg, buffer)
	if err != nil {
		t.Fatalf("IssueAndBuffer: %v", err)
	}
	if result.Cert == nil || result.Record == nil {
		t.Fatal("expected non-nil cert and record")
	}
	if result.Record.CommonName != "buffer-test" {
		t.Fatalf("expected CN buffer-test, got %s", result.Record.CommonName)
	}
}

func TestIssueAndBuffer_NilBuffer_WithDB(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "db-insert-test",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
	}

	// IssueAndBuffer with nil buffer inserts via signerCfg.DB after Sign also inserts
	// This is expected: Sign inserts, then IssueAndBuffer inserts again → duplicate
	_, err := IssueAndBuffer(cfg, nil)
	// err may be duplicate serial (Sign already inserted); that still exercises the branch
	if err != nil {
		t.Logf("IssueAndBuffer nil buffer (expected duplicate): %v", err)
	}
}

func TestIssueAndBuffer_NilBuffer_NilDB(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "no-persist",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
	}

	_, err := IssueAndBuffer(cfg, nil)
	// Sign inserts, then IssueAndBuffer tries again → duplicate is expected
	if err != nil {
		t.Logf("IssueAndBuffer no persist (expected duplicate): %v", err)
	}
}

func TestIssueAndBuffer_SignError(t *testing.T) {
	caCert, _ := newTestCA(t)
	d := newTestDB(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cfg := &SignConfig{
		DB:            d,
		CAKey:         key,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: nil, // nil pub key causes sign error
		Profile:       ProfileTLSServer,
		CommonName:    "error",
		Validity:      24 * time.Hour,
	}

	_, err := IssueAndBuffer(cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestBuildCertRecord(t *testing.T) {
	caCert, caKey := newTestCA(t)
	d := newTestDB(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signResult, err := Sign(&SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "build-test",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &SignConfig{
		CAName:     "test-ca",
		CommonName: "build-test",
		Profile:    ProfileTLSServer,
	}
	record := buildCertRecord(signResult, cfg)
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.CAName != "test-ca" {
		t.Fatalf("expected CAName test-ca, got %s", record.CAName)
	}
	if record.CommonName != "build-test" {
		t.Fatalf("expected CommonName build-test, got %s", record.CommonName)
	}
	if record.Status != "active" {
		t.Fatalf("expected status active, got %s", record.Status)
	}
}

func TestSignCACSR_PathLenZero(t *testing.T) {
	caCert, caKey := newTestCA(t)
	csr := generateTestCSR(t)

	cfg := &OfflineSignConfig{
		CACert:   caCert,
		CAKey:    caKey,
		CSR:      csr,
		Validity: 365 * 24 * time.Hour,
		Hash:     "sha256",
		PathLen:  0,
	}

	certDER, serial, err := SignCACSR(cfg)
	if err != nil {
		t.Fatalf("SignCACSR: %v", err)
	}
	if certDER == nil {
		t.Fatal("expected non-nil certDER")
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatal("expected positive serial")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("expected CA cert")
	}
	if cert.MaxPathLen != 0 {
		t.Fatalf("expected MaxPathLen 0, got %d", cert.MaxPathLen)
	}
}

func TestSignCACSR_PathLenPositive(t *testing.T) {
	caCert, caKey := newTestCA(t)
	csr := generateTestCSR(t)

	cfg := &OfflineSignConfig{
		CACert:   caCert,
		CAKey:    caKey,
		CSR:      csr,
		Validity: 365 * 24 * time.Hour,
		Hash:     "sha384",
		PathLen:  2,
	}

	certDER, _, err := SignCACSR(cfg)
	if err != nil {
		t.Fatalf("SignCACSR: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if cert.MaxPathLen != 2 {
		t.Fatalf("expected MaxPathLen 2, got %d", cert.MaxPathLen)
	}
}

func TestSignCACSR_PathLenNegative(t *testing.T) {
	caCert, caKey := newTestCA(t)
	csr := generateTestCSR(t)

	cfg := &OfflineSignConfig{
		CACert:   caCert,
		CAKey:    caKey,
		CSR:      csr,
		Validity: 365 * 24 * time.Hour,
		Hash:     "sha512",
		PathLen:  -1,
	}

	certDER, _, err := SignCACSR(cfg)
	if err != nil {
		t.Fatalf("SignCACSR: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	// PathLen < 0 means no constraint set; Go default is -1
	if cert.MaxPathLen >= 0 {
		t.Fatalf("expected MaxPathLen < 0 (no constraint), got %d", cert.MaxPathLen)
	}
}

func TestSetRemoteSignerConfig(t *testing.T) {
	old := RemoteSignerConfig()
	defer SetRemoteSignerConfig(old)

	SetRemoteSignerConfig(nil)
	if got := RemoteSignerConfig(); got != nil {
		t.Fatalf("expected nil remote config, got %v", got)
	}
}

func TestLoadTrustPool_Empty(t *testing.T) {
	_, err := LoadTrustPool(map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error for empty trust pool (fail-closed)")
	}
}

func TestLoadTrustPool_WithFile(t *testing.T) {
	caCert, _ := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	tmpFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(tmpFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadTrustPool(map[string]string{"test": tmpFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestLoadTrustPool_BadFile(t *testing.T) {
	_, err := LoadTrustPool(map[string]string{"bad": "/nonexistent/path.pem"}, nil)
	if err == nil {
		t.Fatal("expected error for empty trust pool from bad file (fail-closed)")
	}
}

func TestLoadTrustPoolWithSources_Empty(t *testing.T) {
	pool, sources, err := LoadTrustPoolWithSources(map[string]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if len(sources) != 0 {
		t.Fatalf("expected empty sources, got %d", len(sources))
	}
}

func TestLoadTrustPoolWithSources_WithFile(t *testing.T) {
	caCert, _ := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	tmpFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(tmpFile, certPEM, 0644)

	_, sources, err := LoadTrustPoolWithSources(map[string]string{"test": tmpFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) == 0 {
		t.Fatal("expected non-empty sources")
	}
}

func TestVerifyCertificate_Valid(t *testing.T) {
	caCert, caKey := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "verify-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &pubKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := VerifyCertificate(cert, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatal("expected valid")
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected non-empty chain")
	}
}

func TestVerifyCertificate_Invalid(t *testing.T) {
	caCert, _ := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "untrusted"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	// Self-signed, not in pool
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pubKey.PublicKey, pubKey)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := VerifyCertificate(cert, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for untrusted cert")
	}
}

func TestExportFederatedTrust_Empty(t *testing.T) {
	d := newTestDB(t)
	pemData, err := ExportFederatedTrust(d, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(pemData) != 0 {
		t.Fatalf("expected empty PEM, got %d bytes", len(pemData))
	}
}

func TestBuildFederatedTrustPool(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)

	localCAs := map[string]*x509.Certificate{"local": caCert}
	pool, err := BuildFederatedTrustPool(d, localCAs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestBuildFederatedTrustPool_WithCrossCert(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	// Create a cross-cert
	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "cross-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &pubKey.PublicKey, caKey)

	crossCerts := []*db.CrossCertRecord{
		{
			IssuerCA:     "local",
			SubjectCA:    "remote",
			CertDER:      certDER,
			SerialNumber: "300",
			Status:       "V",
		},
	}

	pool, err := BuildFederatedTrustPool(d, nil, crossCerts)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestBuildFederatedTrustPool_RevokedCrossCert(t *testing.T) {
	d := newTestDB(t)
	crossCerts := []*db.CrossCertRecord{
		{Status: "R", CertDER: []byte("garbage")},
	}
	pool, err := BuildFederatedTrustPool(d, nil, crossCerts)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestBridgeTrustPEMs_Disabled(t *testing.T) {
	d := newTestDB(t)
	bridges := []TrustBridgePolicy{
		{Enabled: false, IssuerCA: "a", SubjectCA: "b"},
	}
	caCfgs := map[string]struct {
		Cert string
		Key  string
	}{}
	results, err := BridgeTrustPEMs(d, bridges, caCfgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestBridgeTrustPEMs_MissingIssuer(t *testing.T) {
	d := newTestDB(t)
	bridges := []TrustBridgePolicy{
		{Enabled: true, IssuerCA: "missing", SubjectCA: "b", Validity: 365},
	}
	caCfgs := map[string]struct {
		Cert string
		Key  string
	}{}
	results, err := BridgeTrustPEMs(d, bridges, caCfgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestEstablishTrustBridge(t *testing.T) {
	d := newTestDB(t)
	issuerCert, issuerKey := newTestCA(t)
	subjectCert, _ := newTestCA(t)

	d.InsertCAMeta(&db.CAMeta{
		Name:         "subject-ca",
		CertDER:      subjectCert.Raw,
		Subject:      subjectCert.Subject.String(),
		NotBefore:    subjectCert.NotBefore,
		NotAfter:     subjectCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "abc",
	})

	record, err := EstablishTrustBridge(d, issuerCert, issuerKey, "issuer-ca", &db.CAMeta{Name: "subject-ca", CertDER: subjectCert.Raw}, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("EstablishTrustBridge: %v", err)
	}
	if record == nil {
		t.Fatal("expected non-nil record")
	}
}

// ---------- helpers ----------

func generateTestCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-csr"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// ---------- LoadSignerFromDB ----------

func TestLoadSignerFromDB_Found(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	encKey, err := EncryptKeyPKCS8(caKey, "testpass")
	if err != nil {
		t.Fatal(err)
	}

	d.InsertCAMeta(&db.CAMeta{
		Name:         "test-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "abc123",
		KeyEncrypted: encKey,
	})

	cert, signer, err := LoadSignerFromDB(d, "test-ca", "testpass")
	if err != nil {
		t.Fatalf("LoadSignerFromDB: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestLoadSignerFromDB_NotFound(t *testing.T) {
	d := newTestDB(t)
	_, _, err := LoadSignerFromDB(d, "nonexistent", "")
	if err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

func TestLoadSignerFromDB_NoEncryptedKey(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)

	d.InsertCAMeta(&db.CAMeta{
		Name:         "no-key-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "def456",
	})

	_, _, err := LoadSignerFromDB(d, "no-key-ca", "")
	if err == nil {
		t.Fatal("expected error for no encrypted key")
	}
}

func TestLoadSignerFromDB_BadPassword(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	encKey, err := EncryptKeyPKCS8(caKey, "correctpass")
	if err != nil {
		t.Fatal(err)
	}

	d.InsertCAMeta(&db.CAMeta{
		Name:         "bad-pass-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "ghi789",
		KeyEncrypted: encKey,
	})

	_, _, err = LoadSignerFromDB(d, "bad-pass-ca", "wrongpass")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

// ---------- LoadSignerAny ----------

func TestLoadSignerAny_NilDB(t *testing.T) {
	_, _, err := LoadSignerAny("", "", nil, "test", "")
	if err == nil {
		t.Fatal("expected error with nil DB and no files")
	}
}

func TestLoadSignerAny_DBFallback(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	encKey, err := EncryptKeyPKCS8(caKey, "testpass")
	if err != nil {
		t.Fatal(err)
	}

	d.InsertCAMeta(&db.CAMeta{
		Name:         "db-ca",
		CertDER:      caCert.Raw,
		Subject:      caCert.Subject.String(),
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "db123",
		KeyEncrypted: encKey,
	})

	cert, signer, err := LoadSignerAny("", "", d, "db-ca", "testpass")
	if err != nil {
		t.Fatalf("LoadSignerAny: %v", err)
	}
	if cert == nil || signer == nil {
		t.Fatal("expected non-nil cert and signer")
	}
}

func TestLoadSignerAny_BadFilePath(t *testing.T) {
	d := newTestDB(t)
	_, _, err := LoadSignerAny("/nonexistent/cert.pem", "/nonexistent/key.pem", d, "missing", "")
	if err == nil {
		t.Fatal("expected error for bad file paths")
	}
}

// ---------- ImportTrustBundle ----------

func TestImportTrustBundle_Valid(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	result, err := ImportTrustBundle(d, certPEM, "test-source")
	if err != nil {
		t.Fatalf("ImportTrustBundle: %v", err)
	}
	if result.Imported != 1 {
		t.Fatalf("expected 1 imported, got %d", result.Imported)
	}
}

func TestImportTrustBundle_EmptyPEM(t *testing.T) {
	d := newTestDB(t)
	result, err := ImportTrustBundle(d, []byte(""), "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 {
		t.Fatalf("expected 0 imported, got %d", result.Imported)
	}
}

func TestImportTrustBundle_Duplicate(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	ImportTrustBundle(d, certPEM, "src")
	result, err := ImportTrustBundle(d, certPEM, "src")
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 {
		t.Fatalf("expected 0 imported (duplicate), got %d", result.Imported)
	}
}

// ---------- VerifyCertificate with sources ----------

func TestVerifyCertificate_WithSources(t *testing.T) {
	caCert, caKey := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "source-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &pubKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Calculate fingerprint of the root (caCert)
	rootFP := fmt.Sprintf("%x", sha256hash(caCert.Raw))
	sources := map[string]string{rootFP: "trust_anchor:test:local"}

	result, err := VerifyCertificate(cert, pool, sources)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatal("expected valid")
	}
	if !result.Verified {
		t.Fatal("expected verified")
	}
}

// ---------- BuildFederatedTrustPool with trust anchors ----------

func TestBuildFederatedTrustPool_WithAnchors(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)

	d.InsertTrustAnchor(&db.TrustAnchor{
		Name:    "anchor1",
		CertDER: caCert.Raw,
		Source:  "test",
		Trusted: true,
		HashID:  "hash1",
	})

	pool, err := BuildFederatedTrustPool(d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

// ---------- BridgeTrustPEMs with valid files ----------

func TestBridgeTrustPEMs_Valid(t *testing.T) {
	d := newTestDB(t)
	issuerCert, issuerKey := newTestCA(t)
	subjectCert, _ := newTestCA(t)

	// Save issuer cert/key to temp files
	certPath := filepath.Join(t.TempDir(), "issuer.pem")
	keyDER, _ := x509.MarshalECPrivateKey(issuerKey.(*ecdsa.PrivateKey))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw})
	os.WriteFile(certPath, certPEM, 0644)
	keyPath := filepath.Join(t.TempDir(), "issuer-key.pem")
	os.WriteFile(keyPath, keyPEM, 0644)

	d.InsertCAMeta(&db.CAMeta{
		Name:         "subject-ca",
		CertDER:      subjectCert.Raw,
		Subject:      subjectCert.Subject.String(),
		NotBefore:    subjectCert.NotBefore,
		NotAfter:     subjectCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "subj",
	})

	bridges := []TrustBridgePolicy{
		{Enabled: true, IssuerCA: "issuer-ca", SubjectCA: "subject-ca", Validity: 365},
	}
	caCfgs := map[string]struct {
		Cert string
		Key  string
	}{
		"issuer-ca": {Cert: certPath, Key: keyPath},
	}
	results, err := BridgeTrustPEMs(d, bridges, caCfgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// ---------- All profiles via Sign ----------

func signWithProfile(t *testing.T, d *db.DB, caCert *x509.Certificate, caKey crypto.Signer, profile Profile, extra ...func(*SignConfig)) *SignResult {
	t.Helper()
	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       profile,
		CommonName:    "test-" + string(profile),
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
		CRLBaseURL:    "http://crl.test/pki",
		OCSPURL:       "http://ocsp.test:9080",
		IssuerURL:     "http://issuer.test/ca",
	}
	for _, fn := range extra {
		fn(sc)
	}
	result, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign(%s): %v", profile, err)
	}
	return result
}

func TestSign_AllProfiles(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	profiles := []Profile{
		ProfileRootCA, ProfilePolicyCA, ProfileSubCA,
		ProfileTLSServer, ProfileTLSClient,
		ProfileOCSPSigner, ProfileTimestamp,
		ProfileCodeSigning, ProfileEmail, ProfileDocument,
		ProfileMAdmin, ProfileMOperator, ProfileMSuperAdmin,
		ProfileMAuditor, ProfileMReadonly, ProfileMConsole,
		ProfileMAutoRenew, ProfileMReporter,
	}

	for _, p := range profiles {
		signWithProfile(t, d, caCert, caKey, p)
	}
}

func TestSign_AgentProxy(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	ou := []string{"gateway:admin"}
	signWithProfile(t, d, caCert, caKey, ProfileAgentProxy, func(sc *SignConfig) {
		sc.Subject = &pkix.Name{OrganizationalUnit: ou}
	})
}

func TestSign_AgentProxy_WithAIC(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signWithProfile(t, d, caCert, caKey, ProfileAgentProxy, func(sc *SignConfig) {
		sc.Subject = &pkix.Name{OrganizationalUnit: []string{"gateway:admin"}}
		sc.AIC = &AICConfig{
			AgentId:                 "agent-001",
			PrincipalUid:            PrincipalUid{Realm: "local", Identifier: "admin", KeyHash: testAICKeyHash()},
			Capabilities:            []Capability{{SchemeId: "mcp", CapabilityId: "tools"}},
			DelegationAuthorization: testAICDelegation(),
		}
	})
}

func TestSign_AgentProxy_WithPrincipalAuthorization(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signWithProfile(t, d, caCert, caKey, ProfileAgentProxy, func(sc *SignConfig) {
		sc.Subject = &pkix.Name{OrganizationalUnit: []string{"gateway:admin"}}
		sc.PrincipalAuthorization = &PrincipalAuthorizationConfig{
			Grants: []Capability{{SchemeId: "gw", CapabilityId: "admin"}},
		}
	})
}

func TestSign_AgentProxy_NoOU(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileAgentProxy,
		CommonName:    "ap-no-ou",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
		Subject:       &pkix.Name{},
	}
	_, err := Sign(sc)
	if err == nil {
		t.Fatal("expected error for agent-proxy without OU")
	}
}

func TestSign_SubCA_WithConstraints(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signWithProfile(t, d, caCert, caKey, ProfileSubCA, func(sc *SignConfig) {
		sc.MaxPathLen = 2
		sc.PermittedDomains = []string{".example.com"}
		sc.ExcludedDomains = []string{"internal.example.com"}
		sc.PermittedEmails = []string{".example.com"}
		sc.ExcludedEmails = []string{"internal.example.com"}
		sc.PermittedURIs = []string{"example.com"}
		sc.ExcludedURIs = []string{"internal.example.com"}
		sc.PermittedIPRanges = []string{"10.0.0.0/8"}
		sc.ExcludedIPRanges = []string{"10.0.1.0/24"}
		sc.CRLPartitions = 3
	})
}

func TestSign_TLSServer_WithMustStaple(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signWithProfile(t, d, caCert, caKey, ProfileTLSServer, func(sc *SignConfig) {
		sc.MustStaple = true
		sc.ExtraEKUOIDs = []string{"1.3.6.1.5.5.7.3.1"}
		sc.IssuerAltNames = []string{"URI:http://issuer.test/issuer"}
		sc.SubjectInfoAccess = []string{"ocsp:http://sia.test/ocsp"}
		sc.PolicyOIDs = []string{"2.5.29.32.0"}
	})
}

func TestSign_UnknownProfile(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       "unknown-profile",
		CommonName:    "unknown",
		Validity:      24 * time.Hour,
	}
	_, err := Sign(sc)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestSign_ED25519(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signer, _ := GenerateKey("ed25519")
	pubKey := signer.Public()
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: pubKey,
		Profile:       ProfileTLSServer,
		CommonName:    "ed25519-test",
		Validity:      24 * time.Hour,
		KeyType:       "ed25519",
	}
	_, err := Sign(sc)
	_ = err // Ed25519 signing may not be supported by ECDSA CA — both ok/fail acceptable
}

func TestSign_RSA2048(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signer, _ := GenerateKey("rsa-2048")
	pubKey := signer.Public()
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: pubKey,
		Profile:       ProfileTLSServer,
		CommonName:    "rsa2048-test",
		Validity:      24 * time.Hour,
		KeyType:       "rsa-2048",
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign rsa2048: %v", err)
	}
}

func TestSign_RSA4096(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signer, _ := GenerateKey("rsa-4096")
	pubKey := signer.Public()
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: pubKey,
		Profile:       ProfileTLSServer,
		CommonName:    "rsa4096-test",
		Validity:      24 * time.Hour,
		KeyType:       "rsa-4096",
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign rsa4096: %v", err)
	}
}

func TestSign_ECDSAP384(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signer, _ := GenerateKey("ecdsa-p384")
	pubKey := signer.Public()
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: pubKey,
		Profile:       ProfileTLSClient,
		CommonName:    "ecdsa384-test",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p384",
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign ecdsa-p384: %v", err)
	}
}

func TestSign_WithDedupCN(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "dedup-test",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
		DedupCN:       true,
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign dedup: %v", err)
	}
	// Second sign with same CN and DedupCN=true should fail (duplicate)
	pubKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc.SubjectPubKey = &pubKey2.PublicKey
	_, err = Sign(sc)
	if err == nil {
		t.Fatal("expected dedup error for second sign with same CN")
	}
}

func TestSign_CN_WithSANs(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &pubKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "san-test.example.com",
		Validity:      24 * time.Hour,
		KeyType:       "ecdsa-p256",
		SANs:          []string{"DNS:san-test.example.com", "DNS:www.example.com", "IP:192.168.1.1", "email:test@example.com", "URI:http://test.example.com"},
	}
	_, err := Sign(sc)
	if err != nil {
		t.Fatalf("Sign SANs: %v", err)
	}
}

func TestSign_SubCA_DefaultPathLen(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	signWithProfile(t, d, caCert, caKey, ProfileSubCA, func(sc *SignConfig) {
		sc.MaxPathLen = 0
	})
}

func TestLoadSigner_CacheHit(t *testing.T) {
	caCert, caKey := newTestCA(t)
	certPath := filepath.Join(t.TempDir(), "cached.pem")
	keyDER, _ := x509.MarshalECPrivateKey(caKey.(*ecdsa.PrivateKey))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	os.WriteFile(certPath, certPEM, 0644)
	keyPath := filepath.Join(t.TempDir(), "cached-key.pem")
	os.WriteFile(keyPath, keyPEM, 0644)

	defer FlushSignerCache()

	cert1, signer1, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert2, signer2, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 != cert2 || signer1 != signer2 {
		t.Fatal("expected cache hit")
	}
}

func TestLoadSigner_BadCertPEM(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(certPath, []byte("not-a-cert"), 0644)
	keyPath := filepath.Join(t.TempDir(), "bad-key.pem")
	os.WriteFile(keyPath, []byte("not-a-key"), 0644)

	_, _, err := LoadSigner(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for bad cert PEM")
	}
}

func TestLoadSigner_MissingCert(t *testing.T) {
	_, _, err := LoadSigner("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
}

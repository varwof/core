// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

// ---- Red line #1: Private key handling (sign.go ParsePrivateKey/LoadPrivateKey/LoadSigner/KeyToPEM) ----

func TestParsePrivateKeyEncryptedPKCS8(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := EncryptKeyPKCS8(key, "secret1")
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
	parsed, err := ParsePrivateKey(pemData, "secret1")
	if err != nil {
		t.Fatalf("ParsePrivateKey encrypted: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("public key mismatch after decrypt")
	}
}

func TestParsePrivateKeyEncryptedWrongPassword(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := EncryptKeyPKCS8(key, "secret1")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
	if _, err := ParsePrivateKey(pemData, "wrong"); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestParsePrivateKeyInvalidPKCS8(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-valid-der")})
	if _, err := ParsePrivateKey(pemData); err == nil {
		t.Fatal("expected error for invalid PKCS8 DER")
	}
}

func TestParsePrivateKeyNotASigner(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParsePrivateKey(pemData); err == nil {
		t.Fatal("expected error for non-signer key (X25519)")
	}
}

func TestParsePrivateKeyPKCS1RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	parsed, err := ParsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKey PKCS1: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("RSA public key mismatch")
	}
}

func TestParsePrivateKeyEC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	parsed, err := ParsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKey EC: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("EC public key mismatch")
	}
}

func TestParsePrivateKeyNoBlock(t *testing.T) {
	if _, err := ParsePrivateKey([]byte("garbage, no PEM block")); err == nil {
		t.Fatal("expected error when no PEM block found")
	}
}

func TestParsePrivateKeySkipsNonKeyBlocks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")})
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	parsed, err := ParsePrivateKey(append(certBlock, keyBlock...))
	if err != nil {
		t.Fatalf("ParsePrivateKey skip non-key blocks: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("public key mismatch")
	}
}

func TestLoadPrivateKeyReadError(t *testing.T) {
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestLoadPrivateKeyEncryptedFile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := EncryptKeyPKCS8(key, "pw")
	keyPath := filepath.Join(t.TempDir(), "enc.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := LoadPrivateKey(keyPath, "pw")
	if err != nil {
		t.Fatalf("LoadPrivateKey encrypted file: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("public key mismatch")
	}
}

func TestFlushSignerCacheKeyPath(t *testing.T) {
	FlushSignerCache("key-a")
	FlushSignerCache("")
}

func TestLoadSignerCacheAndFlush(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := newTestCA(t)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, CertToPEM(caCert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := KeyToPEM(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cert1, signer1, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if cert1 == nil || signer1 == nil {
		t.Fatal("nil cert/signer")
	}
	cert2, signer2, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert2 != cert1 {
		t.Fatal("expected cache hit (same cert pointer)")
	}
	if signer2 != signer1 {
		t.Fatal("expected cache hit (same signer pointer)")
	}
	FlushSignerCache(keyPath)
	cert3, _, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert3 == cert1 {
		t.Fatal("expected fresh load after cache flush")
	}
}

func TestLoadSignerReadCertError(t *testing.T) {
	_, _, err := LoadSigner(filepath.Join(t.TempDir(), "missing.pem"), "x.key")
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestLoadSignerInvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.pem")
	keyPath := filepath.Join(dir, "k.key")
	if err := os.WriteFile(certPath, []byte("not pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadSigner(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestLoadSignerParseCertError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad-der.pem")
	keyPath := filepath.Join(dir, "k.key")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid-der")})
	if err := os.WriteFile(certPath, block, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadSigner(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert DER")
	}
}

func TestLoadSignerMissingKey(t *testing.T) {
	dir := t.TempDir()
	caCert, _ := newTestCA(t)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "missing.key")
	if err := os.WriteFile(certPath, CertToPEM(caCert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadSigner(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestKeyToPEMRoundTrip(t *testing.T) {
	for _, key := range []crypto.Signer{
		mustRSA(t),
		mustEC(t),
		mustEd25519(t),
	} {
		pemData, err := KeyToPEM(key)
		if err != nil {
			t.Fatalf("KeyToPEM: %v", err)
		}
		parsed, err := ParsePrivateKey(pemData)
		if err != nil {
			t.Fatalf("ParsePrivateKey roundtrip: %v", err)
		}
		if !samePublicKey(key, parsed) {
			t.Fatal("public key mismatch after roundtrip")
		}
	}
}

// ---- encrypt.go ----

func TestDecryptPrivateKeyPEMNotASigner(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := DecryptPrivateKeyPEM(pemData, ""); err == nil {
		t.Fatal("expected error for non-signer key")
	}
}

func TestDecryptPrivateKeyPEMSkipsOtherBlocks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")})
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := DecryptPrivateKeyPEM(append(certBlock, keyBlock...), "")
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM skip blocks: %v", err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("public key mismatch")
	}
}

func TestEncryptPrivateKeyPEMRoundTripRSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData, err := EncryptPrivateKeyPEM(key, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedPEM(pemData) {
		t.Fatal("expected ENCRYPTED PRIVATE KEY PEM")
	}
	parsed, err := DecryptPrivateKeyPEM(pemData, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !samePublicKey(key, parsed) {
		t.Fatal("public key mismatch")
	}
}

// ---- Red line #2: Certificate chain verification (verify.go LoadTrustPool/LoadTrustPoolWithSources) ----

func TestLoadTrustPoolEmptyCertPaths(t *testing.T) {
	_, err := LoadTrustPool(map[string]string{"a": ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty trust pool (fail-closed)")
	}
}

func TestLoadTrustPoolFromFiles(t *testing.T) {
	caCert, _ := newTestCA(t)
	certPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(certPath, CertToPEM(caCert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadTrustPool(map[string]string{
		"root":    certPath,
		"missing": filepath.Join(t.TempDir(), "nope.pem"),
		"empty":   "",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestLoadTrustPoolFromDatabase(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)
	if err := d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "root", HashID: "hash-root", CertDER: caCert.Raw,
		Subject: caCert.Subject.String(), NotBefore: caCert.NotBefore,
		NotAfter: caCert.NotAfter, Issuer: caCert.Issuer.String(),
		Trusted: true, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadTrustPool(nil, d)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool from DB anchors")
	}
}

func TestLoadTrustPoolSkipsNonSelfSigned(t *testing.T) {
	d := newTestDB(t)
	parentCert, parentKey := newTestCA(t)
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Sub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, parentCert, &subKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "sub", HashID: "hash-sub", CertDER: subDER,
		Subject: subTmpl.Subject.String(), NotBefore: subTmpl.NotBefore,
		NotAfter: subTmpl.NotAfter, Issuer: parentCert.Subject.String(),
		Trusted: true, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = LoadTrustPool(map[string]string{}, d)
	if err == nil {
		t.Fatal("expected error for empty trust pool (all anchors non-self-signed, fail-closed)")
	}
}

func TestLoadTrustPoolListError(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "list.db"))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := LoadTrustPool(nil, d); err == nil {
		t.Fatal("expected error when listing trust anchors fails")
	}
}

func TestLoadTrustPoolWithSourcesFromFile(t *testing.T) {
	rootCert, rootKey := newTestCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(CertToPEM(rootCert.Raw), CertToPEM(leafDER)...)
	certPath := filepath.Join(t.TempDir(), "chain.pem")
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, sources, err := LoadTrustPoolWithSources(map[string]string{"chain": certPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	rootFP := fmt.Sprintf("%x", sha256.Sum256(rootCert.Raw))
	leafFP := fmt.Sprintf("%x", sha256.Sum256(leafDER))
	if sources[rootFP] != "ca_config:chain" {
		t.Fatalf("root source = %q", sources[rootFP])
	}
	if sources[leafFP] != "ca_config:chain" {
		t.Fatalf("leaf source = %q", sources[leafFP])
	}
}

func TestLoadTrustPoolWithSourcesFromDatabase(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)
	if err := d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "root", HashID: "hash-root", CertDER: caCert.Raw,
		Subject: caCert.Subject.String(), NotBefore: caCert.NotBefore,
		NotAfter: caCert.NotAfter, Issuer: caCert.Issuer.String(),
		Trusted: true, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_, sources, err := LoadTrustPoolWithSources(nil, d)
	if err != nil {
		t.Fatal(err)
	}
	if got := sources["hash-root"]; got != "trust_anchor:test:root" {
		t.Fatalf("trust anchor source = %q", got)
	}
}

// ---- archive.go ----

func TestArchiveCerts(t *testing.T) {
	d := newTestDB(t)
	caCert, _ := newTestCA(t)
	past := time.Now().Add(-60 * 24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	expired := &db.CertRecord{
		SerialNumber: serial40(1), CAName: "test-ca", Status: "E",
		CommonName: "expired", NotBefore: past, NotAfter: past, CertDER: caCert.Raw,
	}
	revokedAt := past
	revoked := &db.CertRecord{
		SerialNumber: serial40(2), CAName: "test-ca", Status: "R",
		CommonName: "revoked", NotBefore: past, NotAfter: future,
		RevokedAt: &revokedAt, CertDER: caCert.Raw,
	}
	excluded := &db.CertRecord{
		SerialNumber: serial40(3), CAName: "excluded-ca", Status: "E",
		CommonName: "excluded", NotBefore: past, NotAfter: past, CertDER: caCert.Raw,
	}
	active := &db.CertRecord{
		SerialNumber: serial40(4), CAName: "test-ca", Status: "V",
		CommonName: "active", NotBefore: past, NotAfter: future, CertDER: caCert.Raw,
	}
	for _, rec := range []*db.CertRecord{expired, revoked, excluded, active} {
		if err := d.InsertCert(rec); err != nil {
			t.Fatalf("InsertCert %s: %v", rec.SerialNumber, err)
		}
	}

	policy := &ArchivePolicy{
		Enabled: true, RetentionDays: 30,
		ExcludeCAs:     []string{"excluded-ca"},
		ArchiveExpired: true, ArchiveRevoked: true,
	}
	res, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiredCount != 1 || res.RevokedCount != 1 || res.Archived != 2 {
		t.Fatalf("archive result = %+v", res)
	}
	if _, err := d.GetCert("test-ca", serial40(1)); err == nil {
		t.Fatal("expired cert should have been removed")
	}
	if _, err := d.GetCert("test-ca", serial40(2)); err == nil {
		t.Fatal("revoked cert should have been removed")
	}
	if _, err := d.GetCert("excluded-ca", serial40(3)); err != nil {
		t.Fatal("excluded CA cert should remain")
	}
	if _, err := d.GetCert("test-ca", serial40(4)); err != nil {
		t.Fatal("active cert should remain")
	}
}

func TestArchiveCertsExecError(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "arch.db"))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := ArchiveCerts(d, &ArchivePolicy{ArchiveExpired: true}); err == nil {
		t.Fatal("expected error on closed DB")
	}
}

// ---- buffer.go ----

func testBufferRecord(serial string, caName string) *db.CertRecord {
	return &db.CertRecord{
		SerialNumber: serial, CAName: caName, Status: "V",
		CommonName: "buf-" + serial, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), CertDER: []byte("cert-der"),
	}
}

func TestMemoryBufferRealtimeAdd(t *testing.T) {
	d := newTestDB(t)
	buf, err := NewMemoryBuffer(d, PersistConfig{Mode: PersistRealtime})
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(10), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCert("test-ca", serial40(10)); err != nil {
		t.Fatal("record should be persisted immediately in realtime mode")
	}
}

func TestMemoryBufferAsyncQueueFullFallback(t *testing.T) {
	d := newTestDB(t)
	buf, err := NewMemoryBuffer(d, PersistConfig{Mode: PersistAsync, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(11), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	// queue full (len 1 >= 1) → fallback to realtime write
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(12), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCert("test-ca", serial40(11)); err != nil {
		t.Fatal("queued record should be flushed on close")
	}
	if _, err := d.GetCert("test-ca", serial40(12)); err != nil {
		t.Fatal("fallback record should be persisted")
	}
}

func TestMemoryBufferBatchTrigger(t *testing.T) {
	d := newTestDB(t)
	buf, err := NewMemoryBuffer(d, PersistConfig{Mode: PersistBatch, BatchSize: 2, BatchInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(13), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(14), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCert("test-ca", serial40(13)); err != nil {
		t.Fatal("batch record 13 should be persisted")
	}
	if _, err := d.GetCert("test-ca", serial40(14)); err != nil {
		t.Fatal("batch record 14 should be persisted")
	}
}

func TestMemoryBufferAsyncTickFlush(t *testing.T) {
	d := newTestDB(t)
	buf, err := NewMemoryBuffer(d, PersistConfig{Mode: PersistAsync, BatchInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Add(&CertBufferItem{Record: testBufferRecord(serial40(15), "test-ca")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCert("test-ca", serial40(15)); err != nil {
		t.Fatal("record should be flushed by ticker")
	}
}

func TestIssueAndBufferBufferError(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "issuebuf.db"))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	caCert, caKey := newTestCA(t)
	buf, err := NewMemoryBuffer(d, PersistConfig{Mode: PersistRealtime})
	if err != nil {
		t.Fatal(err)
	}
	sc := &SignConfig{
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileTLSServer,
		CommonName: "test.example.com",
		SANs:       []string{"DNS:test.example.com"},
		CRLBaseURL: "http://crl.test/pki",
		OCSPURL:    "http://ocsp.test:9080",
		Validity:   365 * 24 * time.Hour,
		SkipDB:     true,
	}
	if _, err := IssueAndBuffer(sc, buf); err == nil {
		t.Fatal("expected error when buffer persists to closed DB")
	}
}

// ---- Red line #4: Revocation (revoke.go) ----

func TestExtractPrincipalUidParseError(t *testing.T) {
	if _, err := extractPrincipalUid([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage DER")
	}
}

func TestExtractPrincipalUidNoAIC(t *testing.T) {
	caCert, caKey := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "plain"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extractPrincipalUid(der); err == nil {
		t.Fatal("expected ErrNoAIC for plain cert")
	}
}

func TestExtractPrincipalUidMalformedAIC(t *testing.T) {
	caCert, caKey := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "bad-aic"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: OIDAIC, Value: []byte("garbage-extension-value")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extractPrincipalUid(der); err == nil {
		t.Fatal("expected error for malformed AIC extension")
	}
}

func TestRevokeInvalidSerial(t *testing.T) {
	d := newTestDB(t)
	if err := Revoke(d, "test-ca", "not-hex", 0); err == nil {
		t.Fatal("expected error for invalid serial")
	}
}

func TestRevokeByPrincipalUidFastPathError(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "rev.db"))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := RevokeByPrincipalUid(d, "x", 1); err == nil {
		t.Fatal("expected error on closed DB")
	}
}

func TestRevokeByPrincipalUidDERFallback(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)
	pu := PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice@varwof.com", KeyHash: testAICKeyHash()}
	sc := &SignConfig{
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileAgentProxy,
		CommonName: "agent-alice",
		Subject: &pkix.Name{
			CommonName:         "agent-alice",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		OCSPURL:  "http://ocsp.test:9080",
		Validity: time.Hour,
		SkipDB:   true,
		AIC: &AICConfig{
			AgentId:                 "agent-alice",
			PrincipalUid:            pu,
			Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"}},
			DelegationAuthorization: testAICDelegation(),
		},
	}
	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	rec := result.Record
	if rec == nil {
		rec = buildCertRecord(result, sc)
	}
	// simulate legacy row: AIC present in DER but principal_uid column not populated
	rec.Status = "V"
	rec.PrincipalUid = ""
	rec.AgentId = ""
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	n, err := RevokeByPrincipalUid(d, pu.String(), 1)
	if err != nil {
		t.Fatalf("RevokeByPrincipalUid DER fallback: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 revoked via DER scan, got %d", n)
	}
}

func TestRevokeByPrincipalUidDERFallbackLastErr(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "bad-aic"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: OIDAIC, Value: []byte("garbage-extension-value")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCert(&db.CertRecord{
		SerialNumber: serial40(7), CAName: "test-ca", Status: "V",
		CommonName: "bad-aic", NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), CertDER: der,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RevokeByPrincipalUid(d, "someone-else", 1); err == nil {
		t.Fatal("expected error when only matching cert has malformed AIC")
	}
}

func TestRevokeWithCascadeInvalidSerial(t *testing.T) {
	d := newTestDB(t)
	if _, err := RevokeWithCascade(d, "test-ca", "bad-serial", 0); err == nil {
		t.Fatal("expected error for invalid serial")
	}
}

func TestRevokeWithCascadeDERPrincipal(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)
	pu := PrincipalUid{Version: 1, Realm: "varwof", Identifier: "bob@varwof.com", KeyHash: testAICKeyHash()}
	sc := &SignConfig{
		CAKey:      caKey,
		CACert:     caCert,
		Profile:    ProfileAgentProxy,
		CommonName: "agent-bob",
		Subject: &pkix.Name{
			CommonName:         "agent-bob",
			OrganizationalUnit: []string{"gateway:ops"},
		},
		OCSPURL:  "http://ocsp.test:9080",
		Validity: time.Hour,
		SkipDB:   true,
		AIC: &AICConfig{
			AgentId:                 "agent-bob",
			PrincipalUid:            pu,
			Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:ops"}},
			DelegationAuthorization: testAICDelegation(),
		},
	}
	result, err := Sign(sc)
	if err != nil {
		t.Fatal(err)
	}
	rec := result.Record
	if rec == nil {
		rec = buildCertRecord(result, sc)
	}
	rec.Status = "V"
	rec.PrincipalUid = ""
	rec.AgentId = ""
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	n, err := RevokeWithCascade(d, rec.CAName, rec.SerialNumber, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 cascaded (self already revoked), got %d", n)
	}
}

// ---- helpers ----

func serial40(n int) string {
	return fmt.Sprintf("%040X", big.NewInt(int64(n)))
}

func samePublicKey(a, b crypto.Signer) bool {
	der1, err1 := x509.MarshalPKCS8PrivateKey(a)
	der2, err2 := x509.MarshalPKCS8PrivateKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(der1, der2)
}

func mustRSA(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustEC(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustEd25519(t *testing.T) crypto.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

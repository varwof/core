// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// ─── Private key encryption / decryption ────────────────────────────

func TestEncryptDecryptPrivateKeyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := EncryptPrivateKeyPEM(key, "secret")
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM: %v", err)
	}
	if !IsEncryptedPEM(enc) {
		t.Fatal("expected encrypted PEM")
	}
	block, _ := pem.Decode(enc)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("unexpected block type %q", block.Type)
	}

	// roundtrip
	dec, err := DecryptPrivateKeyPEM(enc, "secret")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec == nil {
		t.Fatal("nil decrypted key")
	}

	// wrong password
	if _, err := DecryptPrivateKeyPEM(enc, "wrong"); err == nil {
		t.Fatal("expected error with wrong password")
	}

	// plain PKCS8 (unencrypted) passthrough
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	plainPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain})
	if IsEncryptedPEM(plainPEM) {
		t.Fatal("plain key should not be encrypted")
	}
	dec2, err := DecryptPrivateKeyPEM(plainPEM, "")
	if err != nil || dec2 == nil {
		t.Fatalf("plain decrypt: %v", err)
	}

	// combined cert+key file: key block is the second block
	keyPEM2 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain})
	combined := append([]byte("cert block\n"), keyPEM2...)
	if _, err := DecryptPrivateKeyPEM(combined, ""); err != nil {
		t.Fatalf("combined decrypt: %v", err)
	}

	// no PEM block
	if _, err := DecryptPrivateKeyPEM([]byte("garbage"), ""); err == nil {
		t.Fatal("expected no-PEM error")
	}

	// garbage PKCS8 inside PRIVATE KEY
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := DecryptPrivateKeyPEM(bad, ""); err == nil {
		t.Fatal("expected parse error")
	}

	// garbage encrypted data
	badEnc := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{9, 9}})
	if _, err := DecryptPrivateKeyPEM(badEnc, "x"); err == nil {
		t.Fatal("expected encrypted parse error")
	}

	// IsEncryptedPEM on nil
	if IsEncryptedPEM(nil) {
		t.Fatal("nil should not be encrypted")
	}
}

// ─── Hash / PEM helpers ──────────────────────────────────────────────

func TestParseHashAlgoAndSPKIHash(t *testing.T) {
	oid, err := ParseHashAlgo("")
	if err != nil || oid != nil {
		t.Fatalf("empty should return nil oid, got %v %v", oid, err)
	}
	oid, err = ParseHashAlgo("SHA384")
	if err != nil {
		t.Fatal(err)
	}
	if !oid.Equal(HashAlgoOIDs["sha384"]) {
		t.Fatalf("unexpected oid %v", oid)
	}
	if _, err := ParseHashAlgo("md5"); err == nil {
		t.Fatal("expected unsupported algo error")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := SPKIHash(&key.PublicKey)
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(h))
	}

	// SPKIHash error path: unsupported public key type
	type weirdKey struct{}
	if got := SPKIHash(weirdKey{}); got != nil {
		t.Fatalf("expected nil for unsupported key, got %v", got)
	}

	// DefaultHashAlgo
	if !DefaultHashAlgo().Equal(HashAlgoOIDs["sha256"]) {
		t.Fatal("default hash should be sha256")
	}

	// PrincipalUid helpers
	pu := PrincipalUid{Realm: "r", Identifier: "i", KeyHash: []byte{1, 2, 3}}
	if !pu.HashAlgoOID().Equal(DefaultHashAlgo()) {
		t.Fatal("empty HashAlgo should default to sha256")
	}
	pu2 := PrincipalUid{HashAlgo: AlgorithmIdentifier{Algorithm: HashAlgoOIDs["sm3"]}}
	if !pu2.HashAlgoOID().Equal(HashAlgoOIDs["sm3"]) {
		t.Fatal("explicit HashAlgo should be honored")
	}
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return &struct{ x int }{1} }
func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("noop")
}

func TestKeyToPEMErrorPath(t *testing.T) {
	// error path: unsupported key type
	if _, err := KeyToPEM(unsupportedSigner{}); err == nil {
		t.Fatal("expected marshal error for unsupported key")
	}

	// CertToPEM
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if CertToPEM(der) == nil {
		t.Fatal("CertToPEM returned nil")
	}
}

func TestParseGrant(t *testing.T) {
	scheme, capID := parseGrant("varwof/demo-mysql-v1:SELECT:*")
	if scheme != "varwof/demo-mysql-v1" || capID != "SELECT:*" {
		t.Fatalf("unexpected: %q %q", scheme, capID)
	}
	scheme, capID = parseGrant("plaincap")
	if scheme != "generic" || capID != "plaincap" {
		t.Fatalf("unexpected: %q %q", scheme, capID)
	}
}

// ─── parseSANs ────────────────────────────────────────────────────

func TestParseSANs(t *testing.T) {
	tmpl := &x509.Certificate{}
	err := parseSANs(tmpl, []string{
		"DNS:example.com",
		"IP:1.2.3.4",
		"URI:spiffe://example/host",
		"email:test@example.com",
	})
	if err != nil {
		t.Fatalf("valid SANs: %v", err)
	}
	if len(tmpl.DNSNames) != 1 || len(tmpl.IPAddresses) != 1 || len(tmpl.URIs) != 1 || len(tmpl.EmailAddresses) != 1 {
		t.Fatalf("unexpected SAN counts: %+v", tmpl)
	}

	cases := []struct {
		sans []string
	}{
		{[]string{"DNS:bad name!"}},
		{[]string{"IP:999.1.1.1"}},
		{[]string{"URI:::"}},
		{[]string{"email:@@"}},
		{[]string{"foo:bar"}},
	}
	for _, c := range cases {
		if err := parseSANs(&x509.Certificate{}, c.sans); err == nil {
			t.Fatalf("expected error for %v", c.sans)
		}
	}

	// DirName valid full attributes
	tmpl2 := &x509.Certificate{}
	if err := parseSANs(tmpl2, []string{"DirName:CN=foo, O=Org, OU=Dev, C=CN, L=City, ST=State"}); err != nil {
		t.Fatalf("DirName valid: %v", err)
	}
	if len(tmpl2.ExtraExtensions) != 1 {
		t.Fatalf("expected one ExtraExtension, got %d", len(tmpl2.ExtraExtensions))
	}

	// DirName mixed with other SAN types → hasOther branch
	tmpl3 := &x509.Certificate{}
	if err := parseSANs(tmpl3, []string{"DNS:example.org", "DirName:CN=foo,O=Org"}); err != nil {
		t.Fatalf("mixed: %v", err)
	}
	if len(tmpl3.DNSNames) != 0 {
		t.Fatal("DNSNames should be cleared when mixing with DirName")
	}

	// DirName errors
	for _, sans := range [][]string{
		{"DirName:CN"},
		{"DirName:FOO=bar"},
		{"DirName:CN=foo,"},
	} {
		if err := parseSANs(&x509.Certificate{}, sans); err == nil {
			t.Fatalf("expected DirName error for %v", sans)
		}
	}
}

// ─── RevokeBySubCA / BackfillAICFields ────────────────────────────

func signTestAICCert(t *testing.T, d *db.DB, caCert *x509.Certificate, caKey crypto.Signer, cn string) (*SignResult, *ecdsa.PrivateKey) {
	t.Helper()
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sc := &SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		SubjectPubKey: &agentKey.PublicKey,
		CommonName:    cn,
		Subject:       &pkix.Name{CommonName: cn, OrganizationalUnit: []string{"gateway:ops"}},
		Validity:      time.Hour,
		Profile:       ProfileAgentProxy,
		AIC: &AICConfig{
			AgentId:      cn,
			PrincipalUid: PrincipalUid{Realm: "pki", Identifier: "uid-" + cn, KeyHash: make([]byte, 32)},
			Capabilities: []Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT"}},
			DelegationAuthorization: &DelegationAuthorization{
				Reason:             Reason{ReasonCode: "TEST", Description: "test"},
				SignatureValue:     []byte{1},
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
				Timestamp:          time.Now(),
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
			},
		},
	}
	res, err := Sign(sc)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return res, agentKey
}

func TestBackfillAICFields(t *testing.T) {
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)

	// Insert a record whose DER carries the AIC extension but the
	// principal_uid/agent_id columns are empty (mimics legacy rows).
	res, _ := signTestAICCert(t, d, caCert, caKey, "backfill-agent")
	uid := "pki:uid-backfill-agent:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	rec := &db.CertRecord{
		SerialNumber: "DEADBEEF001",
		CAName:       "test-ca",
		Status:       "V",
		Subject:      "CN=backfill-agent",
		CommonName:   "backfill-agent",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		CertDER:      res.CertDER,
		Fingerprint:  db.Fingerprint(res.CertDER),
		Profile:      "agent-proxy",
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := BackfillAICFields(d); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	got, err := d.GetCert("test-ca", "DEADBEEF001")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrincipalUid != uid || got.AgentId != "backfill-agent" {
		t.Fatalf("expected backfill %q/%q, got %q/%q", uid, "backfill-agent", got.PrincipalUid, got.AgentId)
	}

	// Second run is idempotent.
	if err := BackfillAICFields(d); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
}

func TestBackfillAICFieldsErrors(t *testing.T) {
	d := newTestDB(t)

	// Garbage DER → extract fails → row skipped, no error.
	rec := &db.CertRecord{
		SerialNumber: "GARBAGE01",
		CAName:       "test-ca",
		Status:       "V",
		Subject:      "CN=x",
		CommonName:   "x",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		CertDER:      []byte{1, 2, 3},
		Fingerprint:  "f",
		Profile:      "agent-proxy",
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := BackfillAICFields(d); err != nil {
		t.Fatalf("expected no error for unparseable DER, got %v", err)
	}

	// Non-AIC cert → extractAICFields returns empty → skipped.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "plain"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	rec2 := &db.CertRecord{
		SerialNumber: "PLAIN001",
		CAName:       "test-ca",
		Status:       "V",
		Subject:      "CN=plain",
		CommonName:   "plain",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		CertDER:      der,
		Fingerprint:  db.Fingerprint(der),
		Profile:      "agent-proxy",
	}
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}
	if err := BackfillAICFields(d); err != nil {
		t.Fatalf("expected no error for non-AIC cert, got %v", err)
	}
}

func TestRevokeBySubCA(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 3; i++ {
		rec := &db.CertRecord{
			SerialNumber: "SER" + string(rune('A'+i)),
			CAName:       "sub-ca-x",
			Status:       "V",
			Subject:      "CN=cert",
			CommonName:   "cert",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			CertDER:      []byte{1},
			Fingerprint:  "f",
		}
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
	}
	n, err := RevokeBySubCA(d, "sub-ca-x", 1)
	if err != nil || n != 3 {
		t.Fatalf("RevokeBySubCA: n=%d err=%v", n, err)
	}
}

// ─── Sub-CA related ──────────────────────────────────────────────────

func newSubCATestCA(t *testing.T) (*db.DB, *x509.Certificate, crypto.Signer) {
	t.Helper()
	d := newTestDB(t)
	caCert, caKey := newTestCA(t)
	return d, caCert, caKey
}

func TestIssueAndVerifySubCA(t *testing.T) {
	d, parentCert, parentKey := newSubCATestCA(t)
	cfg := &SubCAConfig{
		Name:       "sub-ok",
		ParentCA:   "parent",
		KeyType:    "ecdsa-p256",
		Validity:   365 * 24 * time.Hour,
		MaxPathLen: 0,
	}
	res, err := IssueSubCA(d, cfg, parentCert, parentKey)
	if err != nil {
		t.Fatalf("IssueSubCA: %v", err)
	}
	if res.Cert == nil || res.Key == nil {
		t.Fatal("missing result fields")
	}

	meta, err := VerifySubCA(d, "sub-ok")
	if err != nil {
		t.Fatalf("VerifySubCA: %v", err)
	}
	if meta.Name != "sub-ok" {
		t.Fatalf("unexpected name %q", meta.Name)
	}

	// not found
	if _, err := VerifySubCA(d, "nope"); err != ErrSubCANotFound {
		t.Fatalf("expected ErrSubCANotFound, got %v", err)
	}

	// revoked
	if err := d.RevokeSubCA("sub-ok", 1, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySubCA(d, "sub-ok"); err != ErrSubCARevoked {
		t.Fatalf("expected ErrSubCARevoked, got %v", err)
	}

	// expired
	expiredCert := &x509.Certificate{SerialNumber: big.NewInt(7), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredCert, expiredCert, &parentKey.(*ecdsa.PrivateKey).PublicKey, parentKey)
	expiredRec := &db.SubCAMeta{
		Name:         "sub-expired",
		ParentCA:     "parent",
		CertDER:      expiredDER,
		Subject:      "CN=sub-expired",
		NotBefore:    time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		NotAfter:     time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "f",
		Status:       "active",
	}
	if err := d.InsertSubCA(expiredRec); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySubCA(d, "sub-expired"); err != ErrSubCAExpired {
		t.Fatalf("expected ErrSubCAExpired, got %v", err)
	}
}

func TestGetSubCACertChainAndExport(t *testing.T) {
	d, parentCert, parentKey := newSubCATestCA(t)
	cfg := &SubCAConfig{
		Name:       "sub-chain",
		ParentCA:   "parent-root",
		KeyType:    "ecdsa-p256",
		Validity:   365 * 24 * time.Hour,
		MaxPathLen: 0,
	}
	if _, err := IssueSubCA(d, cfg, parentCert, parentKey); err != nil {
		t.Fatal(err)
	}
	subRec, err := d.GetSubCA("sub-chain")
	if err != nil {
		t.Fatal(err)
	}

	// without parent CA record → chain has 1 cert
	chain, err := GetSubCACertChain(d, "sub-chain")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected chain len 1, got %d", len(chain))
	}

	// with parent CA record → chain has 2 certs
	_ = d.InsertCAMeta(&db.CAMeta{
		Name:         "parent-root",
		CertDER:      parentCert.Raw,
		Subject:      parentCert.Subject.String(),
		NotBefore:    parentCert.NotBefore,
		NotAfter:     parentCert.NotAfter,
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  db.Fingerprint(parentCert.Raw),
	})
	chain2, err := GetSubCACertChain(d, "sub-chain")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain2) != 2 {
		t.Fatalf("expected chain len 2, got %d", len(chain2))
	}

	// not found
	if _, err := GetSubCACertChain(d, "missing"); err == nil {
		t.Fatal("expected error for missing sub-CA")
	}

	// export
	certPEM, keyPEM, err := ExportSubCA(d, "sub-chain")
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 {
		t.Fatal("expected cert PEM")
	}
	if len(keyPEM) != 0 {
		t.Fatal("expected empty key PEM (IssueSubCA does not store the key)")
	}

	// encrypted-key branch: insert a record with KeyEncrypted set
	encRec := &db.SubCAMeta{
		Name:         "sub-encrypted",
		ParentCA:     "parent-root",
		CertDER:      subRec.CertDER,
		KeyEncrypted: []byte("enc-key"),
		Subject:      "CN=sub-encrypted",
		NotBefore:    time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "f",
		Status:       "active",
	}
	if err := d.InsertSubCA(encRec); err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := ExportSubCA(d, "sub-encrypted")
	if err != nil {
		t.Fatal(err)
	}
	if len(keyPEM2) == 0 {
		t.Fatal("expected encrypted key PEM")
	}

	if _, _, err := ExportSubCA(d, "missing"); err == nil {
		t.Fatal("expected export error for missing sub-CA")
	}
}

func TestGenerateAndParseSubCAKey(t *testing.T) {
	key, err := GenerateSubCAKey("ecdsa-p256")
	if err != nil || key == nil {
		t.Fatalf("GenerateSubCAKey: %v", err)
	}
	if _, err := GenerateSubCAKey("sm2"); err == nil {
		t.Fatal("expected SM2 unsupported error")
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := ParseSubCAKey(keyPEM)
	if err != nil || parsed == nil {
		t.Fatalf("ParseSubCAKey: %v", err)
	}
	if _, err := ParseSubCAKey([]byte("garbage")); err == nil {
		t.Fatal("expected parse error for garbage")
	}
}

// ─── ValidateAdminCertFromPEM ─────────────────────────────────────

func adminCertWithScope(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, scope string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var exts []pkix.Extension
	if scope != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1},
			Value: []byte(scope),
		})
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(42),
		Subject:         pkix.Name{CommonName: "admin-user"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: exts,
		URIs:            []*url.URL{{Scheme: "urn", Opaque: "pki:ca:" + scope}},
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

func TestValidateAdminCertFromPEM(t *testing.T) {
	caCert, caKey := newTestCA(t)
	admin := adminCertWithScope(t, caCert, caKey, "target-ca")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: admin.Raw})

	// valid, no target
	cert, err := ValidateAdminCertFromPEM(pemBytes)
	if err != nil || cert == nil {
		t.Fatalf("ValidateAdminCertFromPEM: %v", err)
	}

	// valid with matching target (comma-separated scope)
	cert2, err := ValidateAdminCertFromPEMWithTarget(pemBytes, "target-ca")
	if err != nil || cert2 == nil {
		t.Fatalf("WithTarget matching: %v", err)
	}
	// scope mismatch
	if _, err := ValidateAdminCertFromPEMWithTarget(pemBytes, "other-ca"); err == nil {
		t.Fatal("expected scope mismatch error")
	}

	// nil PEM / bad PEM / bad DER
	if _, err := ValidateAdminCertFromPEM(nil); err == nil {
		t.Fatal("expected error for nil PEM")
	}
	if _, err := ValidateAdminCertFromPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM")
	}
	badDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}})
	if _, err := ValidateAdminCertFromPEM(badDER); err == nil {
		t.Fatal("expected parse error")
	}

	// no DigitalSignature KU
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noKU := &x509.Certificate{SerialNumber: big.NewInt(43), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	noKUDer, _ := x509.CreateCertificate(rand.Reader, noKU, caCert, &key.PublicKey, caKey)
	noKUPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: noKUDer})
	if _, err := ValidateAdminCertFromPEM(noKUPEM); err == nil {
		t.Fatal("expected error for missing DigitalSignature")
	}

	// no scope + target required
	noScope := adminCertWithScope(t, caCert, caKey, "")
	noScopePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: noScope.Raw})
	if _, err := ValidateAdminCertFromPEMWithTarget(noScopePEM, "target-ca"); err == nil {
		t.Fatal("expected error for missing scope")
	}

	// ValidateAdminCertWithTarget: nil cert
	if err := ValidateAdminCertWithTarget(nil, nil, ""); err == nil {
		t.Fatal("expected error for nil cert")
	}

	// chain verification failure: cert signed by a different CA
	otherCA, otherKey := newTestCA(t)
	foreign := adminCertWithScope(t, otherCA, otherKey, "target-ca")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if err := ValidateAdminCertWithTarget(foreign, pool, ""); err == nil {
		t.Fatal("expected chain verification failure")
	}

	// chain verification success
	ownPool := x509.NewCertPool()
	ownPool.AddCert(caCert)
	if err := ValidateAdminCertWithTarget(admin, ownPool, ""); err != nil {
		t.Fatalf("chain verify success: %v", err)
	}

	// ExtractAdminScope on nil cert
	if got := ExtractAdminScope(nil); got != "" {
		t.Fatalf("expected empty scope for nil cert, got %q", got)
	}
	if got := ExtractAdminScope(admin); got != "target-ca" {
		t.Fatalf("expected target-ca, got %q", got)
	}
	multi := adminCertWithScope(t, caCert, caKey, "a, b, a")
	if got := ExtractAdminScope(multi); got != "a,b" {
		t.Fatalf("expected dedup a,b, got %q", got)
	}
}

func TestApplySubCAKeyUsage(t *testing.T) {
	tmpl := &x509.Certificate{}
	applySubCAKeyUsage(tmpl, []string{
		"digital_signature", "key_encipherment", "data_encipherment",
		"key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only",
		"unknown",
	})
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly
	if tmpl.KeyUsage != want {
		t.Fatalf("expected %d, got %d", want, tmpl.KeyUsage)
	}

	if got := joinKeyUsage([]string{"a", "b"}); got != "a,b" {
		t.Fatalf("joinKeyUsage: %q", got)
	}

	// ParseSubCACert error paths
	if _, err := ParseSubCACert([]byte("nope")); err == nil {
		t.Fatal("expected error for non-PEM")
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	if _, err := ParseSubCACert(bad); err == nil {
		t.Fatal("expected parse error")
	}
}

// ─── SM2 stubs (non-gmsm build) ─────────────────────────────────────

func TestSM2Stubs(t *testing.T) {
	if sm2Supported {
		t.Fatal("sm2Supported should be false without gmsm tag")
	}
	if isSM2Key(nil) {
		t.Fatal("isSM2Key should be false")
	}
	if _, err := generateSM2Key(); err == nil {
		t.Fatal("expected SM2 unsupported error")
	}
	if _, err := marshalSM2PrivateKey(nil); err == nil {
		t.Fatal("expected SM2 marshal error")
	}
	if _, err := createSM2Certificate(nil, nil, nil, nil); err == nil {
		t.Fatal("expected SM2 create error")
	}
	if _, err := parseSM2Certificate(nil); err == nil {
		t.Fatal("expected SM2 parse error")
	}
	if _, err := parseSM2PrivateKeyPEM(nil, nil); err == nil {
		t.Fatal("expected SM2 key parse error")
	}
	if exportSM2Key(nil) != nil {
		t.Fatal("exportSM2Key should pass through")
	}
}

// ─── TrustAnchorFederate ──────────────────────────────────────────

func TestTrustAnchorFederateError(t *testing.T) {
	d := newTestDB(t)
	if _, err := TrustAnchorFederate(d, "://not-a-url"); err == nil {
		t.Fatal("expected fetch error for bad URL")
	}
}

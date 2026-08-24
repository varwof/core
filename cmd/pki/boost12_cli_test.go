package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func newIssueCfg(t *testing.T, dir, caName string) (*db.DB, *internal.Config, string, string) {
	t.Helper()
	caCertPath, caKeyPath := writeCACertKey(t, dir, caName)
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			caName: {Cert: caCertPath, Key: caKeyPath},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
			Profile: "tls-server",
		},
	}
	registerCACert(d, caName, caCertPath)
	return d, cfg, caCertPath, caKeyPath
}

// ---------- cmdIssue extra branches ----------

func TestCLIIssueDefaultCAAndKeyType(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "def-ca")
	cfg.Defaults.CA = "def-ca"

	outPath := filepath.Join(dir, "def.pem")
	if err := cmdIssue(cfg, []string{
		"--cn", "def-ca.example.com",
		"--san", "DNS:def-ca.example.com",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with default CA/key-type: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("expected cert output")
	}
}

func TestCLIIssueDefaultProfile(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "prof-ca")
	cfg.Defaults.Profile = "tls-client"

	outPath := filepath.Join(dir, "prof.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "prof-ca",
		"--cn", "prof.example.com",
		"--san", "DNS:prof.example.com",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with default profile: %v", err)
	}
	cert := readCertFile(t, outPath)
	if len(cert.ExtKeyUsage) == 0 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("expected client-auth EKU, got %v", cert.ExtKeyUsage)
	}
}

func TestCLIIssueScopeMirror(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "scope-ca")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"ca-scope-only", []string{"--ca-scope", "Client CA"}},
		{"scope-only", []string{"--scope", "Issuing CA"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(dir, "scope-"+tc.name+".pem")
			args := []string{"--ca", "scope-ca", "--cn", tc.name + ".example.com",
				"--san", "DNS:" + tc.name + ".example.com", "--out", outPath}
			args = append(args, tc.args...)
			if err := cmdIssue(cfg, args); err != nil {
				t.Fatalf("issue: %v", err)
			}
			cert := readCertFile(t, outPath)
			if len(cert.URIs) == 0 {
				t.Fatal("expected scope URI in issued cert")
			}
			if got := cert.URIs[0].String(); !strings.Contains(got, "pki:ca:") {
				t.Fatalf("expected pki:ca: scope URI, got %s", got)
			}
		})
	}
}

func TestCLIIssueAsFlag(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "as-ca")

	outPath := filepath.Join(dir, "as.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "as-ca",
		"--cn", "as.example.com",
		"--as", "gateway-ops",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with --as: %v", err)
	}
	cert := readCertFile(t, outPath)
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "gateway-ops" {
		t.Fatalf("expected OU gateway-ops, got %v", cert.Subject.OrganizationalUnit)
	}
}

func TestCLIIssueDefaultPaths(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "paths-ca")
	t.Chdir(dir)

	if err := cmdIssue(cfg, []string{
		"--ca", "paths-ca",
		"--cn", "paths.example.com",
		"--san", "DNS:paths.example.com",
	}); err != nil {
		t.Fatalf("issue without --out: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	var pemFiles, keyFiles int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pem") {
			pemFiles++
		}
		if strings.HasSuffix(e.Name(), ".key") {
			keyFiles++
		}
	}
	if pemFiles == 0 {
		t.Fatal("expected default serial.pem output")
	}
	if keyFiles == 0 {
		t.Fatal("expected default .key output")
	}
}

func TestCLIIssueKeyPassword(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "kp-ca")

	outPath := filepath.Join(dir, "kp.pem")
	outKey := filepath.Join(dir, "kp.key")
	if err := cmdIssue(cfg, []string{
		"--ca", "kp-ca",
		"--cn", "kp.example.com",
		"--out", outPath,
		"--out-key", outKey,
		"--key-password", "secretpw",
	}); err != nil {
		t.Fatalf("issue with key password: %v", err)
	}
	keyData, _ := os.ReadFile(outKey)
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("expected ENCRYPTED PRIVATE KEY, got %v", block)
	}
}

func TestCLIIssueMultipleSANs(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "multi-san-ca")

	outPath := filepath.Join(dir, "multi.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "multi-san-ca",
		"--cn", "multi.example.com",
		"--san", "DNS:multi.example.com,DNS:alt.example.com,IP:192.168.1.10",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with multiple SANs: %v", err)
	}
	cert := readCertFile(t, outPath)
	if len(cert.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS SANs, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.168.1.10" {
		t.Fatalf("expected IP SAN, got %v", cert.IPAddresses)
	}
}

func TestCLIIssueSubjectCNOverride(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "ov-ca")

	outPath := filepath.Join(dir, "ov.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "ov-ca",
		"--cn", "override.example.com",
		"--subject", "/CN=subject-cn.example.com/O=Test",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with subject+cn override: %v", err)
	}
	cert := readCertFile(t, outPath)
	if cert.Subject.CommonName != "override.example.com" {
		t.Fatalf("expected --cn override, got %q", cert.Subject.CommonName)
	}
}

func TestCLIIssueEncryptedCAKey(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, caKeyPath := newIssueCfg(t, dir, "enc-ca")

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ca.EncryptPrivateKeyPEM(signer, "enc-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caKeyPath, enc, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKI_KEY_PASSWORD", "enc-secret")

	outPath := filepath.Join(dir, "enc.pem")
	if err := cmdIssue(cfg, []string{
		"--ca", "enc-ca",
		"--cn", "enc.example.com",
		"--out", outPath,
	}); err != nil {
		t.Fatalf("issue with encrypted CA key: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("expected cert output")
	}
}

func TestCLIIssueMissingCN(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "ncn-ca")
	if err := cmdIssue(cfg, []string{"--ca", "ncn-ca"}); err == nil {
		t.Fatal("expected error for missing CN")
	}
}

func TestCLIIssueCAUnknown(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "unk-ca")
	if err := cmdIssue(cfg, []string{"--ca", "nope", "--cn", "x.example.com"}); err == nil {
		t.Fatal("expected error for unknown CA")
	}
}

func TestCLIIssueOpenDBError(t *testing.T) {
	cfg := &internal.Config{DB: "/nonexistent/db"}
	if err := cmdIssue(cfg, []string{"--ca", "x", "--cn", "y.example.com"}); err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

func TestCLIIssueLoadCAError(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, caKeyPath := newIssueCfg(t, dir, "loaderr-ca")
	os.WriteFile(caKeyPath, []byte("not a key"), 0600)
	if err := cmdIssue(cfg, []string{"--ca", "loaderr-ca", "--cn", "x.example.com"}); err == nil {
		t.Fatal("expected error for bad CA key")
	}
}

func TestCLIIssueUnknownKeyTypeFallback(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := newIssueCfg(t, dir, "bkt-ca")

	outPath := filepath.Join(dir, "fb.pem")
	if err := cmdIssue(cfg, []string{"--ca", "bkt-ca", "--cn", "fb.example.com", "--key-type", "banana", "--out", outPath}); err != nil {
		t.Fatalf("unknown key type should fall back to default: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("expected cert output")
	}
}

// ---------- cmdRevoke extra branches ----------

func TestCLIRevokeByCertFile(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "by-file.example.com")
	rec, err := d.GetCert("rev-ca", serial)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := ca.CertToPEM(rec.CertDER)
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := cmdRevoke(cfg, []string{"--ca", "rev-ca", "--cert", certPath}); err != nil {
		t.Fatalf("revoke by cert file: %v", err)
	}
	rec, _ = d.GetCert("rev-ca", serial)
	if rec.Status != "R" {
		t.Fatalf("expected revoked, got %q", rec.Status)
	}
}

func TestCLIRevokeMissingSerialOrCert(t *testing.T) {
	cfg := &internal.Config{DB: newTestDBPath(t)}
	if err := cmdRevoke(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing serial/cert")
	}
}

func TestCLIRevokeBadReason(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)
	if err := cmdRevoke(cfg, []string{"--ca", "rev-ca", "--serial", "AABB", "--reason", "banana"}); err == nil {
		t.Fatal("expected error for bad reason")
	}
}

func TestCLIRevokeBadCertPEM(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)
	badPath := filepath.Join(dir, "bad.pem")
	os.WriteFile(badPath, []byte("not a pem"), 0644)
	if err := cmdRevoke(cfg, []string{"--ca", "rev-ca", "--cert", badPath}); err == nil {
		t.Fatal("expected error for bad cert PEM")
	}
}

func TestCLIRevokeCertFileMissing(t *testing.T) {
	_, cfg, _, _ := setupTestCA(t, t.TempDir())
	if err := cmdRevoke(cfg, []string{"--ca", "rev-ca", "--cert", "/nonexistent/cert.pem"}); err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestCLIRevokeByPrincipalUID(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "agent.example.com")
	if err := d.BackfillAICFieldsFromDer("rev-ca", serial, "varwof:alice:abc", "agent-1"); err != nil {
		t.Fatal(err)
	}

	if err := cmdRevoke(cfg, []string{"--principal-uid", "varwof:alice:abc"}); err != nil {
		t.Fatalf("revoke by principal-uid: %v", err)
	}
	rec, _ := d.GetCert("rev-ca", serial)
	if rec.Status != "R" {
		t.Fatalf("expected revoked by principal-uid, got %q", rec.Status)
	}
}

func TestCLIRevokeByPrincipalUIDUnknown(t *testing.T) {
	_, cfg, _, _ := setupTestCA(t, t.TempDir())
	if err := cmdRevoke(cfg, []string{"--principal-uid", "nobody"}); err != nil {
		t.Fatalf("revoke unknown principal should not error: %v", err)
	}
}

func TestCLIRevokeBySubCA(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	// Issue two certs under the same sub-CA scope, then revoke all.
	for _, cn := range []string{"a.example.com", "b.example.com"} {
		issueTestCert(t, d, caCert, caKey, "rev-ca", cn)
	}
	if err := cmdRevoke(cfg, []string{"--sub-ca", "rev-ca"}); err != nil {
		t.Fatalf("revoke by sub-ca: %v", err)
	}
	certs, err := d.ListCertsFiltered("rev-ca", "V", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no valid certs remaining, got %d", len(certs))
	}
}

func TestCLIRevokeBySubCAUnknown(t *testing.T) {
	_, cfg, _, _ := setupTestCA(t, t.TempDir())
	if err := cmdRevoke(cfg, []string{"--sub-ca", "nonexistent-ca"}); err != nil {
		t.Fatalf("revoke unknown sub-ca should not error: %v", err)
	}
}

func TestCLIRevokeDefaultCAFromConfig(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults.CA = "rev-ca"

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "def-revoke.example.com")
	if err := cmdRevoke(cfg, []string{"--serial", serial}); err != nil {
		t.Fatalf("revoke with default CA: %v", err)
	}
	rec, _ := d.GetCert("rev-ca", serial)
	if rec.Status != "R" {
		t.Fatalf("expected revoked, got %q", rec.Status)
	}
}

func TestCLIRevokeNonCertificatePEM(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, _ := ca.KeyToPEM(key)
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(keyPath, keyPEM, 0600)

	if err := cmdRevoke(cfg, []string{"--ca", "rev-ca", "--cert", keyPath}); err == nil {
		t.Fatal("expected error for non-certificate PEM")
	}
}

// ---------- cmdRenew extra branches ----------

func TestCLIRenewDefaultCAFromConfig(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults.CA = "rev-ca"
	cfg.Defaults.KeyType = "ecdsa-p256"

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "default-ca.example.com")
	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0755)

	if err := cmdRenew(cfg, []string{"--serial", serial, "--out-dir", outDir}); err != nil {
		t.Fatalf("renew with default CA: %v", err)
	}
}

func TestCLIRenewCADenied(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result, err := ca.Sign(&ca.SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "rev-ca",
		Profile:       ca.ProfileSubCA,
		CommonName:    "sub.example.com",
		SubjectPubKey: key.Public(),
		Validity:      365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := cmdRenew(cfg, []string{"--ca", "rev-ca", "--serial", result.SerialHex, "--out-dir", dir}); err == nil {
		t.Fatal("expected error refusing to renew a CA certificate")
	}
}

func TestCLIRenewCAUnknown(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "unknown-ca.example.com")

	if err := cmdRenew(cfg, []string{"--ca", "nope", "--serial", serial}); err == nil {
		t.Fatal("expected error for unknown CA")
	}
}

func TestCLIRenewUnknownKeyTypeFallback(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "bad-key-type.example.com")

	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0755)
	if err := cmdRenew(cfg, []string{"--ca", "rev-ca", "--serial", serial, "--key-type", "banana", "--out-dir", outDir}); err != nil {
		t.Fatalf("unknown key type should fall back to default: %v", err)
	}
}

func TestCLIRenewInvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)
	badPath := filepath.Join(dir, "bad.pem")
	os.WriteFile(badPath, []byte("not a pem"), 0644)

	if err := cmdRenew(cfg, []string{"--cert", badPath}); err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestCLIRenewCertFileMissing(t *testing.T) {
	_, cfg, _, _ := setupTestCA(t, t.TempDir())
	if err := cmdRenew(cfg, []string{"--cert", "/nonexistent/cert.pem"}); err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestCLIRenewSerialNotFound(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)
	if err := cmdRenew(cfg, []string{"--ca", "rev-ca", "--serial", "DEADBEEF", "--out-dir", dir}); err == nil {
		t.Fatal("expected error for nonexistent serial")
	}
}

func TestCLIRenewBadKeyFile(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "bad-key.example.com")

	badKey := filepath.Join(dir, "bad.key")
	os.WriteFile(badKey, []byte("not a key"), 0600)
	if err := cmdRenew(cfg, []string{
		"--ca", "rev-ca", "--serial", serial,
		"--keep-key", "--key", badKey, "--out-dir", dir,
	}); err == nil {
		t.Fatal("expected error for bad key file")
	}
}

func TestCLIRenewOpenDBError(t *testing.T) {
	cfg := &internal.Config{DB: "/nonexistent/db"}
	if err := cmdRenew(cfg, []string{"--ca", "x", "--serial", "AABB"}); err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

func TestCLIRenewVPNProfilePreserve(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults.Hash = "sha256"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result, err := ca.Sign(&ca.SignConfig{
		DB:            d,
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "rev-ca",
		Profile:       ca.ProfileVPNClient,
		CommonName:    "vpn.example.com",
		SubjectPubKey: key.Public(),
		SANs:          []string{"DNS:vpn.example.com"},
		Validity:      90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0755)

	if err := cmdRenew(cfg, []string{"--ca", "rev-ca", "--serial", result.SerialHex, "--out-dir", outDir}); err != nil {
		t.Fatalf("renew vpn profile: %v", err)
	}
}

// ---------- cmdCAOfflineSign ----------

func TestCAOfflineSignSuccess(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "offline")
	csrPath := writeTestCSR(t, dir, "offline-sub.example.com")

	outPath := filepath.Join(dir, "signed.pem")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", outPath,
		"--validity", "365",
	}); err != nil {
		t.Fatalf("offline sign: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("signed cert not created")
	}
}

func TestCAOfflineSignCustomHash(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "offhash")
	csrPath := writeTestCSR(t, dir, "hash.example.com")

	outPath := filepath.Join(dir, "hash.pem")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", outPath,
		"--hash", "sha512",
	}); err != nil {
		t.Fatalf("offline sign sha512: %v", err)
	}

	// Unknown hash falls back to sha256 without error.
	out2 := filepath.Join(dir, "fallback.pem")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", out2,
		"--hash", "md5",
	}); err != nil {
		t.Fatalf("offline sign fallback hash: %v", err)
	}
}

func TestCAOfflineSignEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "offenc")
	csrPath := writeTestCSR(t, dir, "enc.example.com")

	keyPEM, _ := os.ReadFile(caKeyPath)
	signer, err := ca.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ca.EncryptPrivateKeyPEM(signer, "offline-pw")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(caKeyPath, enc, 0600)

	outPath := filepath.Join(dir, "enc-signed.pem")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", outPath,
		"--ca-key-password", "offline-pw",
	}); err != nil {
		t.Fatalf("offline sign encrypted key: %v", err)
	}
}

func TestCAOfflineSignMissingFlags(t *testing.T) {
	cfg := &internal.Config{}
	for _, args := range [][]string{
		{},
		{"--ca-cert", "x.pem"},
		{"--ca-cert", "x.pem", "--ca-key", "x.key"},
		{"--ca-cert", "x.pem", "--ca-key", "x.key", "--csr", "x.csr"},
	} {
		if err := cmdCAOfflineSign(cfg, args); err == nil {
			t.Fatalf("expected error for args %v", args)
		}
	}
}

func TestCAOfflineSignReadErrors(t *testing.T) {
	dir := t.TempDir()
	csrPath := writeTestCSR(t, dir, "err.example.com")

	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", "/nonexistent/ca.pem",
		"--ca-key", "/nonexistent/ca.key",
		"--csr", csrPath,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for missing CA cert")
	}

	caCertPath, caKeyPath := writeCACertKey(t, dir, "oferr")
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", "/nonexistent/ca.key",
		"--csr", csrPath,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for missing CA key")
	}

	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", "/nonexistent/x.csr",
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for missing CSR")
	}
}

func TestCAOfflineSignBadInputs(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ofbad")
	csrPath := writeTestCSR(t, dir, "bad.example.com")

	// Bad CA key PEM.
	badKey := filepath.Join(dir, "bad.key")
	os.WriteFile(badKey, []byte("not a key"), 0600)
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", badKey,
		"--csr", csrPath,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for bad CA key")
	}

	// Bad CSR PEM.
	badCSR := filepath.Join(dir, "bad.csr")
	os.WriteFile(badCSR, []byte("not a csr"), 0644)
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", badCSR,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for bad CSR")
	}
}

func TestCAOfflineSignBadCACertPEM(t *testing.T) {
	dir := t.TempDir()
	caKeyPath := filepath.Join(dir, "k.key")
	os.WriteFile(caKeyPath, []byte("not a key"), 0600)
	csrPath := writeTestCSR(t, dir, "bad-cert.example.com")

	// Not PEM at all.
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", filepath.Join(dir, "missing.pem"),
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for missing CA cert")
	}

	// PEM block that is not a certificate (a key PEM).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, _ := ca.KeyToPEM(key)
	keyAsCert := filepath.Join(dir, "key-as-cert.pem")
	os.WriteFile(keyAsCert, keyPEM, 0644)
	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", keyAsCert,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", filepath.Join(dir, "o.pem"),
	}); err == nil {
		t.Fatal("expected error for non-certificate PEM")
	}
}

func TestCAOfflineSignWriteError(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath := writeCACertKey(t, dir, "ofw")
	csrPath := writeTestCSR(t, dir, "w.example.com")

	if err := cmdCAOfflineSign(&internal.Config{}, []string{
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--out", filepath.Join(dir, "no-such-dir", "o.pem"),
	}); err == nil {
		t.Fatal("expected error for unwritable out path")
	}
}

// ---------- cmdCAEncryptKey ----------

func TestCAEncryptKeySuccess(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "enk")
	outPath := filepath.Join(dir, "enk-enc.pem")

	if err := cmdCAEncryptKey(&internal.Config{}, []string{
		"--key", keyPath,
		"--out", outPath,
		"--password", "pw123",
	}); err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("expected encrypted key PEM, got %v", block)
	}
}

func TestCAEncryptKeyVerify(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "envk")
	outPath := filepath.Join(dir, "envk-enc.pem")

	if err := cmdCAEncryptKey(&internal.Config{}, []string{
		"--key", keyPath,
		"--out", outPath,
		"--password", "verify-pw",
		"--verify",
	}); err != nil {
		t.Fatalf("encrypt+verify key: %v", err)
	}
}

func TestCAEncryptKeyInPlaceBackup(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "inplace")

	if err := cmdCAEncryptKey(&internal.Config{}, []string{
		"--key", keyPath,
		"--password", "inplace-pw",
	}); err != nil {
		t.Fatalf("encrypt in place: %v", err)
	}
	if _, err := os.Stat(keyPath + ".bak"); err != nil {
		t.Fatal("expected backup file")
	}
	data, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("expected in-place encrypted key, got %v", block)
	}
}

func TestCAEncryptKeyEnvPassword(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "envpw")
	outPath := filepath.Join(dir, "envpw-enc.pem")
	t.Setenv("PKI_KEY_PASSWORD", "env-secret")

	if err := cmdCAEncryptKey(&internal.Config{}, []string{
		"--key", keyPath,
		"--out", outPath,
	}); err != nil {
		t.Fatalf("encrypt key with env password: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("expected encrypted key PEM, got %v", block)
	}
}

func TestCAEncryptKeyMissingFlag(t *testing.T) {
	if err := cmdCAEncryptKey(&internal.Config{}, []string{}); err == nil {
		t.Fatal("expected error for missing --key")
	}
}

func TestCAEncryptKeyReadError(t *testing.T) {
	if err := cmdCAEncryptKey(&internal.Config{}, []string{"--key", "/nonexistent/key.pem"}); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestCAEncryptKeyParseError(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.key")
	os.WriteFile(badPath, []byte("not a key"), 0600)
	if err := cmdCAEncryptKey(&internal.Config{}, []string{"--key", badPath, "--password", "x"}); err == nil {
		t.Fatal("expected error for bad key PEM")
	}
}

func TestCAEncryptKeyWriteError(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeCACertKey(t, dir, "wrr")
	if err := cmdCAEncryptKey(&internal.Config{}, []string{
		"--key", keyPath,
		"--out", filepath.Join(dir, "no-such-dir", "enc.pem"),
		"--password", "x",
	}); err == nil {
		t.Fatal("expected error for unwritable out path")
	}
}

// ---------- helpers ----------

func readCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeTestCSR(t *testing.T, dir, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(dir, "req.csr")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}
	return csrPath
}

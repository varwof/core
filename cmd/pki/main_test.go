package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	p12 "software.sslmate.com/src/go-pkcs12"
)

func TestVersionString(t *testing.T) {
	s := versionString()
	if !strings.HasPrefix(s, "varwof 1.1.1") {
		t.Fatalf("expected prefix 'varwof 1.1.1', got %q", s)
	}
	if !strings.Contains(s, "go1.26") {
		t.Fatalf("expected Go version in output, got %q", s)
	}
}

func TestCmdVersion(t *testing.T) {
	err := cmdVersion(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestCertKey(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TestSigner"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "signer.pem")
	keyPath = filepath.Join(dir, "signer.key")

	certPEM := pemBlock("CERTIFICATE", der)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pemBlock("PRIVATE KEY", keyDER)
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func pemBlock(typ string, der []byte) []byte {
	var b strings.Builder
	if err := pem.Encode(&b, &pem.Block{Type: typ, Bytes: der}); err != nil {
		panic(err)
	}
	return []byte(b.String())
}

// -- cmdSign tests -----------------------------------------------------------

func TestCLISignDetached(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(filePath, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{}
	err := cmdSign(cfg, []string{
		"--cert", certPath,
		"--key", keyPath,
		filePath,
	})
	if err != nil {
		t.Fatalf("cmdSign: %v", err)
	}

	sigPath := filePath + ".p7s"
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatal("signature file not created")
	}
}

func TestCLISignEmbedded(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "embed.bin")
	if err := os.WriteFile(filePath, []byte("data to sign"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{}
	err := cmdSign(cfg, []string{
		"--cert", certPath,
		"--key", keyPath,
		"--embed",
		filePath,
	})
	if err != nil {
		t.Fatalf("cmdSign embed: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= len("data to sign") {
		t.Fatal("embedded data should be larger than original")
	}
}

func TestCLISignVerifyDetached(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "verify.bin")
	if err := os.WriteFile(filePath, []byte("verify me"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{}
	if err := cmdSign(cfg, []string{
		"--cert", certPath,
		"--key", keyPath,
		filePath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdSign(cfg, []string{
		"--verify",
		"--cert", certPath,
		"--key", keyPath,
		filePath,
	}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestCLISignVerifyEmbedded(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "verify-embed.bin")
	if err := os.WriteFile(filePath, []byte("verify embedded"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{}
	if err := cmdSign(cfg, []string{
		"--cert", certPath,
		"--key", keyPath,
		"--embed",
		filePath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdSign(cfg, []string{
		"--verify",
		"--embed",
		"--cert", certPath,
		"--key", keyPath,
		filePath,
	}); err != nil {
		t.Fatalf("verify embedded failed: %v", err)
	}
}

func TestCLISignMissingFile(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdSign(cfg, []string{
		"--cert", "/nonexistent/cert.pem",
		"--key", "/nonexistent/key.pem",
		"/nonexistent/file.bin",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// -- cmdVerify tests ----------------------------------------------------------

func TestCLIVerifyDetached(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "v.bin")
	if err := os.WriteFile(filePath, []byte("verify detached"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"test": {Cert: certPath}}}
	if err := cmdSign(cfg, []string{
		"--cert", certPath, "--key", keyPath, filePath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdVerify(cfg, []string{"--sig", filePath + ".p7s", filePath}); err != nil {
		t.Fatalf("cmdVerify detached: %v", err)
	}
}

func TestCLIVerifyEmbedded(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "v-embed.bin")
	if err := os.WriteFile(filePath, []byte("verify embedded"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"test": {Cert: certPath}}}
	if err := cmdSign(cfg, []string{
		"--cert", certPath, "--key", keyPath, "--embed", filePath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdVerify(cfg, []string{"--embed", filePath}); err != nil {
		t.Fatalf("cmdVerify embedded: %v", err)
	}
}

func TestCLIVerifyAutoSigPath(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "auto.bin")
	if err := os.WriteFile(filePath, []byte("auto sig path"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"test": {Cert: certPath}}}
	if err := cmdSign(cfg, []string{
		"--cert", certPath, "--key", keyPath, filePath,
	}); err != nil {
		t.Fatal(err)
	}

	// No --sig flag; should auto-detect file.bin + ".p7s"
	if err := cmdVerify(cfg, []string{filePath}); err != nil {
		t.Fatalf("cmdVerify auto: %v", err)
	}
}

func TestCLIVerifyBadSignature(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(filePath, []byte("bad data"), 0644); err != nil {
		t.Fatal(err)
	}
	badSig := filepath.Join(dir, "bad.bin.p7s")
	if err := os.WriteFile(badSig, []byte("not a p7s"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{}
	if err := cmdVerify(cfg, []string{filePath}); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestCLIVerifyMissingFile(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdVerify(cfg, []string{}); err == nil {
		t.Fatal("expected error for missing file argument")
	}
}

// -- cmdExport tests ----------------------------------------------------------

func TestCLIExportPFX(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	outPath := filepath.Join(dir, "out.pfx")

	cfg := &internal.Config{}
	err := cmdExport(cfg, []string{
		"--pfx",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outPath,
	})
	if err != nil {
		t.Fatalf("cmdExport: %v", err)
	}

	pfxData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PFX")
	}

	_, _, _, err = p12.DecodeChain(pfxData, "")
	if err != nil {
		t.Fatalf("pkcs12 DecodeChain: %v", err)
	}
}

func TestCLIExportPFXWithPassword(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	outPath := filepath.Join(dir, "out-pass.pfx")

	cfg := &internal.Config{}
	err := cmdExport(cfg, []string{
		"--pfx",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outPath,
		"--password", "test123",
	})
	if err != nil {
		t.Fatalf("cmdExport: %v", err)
	}

	pfxData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = p12.DecodeChain(pfxData, "test123")
	if err != nil {
		t.Fatalf("pkcs12 DecodeChain: %v", err)
	}
}

func TestCLIExportMissingFlags(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdExport(cfg, []string{"--pfx"})
	if err == nil {
		t.Fatal("expected error for missing --cert and --key")
	}
}

// -- cmdInitCA tests (no DB needed for basic init) ---------------------------

func TestCLIInitCA(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &internal.Config{
		DB: filepath.Join(dir, "pki.db"),
		CAs: map[string]internal.CAConfig{
			"root": {Cert: filepath.Join(outDir, "ca.pem"), Key: filepath.Join(outDir, "ca.key")},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}

	err := cmdInitCA(cfg, []string{
		"--name", "root",
		"--out-cert", filepath.Join(outDir, "ca.pem"),
		"--out-key", filepath.Join(outDir, "ca.key"),
		"--password", "TestP@ss123",
	})
	if err != nil {
		t.Fatalf("cmdInitCA: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outDir, "ca.pem")); err != nil {
		t.Fatal("ca.pem not created")
	}
	if _, err := os.Stat(filepath.Join(outDir, "ca.key")); err != nil {
		t.Fatal("ca.key not created")
	}
}

func TestCLIInitCAWithProfile(t *testing.T) {
	dir := t.TempDir()

	// Init CA with explicit profile
	outCert := filepath.Join(dir, "ca.pem")
	outKey := filepath.Join(dir, "ca.key")

	cfg := &internal.Config{
		DB: filepath.Join(dir, "pki.db"),
		CAs: map[string]internal.CAConfig{
			"testca": {Cert: outCert, Key: outKey},
		},
		Defaults: internal.DefaultsConfig{
			KeyType: "ecdsa-p256",
		},
	}

	err := cmdInitCA(cfg, []string{
		"--name", "testca",
		"--profile", "root-ca",
		"--validity", "365",
		"--out-cert", outCert,
		"--out-key", outKey,
		"--password", "TestP@ss456",
	})
	if err != nil {
		t.Fatalf("cmdInitCA: %v", err)
	}

	if _, err := os.Stat(outCert); err != nil {
		t.Fatal("ca.pem not created")
	}
}

func TestCLIInitCAMissingName(t *testing.T) {
	cfg := &internal.Config{DB: filepath.Join(t.TempDir(), "pki.db")}
	err := cmdInitCA(cfg, []string{})
	if err == nil {
		t.Fatal("expected error for missing --name")
	}
}

func TestCLIRevokeMissingCA(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{
		DB: filepath.Join(dir, "pki.db"),
	}
	err := cmdRevoke(cfg, []string{"--ca", "nonexistent", "--serial", "01"})
	if err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

func TestCLIIssueMissingCA(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdIssue(cfg, []string{"--ca", "nonexistent", "--cn", "test"})
	if err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

func TestCLICRLMissingCA(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdCRL(cfg, []string{"--ca", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

func TestParseHash(t *testing.T) {
	tests := []struct {
		s    string
		want crypto.Hash
	}{
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},
		{"", crypto.SHA256},
		{"unknown", crypto.SHA256},
	}
	for _, tt := range tests {
		got := parseHash(tt.s)
		if got != tt.want {
			t.Errorf("parseHash(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestDetectProfile(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want ca.Profile
	}{
		{
			name: "server auth",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			want: ca.ProfileTLSServer,
		},
		{
			name: "client auth",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			want: ca.ProfileTLSClient,
		},
		{
			name: "code signing",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			},
			want: ca.ProfileCodeSigning,
		},
		{
			name: "email",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			},
			want: ca.ProfileEmail,
		},
		{
			name: "timestamp",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			},
			want: ca.ProfileTimestamp,
		},
		{
			name: "ocsp signer",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			},
			want: ca.ProfileOCSPSigner,
		},
		{
			name: "document (nonRepudiation)",
			cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageContentCommitment,
			},
			want: ca.ProfileDocument,
		},
		{
			name: "unknown falls back to tls-server",
			cert: &x509.Certificate{},
			want: ca.ProfileTLSServer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectProfile(tt.cert)
			if got != tt.want {
				t.Errorf("detectProfile = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSANs(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"a.example.com", "b.example.com"},
		EmailAddresses: []string{"admin@example.com"},
	}
	sans := extractSANs(cert)
	if len(sans) != 3 {
		t.Fatalf("expected 3 SANs, got %d: %v", len(sans), sans)
	}
	if sans[0] != "DNS:a.example.com" {
		t.Errorf("sans[0] = %q, want DNS:a.example.com", sans[0])
	}
	if sans[1] != "DNS:b.example.com" {
		t.Errorf("sans[1] = %q, want DNS:b.example.com", sans[1])
	}
	if sans[2] != "email:admin@example.com" {
		t.Errorf("sans[2] = %q, want email:admin@example.com", sans[2])
	}
}

func TestLoadRootPool(t *testing.T) {
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"root": {Cert: "/nonexistent/cert.pem"}}}
	if pool := loadRootPool(cfg); pool != nil {
		t.Fatal("expected nil for missing file")
	}
}

func TestLoadRootPoolNoRoot(t *testing.T) {
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{}}
	if pool := loadRootPool(cfg); pool != nil {
		t.Fatal("expected nil when no root CA configured")
	}
}

func TestLoadRootPoolSuccess(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(certFile, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"root": {Cert: certFile}}}
	pool := loadRootPool(cfg)
	if pool == nil {
		t.Fatal("expected non-nil pool for valid cert")
	}
}

// ---------- loadChain ----------

func TestLoadChainMissing(t *testing.T) {
	_, err := loadChain("/nonexistent/chain.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadChainEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(p, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	chain, err := loadChain(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 0 {
		t.Fatal("expected empty chain")
	}
}

func TestLoadChainSingle(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	p := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(p, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	chain, err := loadChain(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain))
	}
}

func TestLoadChainNonCertPEM(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake-key")})
	dir := t.TempDir()
	p := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(p, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	chain, err := loadChain(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 0 {
		t.Fatal("expected no certs from non-cert PEM")
	}
}

// ---------- hasFlag ----------

func TestHasFlagFound(t *testing.T) {
	if !hasFlag([]string{"--foo", "--bar"}, "--bar") {
		t.Fatal("expected to find flag")
	}
}

func TestHasFlagNotFound(t *testing.T) {
	if hasFlag([]string{"--foo", "--bar"}, "--baz") {
		t.Fatal("expected not to find flag")
	}
}

func TestHasFlagEmpty(t *testing.T) {
	if hasFlag(nil, "--anything") {
		t.Fatal("expected false for empty args")
	}
}

// ---------- parseOID ----------

func TestParseOIDValid(t *testing.T) {
	oid, err := internal.ParseOID("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(oid) != 4 || oid[0] != 1 || oid[1] != 2 || oid[2] != 3 || oid[3] != 4 {
		t.Fatalf("unexpected OID: %v", oid)
	}
}

func TestParseOIDTooShort(t *testing.T) {
	_, err := internal.ParseOID("1")
	if err == nil {
		t.Fatal("expected error for too-short OID")
	}
}

func TestParseOIDBadComponent(t *testing.T) {
	_, err := internal.ParseOID("1.2.abc")
	if err == nil {
		t.Fatal("expected error for bad component")
	}
}

func TestParseOIDNegative(t *testing.T) {
	_, err := internal.ParseOID("1.-2")
	if err == nil {
		t.Fatal("expected error for negative component")
	}
}

func TestParseOIDOutOfRange(t *testing.T) {
	_, err := internal.ParseOID("1.256")
	if err == nil {
		t.Fatal("expected error for out-of-range component")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	block := pemBlock("CERTIFICATE", []byte{1, 2, 3, 4})
	if !strings.Contains(string(block), "BEGIN CERTIFICATE") {
		t.Fatal("missing PEM header")
	}
	if !strings.Contains(string(block), "END CERTIFICATE") {
		t.Fatal("missing PEM footer")
	}
}

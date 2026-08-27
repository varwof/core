// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

// initRootCA creates a plaintext-key root CA via cmdInitCA and returns the
// cert/key paths (no --password so the parent/reuse flows can LoadPrivateKey).
func initRootCA(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "root.pem")
	keyPath = filepath.Join(dir, "root.key")
	cfg := &internal.Config{
		DB:       filepath.Join(dir, "pki.db"),
		Defaults: internal.DefaultsConfig{KeyType: "ecdsa-p256"},
	}
	err := cmdInitCA(cfg, []string{"--name", "root", "--out-cert", certPath, "--out-key", keyPath})
	if err != nil {
		t.Fatalf("init root CA: %v", err)
	}
	return certPath, keyPath
}

// ---------- cmdInitFull branches ----------

func TestCmdInitFullBranches(t *testing.T) {
	// missing --org
	if err := cmdInitFull(&internal.Config{}, []string{"--domain", "x.com"}); err == nil {
		t.Fatal("expected missing --org error")
	}
	// missing --domain
	if err := cmdInitFull(&internal.Config{}, []string{"--org", "X"}); err == nil {
		t.Fatal("expected missing --domain error")
	}
	// --import-root-cert without --import-root-key
	dir := t.TempDir()
	err := cmdInitFull(&internal.Config{}, []string{
		"--org", "X", "--domain", "x.com", "--out-dir", dir,
		"--import-root-cert", "f.pem",
	})
	if err == nil {
		t.Fatal("expected import-root pair error")
	}
	// invalid admin-names entry (no paren)
	err = cmdInitFull(&internal.Config{}, []string{
		"--org", "X", "--domain", "x.com", "--out-dir", dir, "--admin-names", "bob",
	})
	if err == nil {
		t.Fatal("expected invalid admin-names error")
	}
	// unknown admin role
	err = cmdInitFull(&internal.Config{}, []string{
		"--org", "X", "--domain", "x.com", "--out-dir", dir, "--admin-names", "bob(badrole)",
	})
	if err == nil {
		t.Fatal("expected unknown-role error")
	}
}

func TestCmdInitFullEnterprise(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp", "--domain", "test.varwof.com",
		"--hierarchy", "enterprise",
		"--admin-names", "张三(admin),李四(operator)",
		"--skip-service-certs",
		"--default-key-type", "ecdsa-p256",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
	})
	if err != nil {
		t.Fatalf("cmdInitFull enterprise: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy", "certs", "ca.pem")); err != nil {
		t.Fatal("policy CA not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "pki.json")); err != nil {
		t.Fatal("pki.json not created")
	}

	// Re-run on the same directory: root/policy/subs all exist → skip branches.
	err = cmdInitFull(cfg, []string{
		"--org", "TestCorp", "--domain", "test.varwof.com",
		"--hierarchy", "enterprise",
		"--skip-service-certs",
		"--default-key-type", "ecdsa-p256",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
	})
	if err != nil {
		t.Fatalf("cmdInitFull re-run: %v", err)
	}
}

func TestCmdInitFullImportRoot(t *testing.T) {
	src := t.TempDir()
	certPath, keyPath := initRootCA(t, src)

	// The import path reads the root cert as raw DER, so decode the PEM first.
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("root.pem not a PEM")
	}
	derPath := filepath.Join(src, "root.der")
	if err := os.WriteFile(derPath, block.Bytes, 0644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg := &internal.Config{}
	err = cmdInitFull(cfg, []string{
		"--org", "ImportOrg", "--domain", "import.varwof.com",
		"--import-root-cert", derPath, "--import-root-key", keyPath,
		"--skip-service-certs",
		"--default-key-type", "ecdsa-p256",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
	})
	if err != nil {
		t.Fatalf("cmdInitFull import-root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root", "certs", "ca.pem")); err != nil {
		t.Fatal("imported root cert not copied")
	}
	if _, err := os.Stat(filepath.Join(dir, "management", "certs", "ca.pem")); err != nil {
		t.Fatal("sub CA not created under imported root")
	}
}

// ---------- cmdInitCA branches ----------

func TestCmdInitCABranches(t *testing.T) {
	dir := t.TempDir()
	rootCert, rootKey := initRootCA(t, dir)
	cfg := &internal.Config{
		DB:       filepath.Join(dir, "pki.db"),
		CAs:      map[string]internal.CAConfig{"root": {Cert: rootCert, Key: rootKey}},
		Defaults: internal.DefaultsConfig{KeyType: "ecdsa-p256"},
	}

	// sub-CA under parent root
	childCert := filepath.Join(dir, "child.pem")
	childKey := filepath.Join(dir, "child.key")
	err := cmdInitCA(cfg, []string{"--name", "child", "--profile", "sub-ca",
		"--parent", "root", "--parent-key", rootKey,
		"--out-cert", childCert, "--out-key", childKey, "--password", "pw2"})
	if err != nil {
		t.Fatalf("child CA: %v", err)
	}
	if _, err := os.Stat(childCert); err != nil {
		t.Fatal("child cert not created")
	}

	// parent not found in ca_meta
	err = cmdInitCA(cfg, []string{"--name", "x1", "--parent", "nope", "--parent-key", rootKey})
	if err == nil {
		t.Fatal("expected parent-not-found error")
	}

	// parent key missing (config has no CAs entry to fall back on)
	cfgNoCA := &internal.Config{DB: filepath.Join(dir, "pki.db"), Defaults: internal.DefaultsConfig{KeyType: "ecdsa-p256"}}
	err = cmdInitCA(cfgNoCA, []string{"--name", "x2", "--parent", "root"})
	if err == nil {
		t.Fatal("expected parent-key-missing error")
	}

	// reuse-key: new CA certificate with an existing key (also hits no-out-key warning)
	reuseCert := filepath.Join(dir, "reuse.pem")
	err = cmdInitCA(cfg, []string{"--name", "reuse-ca", "--reuse-key", rootKey, "--out-cert", reuseCert})
	if err != nil {
		t.Fatalf("reuse key: %v", err)
	}
	if _, err := os.Stat(reuseCert); err != nil {
		t.Fatal("reuse cert not created")
	}

	// permitted/excluded lists on a sub-CA (applied via NameConstraints)
	constraintCert := filepath.Join(dir, "constraints.pem")
	constraintKey := filepath.Join(dir, "constraints.key")
	err = cmdInitCA(cfg, []string{"--name", "constraints", "--profile", "sub-ca",
		"--parent", "root", "--parent-key", rootKey,
		"--permitted-dns", "a.com, b.com", "--excluded-dns", "x.com",
		"--permitted-emails", "a@a.com", "--excluded-emails", "b@b.com",
		"--permitted-uris", "spiffe://trust", "--excluded-uris", "spiffe://deny",
		"--permitted-ips", "10.0.0.0/8", "--excluded-ips", "192.168.0.0/16",
		"--out-cert", constraintCert, "--out-key", constraintKey})
	if err != nil {
		t.Fatalf("constraints: %v", err)
	}

	// no-store-key: prints key to stderr, no key file written
	err = cmdInitCA(cfg, []string{"--name", "nostore", "--no-store-key"})
	if err != nil {
		t.Fatalf("no-store-key: %v", err)
	}
}

// ---------- runCmd dispatch ----------

func TestRunCmdDispatchMore(t *testing.T) {
	// backward-compat aliases all resolve and fail fast (exit 1)
	for _, args := range [][]string{
		{"init-ca"},             // missing --name
		{"ca-info"},             // missing --name
		{"ct-submit"},           // missing --url / --cert
		{"cross-cert"},          // unknown subcommand
		{"cross-cert", "issue"}, // missing args
		{"crl-verify"},          // missing --in / --cacert
	} {
		if code := runCmd(args); code != 1 {
			t.Fatalf("runCmd(%v) expected exit 1, got %d", args, code)
		}
	}
	// -h and --help print usage and exit 0
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		if code := runCmd(args); code != 0 {
			t.Fatalf("runCmd(%v) expected exit 0, got %d", args, code)
		}
	}
}

func TestCompletionDispatch(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdCompletion(cfg, nil); err != nil {
		t.Fatalf("usage: %v", err)
	}
	if err := cmdCompletion(cfg, []string{"bash"}); err != nil {
		t.Fatalf("bash: %v", err)
	}
	if err := cmdCompletion(cfg, []string{"zsh"}); err != nil {
		t.Fatalf("zsh: %v", err)
	}
	if err := cmdCompletion(cfg, []string{"fish"}); err != nil {
		t.Fatalf("fish: %v", err)
	}
	if err := cmdCompletion(cfg, []string{"nope"}); err == nil {
		t.Fatal("expected unsupported-shell error")
	}
}

// ---------- startServers: TLS listener + rate limit + metrics ----------

func writeServerTLSFiles(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert = filepath.Join(dir, "tls.pem")
	key = filepath.Join(dir, "tls.key")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	return cert, key
}

func TestStartServersTLSAndOptions(t *testing.T) {
	cfg := buildServeConfig(t)
	tlsCert, tlsKey := writeServerTLSFiles(t, t.TempDir())
	cfg.Serve.TLSAddr = "127.0.0.1:0"
	cfg.Serve.TLSCert = tlsCert
	cfg.Serve.TLSKey = tlsKey
	cfg.Serve.TLSClientCA = cfg.CAs["issuing"].Cert
	cfg.Serve.MetricsEnabled = internal.BoolPtr(true)
	cfg.RateLimit = internal.RateLimitConfig{Enabled: internal.BoolPtr(true), Rate: 100, Burst: 20}

	savedPath := configPath
	configPath = filepath.Join(t.TempDir(), "pki.json")
	defer func() { configPath = savedPath }()

	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err != nil {
		t.Fatalf("startServers: %v", err)
	}
	if httpServer == nil || tlsServer == nil {
		t.Fatal("expected http and tls servers to be created")
	}

	stopCRL()
	stopTSARenewal()
	stopAuditSaltRetirement()
	stopRecordBuffer()
	if httpServer != nil {
		httpServer.Close()
	}
	if tlsServer != nil {
		tlsServer.Close()
	}
	httpServer, tlsServer, fullMux, publicMux = nil, nil, nil, nil
	crlStopFn, tsaStopFn, rbStopFn, currentDB = nil, nil, nil, nil
}

// ---------- reloadConfigNowWithMuxes success path ----------

func TestReloadConfigNowWithMuxesRunning(t *testing.T) {
	cfg := buildServeConfig(t)
	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err != nil {
		t.Fatalf("startServers: %v", err)
	}

	dir := t.TempDir()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	reloadConfigNowWithMuxes(path, fullMux, publicMux)
	if currentDB == nil {
		t.Fatal("expected currentDB to be set after successful reload")
	}

	stopCRL()
	stopTSARenewal()
	stopAuditSaltRetirement()
	stopRecordBuffer()
	stopEngine()
	if httpServer != nil {
		httpServer.Close()
	}
	if tlsServer != nil {
		tlsServer.Close()
	}
	if currentDB != nil {
		currentDB.Close()
	}
	httpServer, tlsServer, fullMux, publicMux = nil, nil, nil, nil
	crlStopFn, tsaStopFn, rbStopFn, currentDB = nil, nil, nil, nil
}

// TestReloadKeepEngineOnSameDB verifies the E04 keep-engine path: reloading
// with an unchanged DB DSN keeps the resident memory engine running (same
// engine pointer, no full rebuild) while a changed DSN forces a rebuild.
func TestReloadKeepEngineOnSameDB(t *testing.T) {
	cfg := buildServeConfig(t)
	cfg.Engine = &internal.EngineConfig{MaxCerts: 10000}

	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err != nil {
		t.Fatalf("startServers: %v", err)
	}
	currentDB = database
	if fullMux == nil || !fullMux.EngineEnabled() {
		stopCRL()
		stopTSARenewal()
		stopAuditSaltRetirement()
		t.Fatal("engine should be enabled after startServers")
	}
	engineBefore := fullMux.Engine()

	dir := t.TempDir()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	reloadConfigNowWithMuxes(path, fullMux, publicMux)
	if !fullMux.EngineEnabled() {
		t.Fatal("engine should remain enabled after same-DB reload")
	}
	if fullMux.Engine() != engineBefore {
		t.Fatal("same-DB reload must keep the resident engine (no full rebuild)")
	}
	if fullMux.Engine().DB().Path() != cfg.DB {
		t.Fatalf("engine write path should point at the new handle's store, got %q",
			fullMux.Engine().DB().Path())
	}

	stopCRL()
	stopTSARenewal()
	stopAuditSaltRetirement()
	stopRecordBuffer()
	stopEngine()
	if httpServer != nil {
		httpServer.Close()
	}
	if tlsServer != nil {
		tlsServer.Close()
	}
	if currentDB != nil {
		currentDB.Close()
	}
	httpServer, tlsServer, fullMux, publicMux = nil, nil, nil, nil
	crlStopFn, tsaStopFn, rbStopFn, currentDB = nil, nil, nil, nil
}

// TestReloadRebuildsEngineOnChangedDB verifies the E04 fallback path: when the
// reload points at a different DB store, the resident engine is stopped and a
// fresh engine is built over the new handle.
func TestReloadRebuildsEngineOnChangedDB(t *testing.T) {
	cfg := buildServeConfig(t)
	cfg.Engine = &internal.EngineConfig{MaxCerts: 10000}

	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err != nil {
		t.Fatalf("startServers: %v", err)
	}
	currentDB = database
	if !fullMux.EngineEnabled() {
		stopCRL()
		stopTSARenewal()
		stopAuditSaltRetirement()
		t.Fatal("engine should be enabled after startServers")
	}

	// Change the DB DSN to a different store; the engine must rebuild.
	cfg2 := *cfg
	cfg2.DB = filepath.Join(t.TempDir(), "other.db")

	dir := t.TempDir()
	data, err := json.Marshal(&cfg2)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	reloadConfigNowWithMuxes(path, fullMux, publicMux)
	if !fullMux.EngineEnabled() {
		t.Fatal("engine should be re-enabled after changed-DB reload")
	}
	if fullMux.Engine().DB().Path() != cfg2.DB {
		t.Fatalf("engine should be rebuilt over the new store, got %q",
			fullMux.Engine().DB().Path())
	}

	stopCRL()
	stopTSARenewal()
	stopAuditSaltRetirement()
	stopRecordBuffer()
	stopEngine()
	if httpServer != nil {
		httpServer.Close()
	}
	if tlsServer != nil {
		tlsServer.Close()
	}
	if currentDB != nil {
		currentDB.Close()
	}
	httpServer, tlsServer, fullMux, publicMux = nil, nil, nil, nil
	crlStopFn, tsaStopFn, rbStopFn, currentDB = nil, nil, nil, nil
}

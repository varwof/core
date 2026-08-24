// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// ---------- runCmd (main dispatch) ----------

func TestRunCmdDispatch(t *testing.T) {
	if code := runCmd(nil); code != 1 {
		t.Fatalf("expected usage exit 1, got %d", code)
	}
	if code := runCmd([]string{"help"}); code != 0 {
		t.Fatalf("help should exit 0, got %d", code)
	}
	if code := runCmd([]string{"version"}); code != 0 {
		t.Fatalf("version should exit 0, got %d", code)
	}
	// verbose flag + two-level command with a failing command → cmd_failed branch
	if code := runCmd([]string{"-v", "ca", "info"}); code != 1 {
		t.Fatalf("ca info without name should exit 1, got %d", code)
	}
	// unknown command
	if code := runCmd([]string{"frobnicate"}); code != 1 {
		t.Fatalf("unknown command should exit 1, got %d", code)
	}
	// sub consumed as two-level arg that doesn't resolve
	if code := runCmd([]string{"ca", "bogus-sub"}); code != 1 {
		t.Fatalf("bad sub should exit 1, got %d", code)
	}
	// error from a real command → cmd_failed branch
	if code := runCmd([]string{"crl", "--ca", "nope"}); code != 1 {
		t.Fatalf("crl with unknown ca should exit 1, got %d", code)
	}
}

func TestRunCmdWithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runCmd([]string{"--config", cfgPath, "version"}); code != 0 {
		t.Fatalf("--config version should exit 0, got %d", code)
	}
	if code := runCmd([]string{"--config=" + cfgPath, "version"}); code != 0 {
		t.Fatalf("--config= version should exit 0, got %d", code)
	}
	// bad config file → warn but continue
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{invalid"), 0600)
	if code := runCmd([]string{"--config", bad, "version"}); code != 0 {
		t.Fatalf("bad config version should exit 0, got %d", code)
	}
	// empty config file discovery
	os.WriteFile(cfgPath, []byte("{}\n"), 0600)
	if code := runCmd([]string{"version", "--config", cfgPath}); code != 0 {
		t.Fatalf("trailing --config should exit 0, got %d", code)
	}
}

// ---------- cmdServe ----------

func TestCmdServeErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}
	// no TSA signer configured → startServers fails fast
	if err := cmdServe(cfg, nil); err == nil {
		t.Fatal("expected serve error without TSA/OCSP signers")
	}
}

// ---------- startServers ----------

func buildServeConfig(t *testing.T) *internal.Config {
	t.Helper()
	dir := t.TempDir()

	issuingCert, issuingKey, _ := makePolicySigningCert(t, "admin")
	tsaCert, tsaKey, _ := makePolicySigningCert(t, "admin")
	ocspCert, ocspKey, _ := makePolicySigningCert(t, "admin")

	writePEM := func(name string, der []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
		return p
	}
	issuingCertPath := writePEM("issuing.pem", issuingCert.Raw)
	tsaCertPath := writePEM("tsa.pem", tsaCert.Raw)
	ocspCertPath := writePEM("ocsp.pem", ocspCert.Raw)
	issuingKeyPath := filepath.Join(dir, "issuing.key")
	tsaKeyPath := filepath.Join(dir, "tsa.key")
	ocspKeyPath := filepath.Join(dir, "ocsp.key")
	issuingKeyPEM, _ := ca.KeyToPEM(issuingKey)
	tsaKeyPEM, _ := ca.KeyToPEM(tsaKey)
	ocspKeyPEM, _ := ca.KeyToPEM(ocspKey)
	os.WriteFile(issuingKeyPath, issuingKeyPEM, 0600)
	os.WriteFile(tsaKeyPath, tsaKeyPEM, 0600)
	os.WriteFile(ocspKeyPath, ocspKeyPEM, 0600)

	return &internal.Config{
		DB: filepath.Join(dir, "pki.db"),
		Defaults: internal.DefaultsConfig{
			CA:      "issuing",
			KeyType: "ecdsa-p256",
		},
		CAs: map[string]internal.CAConfig{
			"issuing": {Cert: issuingCertPath, Key: issuingKeyPath},
		},
		TSA: internal.TSAConfig{
			SignerCert: tsaCertPath,
			SignerKey:  tsaKeyPath,
		},
		OCSP: internal.OCSPConfig{
			SignerCert: ocspCertPath,
			SignerKey:  ocspKeyPath,
		},
		Serve: internal.ServeConfig{Addr: "127.0.0.1:0"},
	}
}

func TestStartServersSuccess(t *testing.T) {
	cfg := buildServeConfig(t)

	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err != nil {
		t.Fatalf("startServers: %v", err)
	}

	// servers should be running on the global muxes
	if fullMux == nil || publicMux == nil {
		t.Fatal("expected fullMux/publicMux to be created")
	}
	if httpServer == nil {
		t.Fatal("expected httpServer to be created")
	}

	// tear down background loops + server
	stopCRL()
	stopTSARenewal()
	stopAuditSaltRetirement()
	stopRecordBuffer() // closes the WAL file; must run before TempDir cleanup
	if httpServer != nil {
		httpServer.Close()
	}
	if tlsServer != nil {
		tlsServer.Close()
	}

	// reset globals
	httpServer = nil
	tlsServer = nil
	fullMux = nil
	publicMux = nil
	crlStopFn = nil
	tsaStopFn = nil
	rbStopFn = nil
	currentDB = nil
}

func TestStartServersMissingOCSP(t *testing.T) {
	cfg := buildServeConfig(t)
	cfg.OCSP.SignerCert = ""
	cfg.OCSP.SignerKey = ""

	database, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := startServers(cfg, database); err == nil {
		t.Fatal("expected error without OCSP signer")
	}
}

// ---------- reloadConfigNowWithMuxes ----------

func TestReloadConfigNowWithMuxesErrors(t *testing.T) {
	// empty path → warn only
	reloadConfigNowWithMuxes("", nil, nil)

	dir := t.TempDir()
	// bad JSON config path → error logged, no panic
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{invalid"), 0600)
	reloadConfigNowWithMuxes(bad, nil, nil)

	// valid JSON but no TSA/OCSP signers → loadTSAConfig fails, returns early (muxes nil, no panic)
	good := filepath.Join(dir, "pki.json")
	os.WriteFile(good, []byte("{}\n"), 0600)
	reloadConfigNowWithMuxes(good, nil, nil)
}

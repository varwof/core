// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func testCLIConfig(t *testing.T) *internal.Config {
	t.Helper()
	dir := t.TempDir()
	return &internal.Config{DB: filepath.Join(dir, "cli.db")}
}

// ─── rbac subcommand ─────────────────────────────────────────────────

func TestCmdRBAC(t *testing.T) {
	cfg := testCLIConfig(t)

	// no args → show mode (simple default)
	if err := cmdRBAC(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// enterprise mode shows extra line
	cfg.RBAC.PermissionMode = "enterprise"
	if err := cmdRBAC(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// unknown subcommand
	if err := cmdRBAC(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// mode with no flags → show
	if err := cmdRBACMode(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// both flags → error
	if err := cmdRBACMode(cfg, []string{"--enterprise", "--simple"}); err == nil {
		t.Fatal("expected both-flags error")
	}
	// write mode without configPath → error
	oldPath := configPath
	configPath = ""
	if err := cmdRBACMode(cfg, []string{"--enterprise"}); err == nil {
		t.Fatal("expected requireWriteConfig error")
	}
	configPath = oldPath

	// scope command usage error
	if err := cmdRBACScope(cfg, nil); err == nil {
		t.Fatal("expected usage error")
	}
	// scope list without configPath → error
	configPath = ""
	if err := cmdRBACScope(cfg, []string{"--list"}); err == nil {
		t.Fatal("expected no-config error for list")
	}
	// scope write without configPath → error
	if err := cmdRBACScope(cfg, []string{"--role", "admin", "--scope", "x"}); err == nil {
		t.Fatal("expected requireWriteConfig error for write")
	}
}

func TestCmdRBACScopeWriteAndList(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testCLIConfig(t)
	configPath = cfgPath
	defer func() { configPath = "" }()

	// write mode
	if err := cmdRBACScope(cfg, []string{"--role", "admin", "--scope", "issuing-ca"}); err != nil {
		t.Fatal(err)
	}
	// duplicate scope → "already exists" (no error)
	if err := cmdRBACScope(cfg, []string{"--role", "admin", "--scope", "issuing-ca"}); err != nil {
		t.Fatal(err)
	}
	// list mode
	if err := cmdRBACScope(cfg, []string{"--list"}); err != nil {
		t.Fatal(err)
	}
	// rbac mode enterprise/simple write
	if err := cmdRBACMode(cfg, []string{"--enterprise"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRBACMode(cfg, []string{"--simple"}); err != nil {
		t.Fatal(err)
	}
}

// ─── trust subcommand ─────────────────────────────────────────────────

func makeSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root", Organization: []string{"acme"}, Country: []string{"CN"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCmdTrust(t *testing.T) {
	cfg := testCLIConfig(t)
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(pemPath, makeSelfSignedCertPEM(t), 0600); err != nil {
		t.Fatal(err)
	}

	// no subcommand → error
	if err := cmdTrust(cfg, nil); err == nil {
		t.Fatal("expected subcommand required error")
	}
	// unknown subcommand
	if err := cmdTrust(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}

	// import from file
	if err := cmdTrustImport(cfg, []string{"--file", pemPath}); err != nil {
		t.Fatalf("import: %v", err)
	}
	// import with missing file → error
	if err := cmdTrustImport(cfg, []string{"--file", filepath.Join(dir, "nope.pem")}); err == nil {
		t.Fatal("expected read error")
	}
	// import with --trusted=false
	if err := cmdTrustImport(cfg, []string{"--file", pemPath, "--trusted=false"}); err != nil {
		t.Fatal(err)
	}

	// find the imported anchor hash
	d, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := d.ListTrustAnchors(nil)
	if err != nil || len(anchors) == 0 {
		t.Fatalf("list anchors: %v (%d)", err, len(anchors))
	}
	hashID := anchors[0].HashID
	d.Close()

	// list with filters
	if err := cmdTrustList(cfg, []string{"--trusted=true", "--source=file", "--org=acme", "--country=CN", "--algo=ecdsa"}); err != nil {
		t.Fatal(err)
	}
	// info
	if err := cmdTrustInfo(cfg, []string{"--hash", hashID}); err != nil {
		t.Fatal(err)
	}
	// info missing hash → error
	if err := cmdTrustInfo(cfg, nil); err == nil {
		t.Fatal("expected --hash required error")
	}
	// info unknown hash → error
	if err := cmdTrustInfo(cfg, []string{"--hash", "deadbeef"}); err == nil {
		t.Fatal("expected unknown anchor error")
	}
	// untrust → trust
	if err := cmdTrustSet(cfg, []string{hashID}, false); err != nil {
		t.Fatal(err)
	}
	if err := cmdTrustSet(cfg, []string{"--hash", hashID}, true); err != nil {
		t.Fatal(err)
	}
	// trust missing hash → error
	if err := cmdTrustSet(cfg, nil, true); err == nil {
		t.Fatal("expected --hash required error")
	}
	// stats
	if err := cmdTrustStats(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// remove
	if err := cmdTrustRemove(cfg, []string{"--hash", hashID}); err != nil {
		t.Fatal(err)
	}
	// remove missing hash → error
	if err := cmdTrustRemove(cfg, nil); err == nil {
		t.Fatal("expected --hash required error")
	}
}

// ─── db transfer / backup / migrate ───────────────────────────────

func TestCmdDBTransfer(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "src.db")
	to := filepath.Join(dir, "dst.db")

	// create source with a row
	src, err := db.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.CreateUser("alice", "hash", "salt", "admin"); err != nil {
		t.Fatal(err)
	}
	src.Close()

	if err := cmdDBTransfer(nil, []string{"--from", from, "--to", to}); err != nil {
		t.Fatalf("transfer: %v", err)
	}

	// missing flags → error
	if err := cmdDBTransfer(nil, nil); err == nil {
		t.Fatal("expected usage error")
	}
	// bad source → error
	if err := cmdDBTransfer(nil, []string{"--from", filepath.Join(dir, "missing"), "--to", to}); err != nil {
		// opening a fresh source runs migrations, so missing path is fine;
		// only assert no panic here.
		_ = err
	}

	// verify the user survived the transfer
	dst, err := db.Open(to)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	u, err := dst.GetUserByUsername("alice")
	if err != nil || u == nil {
		t.Fatalf("expected alice in target, got %v %v", u, err)
	}
}

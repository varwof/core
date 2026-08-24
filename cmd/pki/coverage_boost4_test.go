package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func TestCmdAutoRenew(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	// empty DB → no results, no error
	if err := autoRenewOnce(cfg, nil); err != nil {
		t.Fatalf("autoRenewOnce empty: %v", err)
	}

	// issue a cert and renew it via renewCert
	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "renew-me.example.com")
	newSerial, err := renewCert(d, cfg, "rev-ca", serial, 30)
	if err != nil {
		t.Fatalf("renewCert: %v", err)
	}
	if newSerial == "" {
		t.Fatal("expected new serial")
	}
	// renewCert on nonexistent cert → error
	if _, err := renewCert(d, cfg, "rev-ca", "00DEAD", 30); err == nil {
		t.Fatal("expected get cert error")
	}
	// renewCert on unconfigured CA → error
	if _, err := renewCert(d, cfg, "ghost-ca", serial, 30); err == nil {
		t.Fatal("expected unconfigured CA error")
	}
	// notifyEvent no-op path
	notifyEvent(cfg, d, "cert_issued", "rev-ca", newSerial, "renew-me.example.com", "test")
}

func TestCmdNotify(t *testing.T) {
	cfg := &internal.Config{}

	// help / no args
	if err := cmdNotify(cfg, nil); err != nil {
		t.Fatal(err)
	}
	// unknown subcommand
	if err := cmdNotify(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// smtp not configured
	if err := cmdNotifyTestSMTP(cfg, []string{}); err == nil {
		t.Fatal("expected smtp not configured error")
	}
	// smtp host but no recipients
	cfg2 := &internal.Config{SMTP: internal.SMTPConfig{Host: "localhost:25"}}
	if err := cmdNotifyTestSMTP(cfg2, []string{}); err == nil {
		t.Fatal("expected no recipients error")
	}
}

func TestIsNotified(t *testing.T) {
	if isNotified("uniq/1") {
		t.Fatal("first check should not be notified")
	}
	if !isNotified("uniq/1") {
		t.Fatal("second check should be notified")
	}
}

func TestCheckExpiry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// expiring CA meta (within 7-day threshold)
	if err := d.InsertCAMeta(&db.CAMeta{
		Name:         "exp-ca",
		CertDER:      []byte{1, 2, 3},
		NotBefore:    time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(3 * 24 * time.Hour),
		KeyAlgorithm: "ecdsa-p256",
	}); err != nil {
		t.Fatal(err)
	}
	// expiring cert under that CA
	insertCertRecord(t, d, "EE1", "expire-host.example.com", "V", time.Now().Add(5*24*time.Hour))
	// non-expiring cert (skipped)
	insertCertRecord(t, d, "EE2", "safe-host.example.com", "V", time.Now().Add(365*24*time.Hour))
	// revoked cert (skipped)
	insertCertRecord(t, d, "EE3", "revoked-host.example.com", "R", time.Now().Add(5*24*time.Hour))

	cfg := &internal.Config{
		DB:      dbPath,
		Webhook: internal.WebhookConfig{URL: srv.URL},
	}
	checkExpiry(cfg, d)
	if hits == 0 {
		t.Fatal("expected webhook POST(s) from expiry notifications")
	}

	// no thresholds configured → default 30/7/1
	checkExpiry(cfg, d)
	// error-free path when CA meta not found (unknown list already covered)
	cfg2 := &internal.Config{DB: dbPath}
	checkExpiry(cfg2, d)
}

func TestCmdColdBackup(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCACertKey(t, dir, "root")
	outPath := filepath.Join(dir, "backup.json")

	// unknown subcommand
	if err := cmdCAColdBackup(&internal.Config{}, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// empty subcommand → usage
	if err := cmdCAColdBackup(&internal.Config{}, nil); err == nil {
		t.Fatal("expected usage error")
	}

	fsBackup := func(args ...string) error {
		return caColdBackupCreate(flag.NewFlagSet("backup", flag.ExitOnError), args)
	}
	fsVerify := func(args ...string) error {
		return caColdBackupVerify(flag.NewFlagSet("verify", flag.ExitOnError), args)
	}

	// backup
	if err := fsBackup("--ca-name", "root", "--ca-cert", certPath, "--ca-key", keyPath, "--password", "secret", "--out", outPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	// verify (correct password)
	if err := fsVerify("--in", outPath, "--password", "secret"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// verify missing --in
	if err := fsVerify(); err == nil {
		t.Fatal("expected --in required error")
	}
	// verify wrong password
	if err := fsVerify("--in", outPath, "--password", "wrong"); err == nil {
		t.Fatal("expected wrong password error")
	}
	// backup with --shred
	if err := fsBackup("--ca-name", "root", "--ca-cert", certPath, "--ca-key", keyPath, "--password", "secret2", "--out", outPath, "--shred"); err != nil {
		t.Fatalf("backup+shred: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("expected key to be shredded")
	}
	// --shred without --ca-key → error
	if err := fsBackup("--ca-name", "root", "--ca-cert", certPath, "--password", "secret3", "--out", outPath, "--shred"); err == nil {
		t.Fatal("expected --shred requires --ca-key error")
	}
	// missing password → resolveBackupPassword falls through to readPassword (stdin not a tty → error in CI)
	if err := fsBackup("--ca-name", "root", "--ca-cert", certPath, "--ca-key", keyPath, "--out", outPath); err == nil {
		t.Fatal("expected password resolution error (no tty)")
	}
}

func TestResolveBackupPassword(t *testing.T) {
	// explicit password
	if got, err := resolveBackupPassword("abc", ""); err != nil || got != "abc" {
		t.Fatalf("explicit: got %q err %v", got, err)
	}
	// password file
	dir := t.TempDir()
	pf := filepath.Join(dir, "pwd.txt")
	if err := os.WriteFile(pf, []byte("  fromfile  \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveBackupPassword("", pf); err != nil || got != "fromfile" {
		t.Fatalf("password file: got %q err %v", got, err)
	}
	// missing password file
	if _, err := resolveBackupPassword("", filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected read error")
	}
	// env var
	t.Setenv("PKI_BACKUP_PASSWORD", "envpwd")
	if got, err := resolveBackupPassword("", ""); err != nil || got != "envpwd" {
		t.Fatalf("env: got %q err %v", got, err)
	}
}

func TestCmdTrustBridge(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}

	// no args
	if err := cmdTrustBridge(cfg, nil); err == nil {
		t.Fatal("expected usage error")
	}
	// unknown subcommand
	if err := cmdTrustBridge(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// list (empty)
	if err := cmdTrustBridge(cfg, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	// issue with missing args
	if err := cmdTrustBridge(cfg, []string{"issue", "only-issuer"}); err == nil {
		t.Fatal("expected usage error")
	}
	// issue with configured CA (BridgeTrustPEMs swallows load errors → empty result)
	cfg.CAs = map[string]internal.CAConfig{
		"issuer-ca": {Cert: filepath.Join(dir, "nope.pem"), Key: filepath.Join(dir, "nope.key")},
	}
	if err := cmdTrustBridge(cfg, []string{"issue", "issuer-ca", "subject-ca", "30"}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// federate with missing url
	if err := cmdTrustBridge(cfg, []string{"federate"}); err == nil {
		t.Fatal("expected usage error")
	}
	// federate with unreachable URL
	if err := cmdTrustBridge(cfg, []string{"federate", "http://127.0.0.1:1/anchors.pem"}); err == nil {
		t.Fatal("expected federation error")
	}
}

func TestPrintJSON(t *testing.T) {
	if err := printJSON(map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	var v interface{} = make(chan int)
	if err := printJSON(v); err == nil {
		t.Fatal("expected marshal error")
	}
	_ = json.Valid([]byte("{}"))
}

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/tsa"
)

func TestServeWaitSignal(t *testing.T) {
	var reloads atomic.Int32
	oldFn := reloadFn
	setReloadHandler(func() { reloads.Add(1) })
	defer setReloadHandler(oldFn)

	srv := &http.Server{}
	sigCh := make(chan os.Signal, 2)
	sigCh <- syscall.SIGHUP
	sigCh <- syscall.SIGTERM
	done := make(chan error, 1)
	go func() { done <- serveWaitSignal(srv, nil, sigCh) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveWaitSignal did not return after SIGTERM")
	}
	if reloads.Load() != 1 {
		t.Fatalf("expected 1 reload on SIGHUP, got %d", reloads.Load())
	}
}

func TestReloadConfigAndRecordBuffer(t *testing.T) {
	// reloadFn nil → warn path (no panic)
	reloadConfig()

	var called atomic.Bool
	oldFn := reloadFn
	setReloadHandler(func() { called.Store(true) })
	reloadConfig()
	setReloadHandler(oldFn)
	if !called.Load() {
		t.Fatal("expected reload handler to fire")
	}

	// stopRecordBuffer nil fn → no-op
	rbStopFn = nil
	stopRecordBuffer()
	// stopRecordBuffer with fn
	var rbCalled atomic.Bool
	rbStopFn = func() { rbCalled.Store(true) }
	stopRecordBuffer()
	if !rbCalled.Load() {
		t.Fatal("expected rbStopFn to fire")
	}
	if rbStopFn != nil {
		t.Fatal("expected rbStopFn to be cleared")
	}
}

func TestShutdownTimeoutAndServeCommon(t *testing.T) {
	old := shutdownTimeout
	defer func() { shutdownTimeout = old }()
	// invalid duration → keeps default
	setShutdownTimeout(&internal.Config{Serve: internal.ServeConfig{ShutdownTimeout: "bogus"}})
	// valid duration
	setShutdownTimeout(&internal.Config{Serve: internal.ServeConfig{ShutdownTimeout: "5s"}})
	if shutdownTimeout != 5*time.Second {
		t.Fatalf("expected 5s, got %v", shutdownTimeout)
	}
	// nil cfg → no change
	setShutdownTimeout(nil)
}

func TestInitRemoteSigner(t *testing.T) {
	orig := ca.RemoteSignerConfig()
	defer ca.SetRemoteSignerConfig(orig)

	// not remote_hsm → no-op
	if err := initRemoteSigner(&internal.Config{}); err != nil {
		t.Fatal(err)
	}
	if ca.RemoteSignerConfig() != nil {
		t.Fatal("expected no remote signer for software backend")
	}
	// remote_hsm with URL → configures global
	if err := initRemoteSigner(&internal.Config{KeyBackend: internal.KeyBackendConfig{
		Type: "remote_hsm", URL: "https://signer:9443",
	}}); err != nil {
		t.Fatal(err)
	}
	if ca.RemoteSignerConfig() == nil {
		t.Fatal("expected remote signer configured")
	}
}

func TestAuditSaltRetirementLifecycle(t *testing.T) {
	d := newTestDB(t)
	defer d.Close()

	// disabled → no goroutine
	disabled := &internal.Config{Serve: internal.ServeConfig{
		AuditSalt: internal.AuditSaltConfig{Enabled: boolPtr(false)},
	}}
	startAuditSaltRetirement(d, disabled)
	if auditSaltStopFn != nil {
		t.Fatal("expected no goroutine when disabled")
	}
	stopAuditSaltRetirement()

	// enabled → start + stop
	enabled := &internal.Config{Serve: internal.ServeConfig{
		AuditSalt: internal.AuditSaltConfig{Enabled: boolPtr(true), CleanupInterval: "24h", RetentionDays: 365},
	}}
	startAuditSaltRetirement(d, enabled)
	if auditSaltStopFn == nil {
		t.Fatal("expected audit salt goroutine started")
	}
	stopAuditSaltRetirement()
	if auditSaltStopFn != nil {
		t.Fatal("expected stop to clear fn")
	}
}

func TestTSARenewalLifecycle(t *testing.T) {
	// nil rc / empty CoreURL → no-op
	startTSARenewal(&internal.Config{}, nil)
	if tsaStopFn != nil {
		t.Fatal("expected no goroutine for nil rc")
	}
	startTSARenewal(&internal.Config{TSA: internal.TSAConfig{CoreURL: "http://x"}}, nil)
	if tsaStopFn != nil {
		t.Fatal("expected no goroutine for nil rc with url")
	}
	// rc set + CoreURL empty → no-op
	rc := tsa.NewRuntimeConfig(&tsa.TSAConfig{})
	startTSARenewal(&internal.Config{TSA: internal.TSAConfig{}}, rc)
	if tsaStopFn != nil {
		t.Fatal("expected no goroutine for empty core url")
	}
	// rc set + CoreURL set → goroutine started, then stopped
	startTSARenewal(&internal.Config{TSA: internal.TSAConfig{CoreURL: "http://127.0.0.1:1", CheckInterval: "1h"}}, rc)
	if tsaStopFn == nil {
		t.Fatal("expected TSA renewal goroutine started")
	}
	stopTSARenewal()
	if tsaStopFn != nil {
		t.Fatal("expected stop to clear fn")
	}
}

func TestCrlLoop(t *testing.T) {
	dir := t.TempDir()
	d, cfg, _, _ := setupTestCA(t, dir)
	defer d.Close()

	outDir := filepath.Join(dir, "crl")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.CRL.OutputDir = outDir
	cfg.CRL.Partitions = 2
	cfg.CRL.ValidityDays = 30

	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time, 1)
	tick <- time.Now()
	done := make(chan struct{})
	go func() {
		crlLoop(ctx, d, nil, cfg, tick)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("crlLoop did not exit after cancel")
	}

	var entries []os.DirEntry
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err = os.ReadDir(outDir)
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatalf("expected CRL files written, got %d entries (%v)", len(entries), err)
	}
}

func TestCmdArchive(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := &internal.Config{DB: dbPath}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// list mode (empty)
	if err := cmdArchive(cfg, []string{"--list"}); err != nil {
		t.Fatal(err)
	}
	// list with CA filter (empty)
	if err := cmdArchive(cfg, []string{"--list", "--ca", "some-ca"}); err != nil {
		t.Fatal(err)
	}
	// archive run (empty DB)
	if err := cmdArchive(cfg, []string{"--retention", "30"}); err != nil {
		t.Fatal(err)
	}
	// archive revoked + expired
	if err := cmdArchive(cfg, []string{"--revoked", "--expired=false"}); err != nil {
		t.Fatal(err)
	}
}

func TestExecBinaryError(t *testing.T) {
	if err := execBinary("/nonexistent/pki-binary", nil); err == nil {
		t.Fatal("expected exec error")
	}
}

func boolPtr(b bool) *bool { return &b }

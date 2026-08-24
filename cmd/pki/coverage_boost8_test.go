// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varwof/core/internal"
)

func TestPollConfigTickerWithReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var reloads atomic.Int32
	tick := make(chan time.Time, 3)
	done := make(chan struct{})
	go func() {
		pollConfigTickerWithReload(cfgPath, tick, func(string) { reloads.Add(1) })
		close(done)
	}()

	// first tick just records mtime
	tick <- time.Now()
	time.Sleep(50 * time.Millisecond)
	if reloads.Load() != 0 {
		t.Fatal("first tick must not reload")
	}

	// bump mtime then tick → reload fires
	future := time.Now().Add(5 * time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatal(err)
	}
	tick <- time.Now()
	time.Sleep(100 * time.Millisecond)
	if reloads.Load() != 1 {
		t.Fatalf("expected 1 reload, got %d", reloads.Load())
	}

	// unchanged mtime → no reload
	tick <- time.Now()
	time.Sleep(100 * time.Millisecond)
	if reloads.Load() != 1 {
		t.Fatalf("expected still 1 reload, got %d", reloads.Load())
	}

	// missing file → no panic, loop continues
	time.Sleep(10 * time.Millisecond)
	tick <- time.Now()
	time.Sleep(50 * time.Millisecond)
}

func TestServeCmdDispatch(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := &internal.Config{DB: dbPath}

	// unknown subcommand
	if err := serveCmd(cfg, []string{"bogus"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	// tsa subcommand with no signer cert → loadTSAConfig fails before serving
	if err := serveCmd(cfg, []string{"tsa"}); err == nil {
		t.Fatal("expected TSA config error")
	}
	// ocsp subcommand with no signer cert → loadOCSPConfig fails before serving
	if err := serveCmd(cfg, []string{"ocsp"}); err == nil {
		t.Fatal("expected OCSP config error")
	}
}

func TestReloadConfigNowEmptyPath(t *testing.T) {
	reloadConfigNowWithMuxes("", nil, nil)
}

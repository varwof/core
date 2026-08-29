// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
)

func TestCmdDBAndKeyDispatchGuards(t *testing.T) {
	cfg := &internal.Config{}
	if err := cmdDB(cfg, nil); err == nil {
		t.Fatal("db without subcommand must error")
	}
	if err := cmdDB(cfg, []string{"bogus"}); err == nil {
		t.Fatal("unknown db subcommand must error")
	}
	if err := cmdKey(cfg, nil); err == nil {
		t.Fatal("key without subcommand must error")
	}
	if err := cmdKey(cfg, []string{"bogus"}); err == nil {
		t.Fatal("unknown key subcommand must error")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := writeFileAtomic(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("atomic write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "{}" {
		t.Fatalf("atomically written content: %q (err=%v)", data, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm: %v (%v)", fi, err)
	}

	if err := writeFileAtomic(filepath.Join(dir, "nope", "x.json"), []byte("{}"), 0o600); err == nil {
		t.Fatal("write into missing dir must error")
	}
}

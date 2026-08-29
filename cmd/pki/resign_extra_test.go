// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
)

func TestCmdReSignBranches(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults = internal.DefaultsConfig{CA: "", Hash: "sha256", DefaultOrg: "ACME", DefaultCountry: "US"}

	if err := cmdReSign(cfg, nil); err == nil {
		t.Fatal("missing ca/serial must error")
	}
	if err := cmdReSign(cfg, []string{"--ca", "rev-ca"}); err == nil {
		t.Fatal("missing serial must error")
	}
	if err := cmdReSign(cfg, []string{"--ca", "rev-ca", "--serial", "1", "--target-ca", "nope"}); err == nil {
		t.Fatal("unknown target CA must error")
	}
	if err := cmdReSign(cfg, []string{"--ca", "rev-ca", "--serial", "999", "--target-ca", "rev-ca"}); err == nil {
		t.Fatal("missing cert serial must error")
	}

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "resign.example.com")

	out := filepath.Join(dir, "resigned.pem")
	if err := cmdReSign(cfg, []string{"--ca", "rev-ca", "--serial", serial, "--target-ca", "rev-ca", "--out", out, "--validity", "400"}); err != nil {
		t.Fatalf("re-sign with output: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("re-signed cert not written: %v", err)
	}
	if err := cmdReSign(cfg, []string{"--ca", "rev-ca", "--serial", serial, "--target-ca", "rev-ca"}); err != nil {
		t.Fatalf("re-sign without output: %v", err)
	}
}

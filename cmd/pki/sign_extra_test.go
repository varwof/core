// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
)

func TestCLISignBranches(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	filePath := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(filePath, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &internal.Config{}
	cfg.Defaults.Hash = "sha256"

	if err := cmdSign(cfg, nil); err == nil {
		t.Fatal("missing file arg must error")
	}

	if err := cmdSign(cfg, []string{"--ca", "nope", filePath}); err == nil {
		t.Fatal("unknown CA must error")
	}

	if err := cmdSign(cfg, []string{"--cert", certPath, "--key", keyPath, filePath}); err != nil {
		t.Fatalf("detached sign: %v", err)
	}

	sigFile := filePath + ".p7s"
	if _, err := os.Stat(sigFile); err != nil {
		t.Fatalf("p7s not written: %v", err)
	}
	if err := cmdSign(cfg, []string{"--verify", "--sig", sigFile, filePath}); err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if err := cmdSign(cfg, []string{"--verify", "--sig", filepath.Join(dir, "missing.p7s"), filePath}); err == nil {
		t.Fatal("verify missing sig must error")
	}

	embedded := filepath.Join(dir, "embedded.bin")
	if err := os.WriteFile(embedded, []byte("embedded data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cfg, []string{"--embed", "--cert", certPath, "--key", keyPath, embedded}); err != nil {
		t.Fatalf("embedded sign: %v", err)
	}
	if err := cmdSign(cfg, []string{"--verify", "--embed", embedded}); err != nil {
		t.Fatalf("verify embedded: %v", err)
	}

	if err := cmdSign(cfg, []string{"--cert", certPath, "--key", filepath.Join(dir, "missing.key"), filePath}); err == nil {
		t.Fatal("missing key must error")
	}
	badSig := filepath.Join(dir, "bad.p7s")
	os.WriteFile(badSig, []byte("nope"), 0o600)
	if err := cmdSign(cfg, []string{"--verify", "--sig", badSig, filePath}); err == nil {
		t.Fatal("bad sig content must error")
	}
}

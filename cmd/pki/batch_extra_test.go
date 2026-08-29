// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"github.com/varwof/core/internal"
	"os"
	"path/filepath"
	"testing"
)

func TestCmdBatchBranches(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults = internal.DefaultsConfig{Profile: "tls-server", KeyType: "ecdsa-p256", Hash: "sha256", DefaultOrg: "ACME", DefaultCountry: "US"}

	noCSV := cmdBatch(cfg, nil)
	if noCSV == nil {
		t.Fatal("missing --csv must error")
	}

	badCACfg := *cfg
	badCACfg.CAs = map[string]internal.CAConfig{}
	if err := cmdBatch(&badCACfg, []string{"--csv", "x.csv", "--ca", "rev-ca"}); err == nil {
		t.Fatal("unknown CA must error")
	}

	missingCol := filepath.Join(dir, "no-col.csv")
	os.WriteFile(missingCol, []byte("name\nbob\n"), 0o644)
	if err := cmdBatch(cfg, []string{"--csv", missingCol}); err == nil {
		t.Fatal("csv without cn column must error")
	}

	skipRow := filepath.Join(dir, "skip.csv")
	os.WriteFile(skipRow, []byte("cn,san\n\n  \nbob,\n"), 0o644)
	if err := cmdBatch(cfg, []string{"--csv", skipRow}); err == nil {
		t.Fatal("batch with skipped rows must report error")
	}

	_ = d
	_ = caCert
	_ = caKey
}

func TestCmdBatchSuccess(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)
	cfg.Defaults = internal.DefaultsConfig{Profile: "tls-server", KeyType: "ecdsa-p256", Hash: "sha256", DefaultOrg: "ACME", DefaultCountry: "US"}
	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0o755)

	csvPath := filepath.Join(dir, "batch.csv")
	csvContent := "cn,san,profile,key-type,validity,must-staple,eku-oid\nbatch-one.example.com,DNS:www.example.com,tls-server,ecdsa-p256,365,no,1.2.3.4\n"
	os.WriteFile(csvPath, []byte(csvContent), 0o644)

	if err := cmdBatch(cfg, []string{"--csv", csvPath, "--ca", "rev-ca", "--out-dir", outDir}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "batch-one.example.com.pem")); err != nil {
		t.Fatal("batch cert not written")
	}
	if _, err := os.Stat(filepath.Join(outDir, "batch-one.example.com.key")); err != nil {
		t.Fatal("batch key not written")
	}
}

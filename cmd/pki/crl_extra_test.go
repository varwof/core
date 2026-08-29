// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
)

func TestCmdCRLDeltaAndArgBranches(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "delta.example.com")
	if err := d.RevokeCert("rev-ca", serial, 1); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"unexpected-positional", []string{"--ca", "rev-ca", "--out", filepath.Join(dir, "u.crl"), "oops"}},
		{"missing-ca", []string{"--out", filepath.Join(dir, "m.crl")}},
		{"ca-not-configured", []string{"--ca", "ghost-ca", "--out", filepath.Join(dir, "n.crl")}},
		{"delta-no-since", []string{"--ca", "rev-ca", "--delta", "--out", filepath.Join(dir, "d1.crl")}},
		{"delta-bad-since", []string{"--ca", "rev-ca", "--delta", "--since", "nope", "--out", filepath.Join(dir, "d2.crl")}},
	}
	for _, tc := range cases {
		if err := cmdCRL(cfg, tc.args); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}

	partitions := filepath.Join(dir, "part.crl")
	if err := cmdCRL(cfg, []string{"--ca", "rev-ca", "--out", partitions, "--partition", "0", "--total", "2"}); err != nil {
		t.Fatalf("partitioned crl: %v", err)
	}
	if _, err := os.Stat(partitions); err != nil {
		t.Fatal("partitioned CRL not written")
	}

	outDir := filepath.Join(dir, "outdir")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgCRL := &internal.CRLConfig{OutputDir: outDir}
	cfg.CRL = *cfgCRL
	if err := cmdCRL(cfg, []string{"--ca", "rev-ca"}); err != nil {
		t.Fatalf("default out dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "rev-ca.crl")); err != nil {
		t.Fatal("default-path CRL not written under output dir")
	}
}

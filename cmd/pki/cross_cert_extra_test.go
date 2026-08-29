// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCmdCrossCertIssue(t *testing.T) {
	dir := t.TempDir()
	d, cfg, _, _ := setupTestCA(t, dir)

	targetCertPath, _ := writeCACertKey(t, dir, "target-ca")
	registerCACert(d, "target-ca", targetCertPath)

	if err := cmdCrossCertIssue(cfg, nil); err == nil {
		t.Fatal("no args must error (usage)")
	}
	if err := cmdCrossCertIssue(cfg, []string{"--issuer", "rev-ca"}); err == nil {
		t.Fatal("missing --target must error")
	}
	if err := cmdCrossCertIssue(cfg, []string{"--issuer", "rev-ca", "--target", "target-ca", "--validity", "abc"}); err == nil {
		t.Fatal("bad --validity must error")
	}
	if err := cmdCrossCertIssue(cfg, []string{"--issuer", "rev-ca", "--target", "ghost"}); err == nil {
		t.Fatal("unknown target must error")
	}

	out := filepath.Join(dir, "cross.pem")
	if err := cmdCrossCertIssue(cfg, []string{
		"--issuer", "rev-ca", "--target", "target-ca", "--validity", "365", "--out", out,
	}); err != nil {
		t.Fatalf("cross issue: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("cross certificate not written")
	}
}

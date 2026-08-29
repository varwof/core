// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func insertInfoRecord(t *testing.T, d *db.DB, caName, serial, cn string, status string, notAfter time.Time) {
	t.Helper()
	rec := &db.CertRecord{
		SerialNumber: serial,
		CAName:       caName,
		Status:       status,
		Subject:      "CN=" + cn,
		CommonName:   cn,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		CertDER:      []byte("x"),
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
}

func TestCmdCAInfo(t *testing.T) {
	dir := t.TempDir()
	d, cfg, _, _ := setupTestCA(t, dir)

	if err := cmdCAInfo(cfg, nil); err == nil {
		t.Fatal("missing --name must error")
	}
	if err := cmdCAInfo(cfg, []string{"--name", "ghost-ca"}); err == nil {
		t.Fatal("unknown CA must error")
	}

	insertInfoRecord(t, d, "rev-ca", "E10000000000000000000000000000000000001", "expired.example.com", "V", time.Now().Add(-24*time.Hour))
	insertInfoRecord(t, d, "rev-ca", "E10000000000000000000000000000000000002", "soon.example.com", "V", time.Now().Add(20*24*time.Hour))
	insertInfoRecord(t, d, "rev-ca", "E10000000000000000000000000000000000003", "revoked.example.com", "R", time.Now().Add(30*24*time.Hour))

	out := filepath.Join(dir, "ca.pem")
	if err := cmdCAInfo(cfg, []string{"--name", "rev-ca", "--out", out}); err != nil {
		t.Fatalf("ca-info: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("ca cert not written")
	}

	if err := cmdCAInfo(cfg, []string{"--name", "rev-ca"}); err != nil {
		t.Fatalf("ca-info without --out: %v", err)
	}
}

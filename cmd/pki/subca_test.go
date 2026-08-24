// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func runCapture(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	callErr := fn()
	w.Close()
	os.Stdout = old
	if callErr != nil {
		t.Fatalf("command failed: %v", callErr)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestCLISubCACreateListInfo(t *testing.T) {
	dir := t.TempDir()
	parentCertPath, parentKeyPath := writeCACertKey(t, dir, "parent")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"parent-ca": {Cert: parentCertPath, Key: parentKeyPath},
		},
	}
	if err := registerCACert(d, "parent-ca", parentCertPath); err != nil {
		t.Fatal(err)
	}

	if err := cmdSubCACreate(cfg, []string{
		"--name", "child-ca",
		"--parent", "parent-ca",
		"--key-type", "ecdsa-p256",
		"--max-path-len", "1",
		"--protocol", "cmp",
	}); err != nil {
		t.Fatalf("sub-ca create: %v", err)
	}

	// list should show the new sub-CA.
	listOut := runCapture(t, func() error {
		return cmdSubCAList(cfg, nil)
	})
	if !contains(listOut, "child-ca") {
		t.Fatalf("expected child-ca in list output, got:\n%s", listOut)
	}

	// info should return parent + protocol details.
	infoOut := runCapture(t, func() error {
		return cmdSubCAInfo(cfg, []string{"--name", "child-ca"})
	})
	if !contains(infoOut, "Parent CA:     parent-ca") {
		t.Fatalf("expected parent info, got:\n%s", infoOut)
	}
	if !contains(infoOut, "Protocol:      cmp") {
		t.Fatalf("expected protocol info, got:\n%s", infoOut)
	}
}

func TestCLISubCACreateWithOutDir(t *testing.T) {
	dir := t.TempDir()
	parentCertPath, parentKeyPath := writeCACertKey(t, dir, "parent-out")
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{
		DB: dbPath,
		CAs: map[string]internal.CAConfig{
			"parent-out-ca": {Cert: parentCertPath, Key: parentKeyPath},
		},
	}
	if err := registerCACert(d, "parent-out-ca", parentCertPath); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "subcas")
	if err := cmdSubCACreate(cfg, []string{
		"--name", "out-ca",
		"--parent", "parent-out-ca",
		"--out", outDir,
	}); err != nil {
		t.Fatalf("sub-ca create --out: %v", err)
	}
	for _, f := range []string{"out-ca.pem", "out-ca.key"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Fatalf("expected %s written: %v", f, err)
		}
	}
}

func TestCLISubCACreateMissingArgs(t *testing.T) {
	dbPath := newTestDBPath(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg := &internal.Config{DB: dbPath, CAs: map[string]internal.CAConfig{}}

	err = cmdSubCACreate(cfg, []string{"--name", "x"})
	if err == nil {
		t.Fatal("expected error when --parent missing")
	}
}

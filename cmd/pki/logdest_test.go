package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitLogFormatWritesToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pki.log")
	initLogFormat("json", "file:"+path, false)
	slog.Info("test-write", "k", "v")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"msg":"test-write"`) && !strings.Contains(string(data), "test-write") {
		t.Fatalf("log file missing entry: %q", string(data))
	}
	// restore stderr default for other tests
	initLogFormat("text", "stderr", false)
}

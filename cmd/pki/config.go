package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/core/internal"
)

// configPath is the single source of truth for the resolved config file path.
// Set by main() after parsing --config / auto-discovery.
var configPath string

// resolveConfigPath resolves the config file path.
// Priority: explicit flag > SearchConfigPath > DefaultConfigPath.
func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := internal.SearchConfigPath(); p != "" {
		return p
	}
	return internal.DefaultConfigPath()
}

// readRawConfig reads the config file as a raw map (for partial mutation + write-back).
func readRawConfig(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfgMap map[string]interface{}
	if err := json.Unmarshal(data, &cfgMap); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfgMap, nil
}

// writeRawConfig atomically writes a config map back to disk (tmp+rename).
func writeRawConfig(path string, cfgMap map[string]interface{}) error {
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// Config may carry plaintext passwords/keys — always write 0600 (M16).
	return writeFileAtomic(path, data, 0600)
}

// writeFileAtomic writes data to path atomically via tmp+rename, fsyncs the
// file and the parent directory so the write survives a power loss, and uses a
// per-call unique temp name so concurrent writers never clobber each other
// (M16).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// requireWriteConfig returns configPath or an error if not configured.
// Use this in subcommands that write to the config file.
func requireWriteConfig() (string, error) {
	if configPath == "" {
		return "", fmt.Errorf("no config file path; use --config to specify")
	}
	return configPath, nil
}

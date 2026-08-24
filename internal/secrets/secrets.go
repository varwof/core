// Package secrets resolves CA private key passwords from multiple sources.
//
// Precedence chain (first non-empty wins):
//
//  1. Per-CA env var: PKI_KEY_PASSWORD_<CA_NAME> (uppercase, hyphens→underscores)
//     Example: PKI_KEY_PASSWORD_ISSUING for CA named "issuing"
//  2. Global env var: PKI_KEY_PASSWORD (systemd LoadCredential injection)
//  3. Secrets file: path from PKI_PASSWORD_FILE env var (format: "ca_name=password" per line)
//  4. Config file value: the "password" field in ca.password JSON config
//
// This allows deployments to keep passwords out of the JSON config file entirely,
// using systemd credentials or environment injection instead (Tier 1 security).
package secrets

import (
	"log/slog"
	"os"
	"strings"
)

// ResolveCAKeyPassword resolves the CA private key password using the precedence chain.
// caName is the logical CA name from config (e.g., "issuing", "root").
// configPassword is the value from the JSON config's ca.password field (may be empty).
func ResolveCAKeyPassword(caName, configPassword string) string {
	// 1. Per-CA env var: PKI_KEY_PASSWORD_ISSUING
	envKey := "PKI_KEY_PASSWORD_" + strings.ToUpper(strings.ReplaceAll(caName, "-", "_"))
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	// M27 fix: a CA name containing an underscore collides with a hyphenated
	// name (e.g. "my_ca" and "my-ca" both map to PKI_KEY_PASSWORD_MY_CA). Warn
	// so operators do not silently read the wrong CA's password.
	if strings.Contains(caName, "_") {
		slog.Warn("secrets: CA name contains '_' which collides with the '-'→'_' env mapping; "+
			"PKI_KEY_PASSWORD_<NAME> may resolve to another CA's password",
			"ca", caName, "env_key", envKey)
	}

	// 2. Global env var: PKI_KEY_PASSWORD
	if v := os.Getenv("PKI_KEY_PASSWORD"); v != "" {
		return v
	}

	// 3. Secrets file: PKI_PASSWORD_FILE
	if filePath := os.Getenv("PKI_PASSWORD_FILE"); filePath != "" {
		if v := readPasswordFromFile(filePath, caName); v != "" {
			return v
		}
		// M27 fix: the operator set PKI_PASSWORD_FILE intending it to override
		// the config password, but the file was unreadable or had no entry for
		// this CA. Falling back to config plaintext silently could downgrade
		// security; log a warning so the misconfiguration is visible.
		slog.Warn("secrets: PKI_PASSWORD_FILE set but no password resolved for CA; "+
			"falling back to config value (check file permissions and ca_name entry)",
			"ca", caName, "file", filePath)
	}

	// 4. Config file fallback
	return configPassword
}

// readPasswordFromFile reads a password for the given CA name from a file.
// File format: one entry per line, "ca_name=password" (lines starting with # are comments).
func readPasswordFromFile(filePath, caName string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	prefix := caName + "="
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			return line[len(prefix):]
		}
	}
	return ""
}

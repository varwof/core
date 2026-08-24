package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCAKeyPassword_PerCAEnvVar(t *testing.T) {
	t.Setenv("PKI_KEY_PASSWORD_ISSUING", "per-ca-pass")
	t.Setenv("PKI_KEY_PASSWORD", "global-pass")

	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "per-ca-pass" {
		t.Errorf("expected per-ca-pass, got %q", got)
	}
}

func TestResolveCAKeyPassword_PerCAEnvVar_HyphenToUnderscore(t *testing.T) {
	t.Setenv("PKI_KEY_PASSWORD_MY_ISSUING", "hyphen-pass")

	got := ResolveCAKeyPassword("my-issuing", "config-pass")
	if got != "hyphen-pass" {
		t.Errorf("expected hyphen-pass, got %q", got)
	}
}

func TestResolveCAKeyPassword_GlobalEnvVar(t *testing.T) {
	t.Setenv("PKI_KEY_PASSWORD", "global-pass")

	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "global-pass" {
		t.Errorf("expected global-pass, got %q", got)
	}
}

func TestResolveCAKeyPassword_SecretsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "passwords.txt")
	os.WriteFile(file, []byte("# comment\nissuing=file-pass\nroot=root-pass\n"), 0600)
	t.Setenv("PKI_PASSWORD_FILE", file)

	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "file-pass" {
		t.Errorf("expected file-pass, got %q", got)
	}
}

func TestResolveCAKeyPassword_SecretsFile_NotFound(t *testing.T) {
	t.Setenv("PKI_PASSWORD_FILE", "/nonexistent/path")

	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "config-pass" {
		t.Errorf("expected config-pass fallback, got %q", got)
	}
}

func TestResolveCAKeyPassword_SecretsFile_WrongCA(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "passwords.txt")
	os.WriteFile(file, []byte("other=other-pass\n"), 0600)
	t.Setenv("PKI_PASSWORD_FILE", file)

	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "config-pass" {
		t.Errorf("expected config-pass fallback, got %q", got)
	}
}

func TestResolveCAKeyPassword_ConfigFallback(t *testing.T) {
	got := ResolveCAKeyPassword("issuing", "config-pass")
	if got != "config-pass" {
		t.Errorf("expected config-pass, got %q", got)
	}
}

func TestResolveCAKeyPassword_EmptyConfig(t *testing.T) {
	got := ResolveCAKeyPassword("issuing", "")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestResolveCAKeyPassword_Precedence(t *testing.T) {
	// Global < per-CA
	t.Setenv("PKI_KEY_PASSWORD", "global")
	t.Setenv("PKI_KEY_PASSWORD_ISSUING", "per-ca")
	got := ResolveCAKeyPassword("issuing", "config")
	if got != "per-ca" {
		t.Errorf("per-CA should win over global, got %q", got)
	}

	// Per-CA for different CA falls back to global
	t.Setenv("PKI_KEY_PASSWORD_OTHER", "")
	got = ResolveCAKeyPassword("other", "config")
	if got != "global" {
		t.Errorf("global should win over config, got %q", got)
	}
}

func TestReadPasswordFromFile_CommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw.txt")
	content := `# This is a comment

issuing=secret123

# Another comment
root=root456
`
	os.WriteFile(file, []byte(content), 0600)

	got := readPasswordFromFile(file, "issuing")
	if got != "secret123" {
		t.Errorf("expected secret123, got %q", got)
	}
	got = readPasswordFromFile(file, "root")
	if got != "root456" {
		t.Errorf("expected root456, got %q", got)
	}
}

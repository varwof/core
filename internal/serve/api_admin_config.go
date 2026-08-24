// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/varwof/core/internal"
)

// apiConfig handles GET/PUT /api/v1/admin/config
func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.apiGetConfig(w, r)
	case http.MethodPut:
		s.apiUpdateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiGetConfig handles GET /api/v1/admin/config
func (s *Server) apiGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if cfg == nil {
		apiErrorJSON(w, http.StatusInternalServerError, "config not loaded", "")
		return
	}

	cfgPath := ""
	if p := internal.SearchConfigPath(); p != "" {
		cfgPath = p
	}

	// C5 fix: redact sensitive fields before serializing.
	raw, err := json.Marshal(cfg)
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, "marshal config: "+err.Error(), "")
		return
	}
	var redacted map[string]interface{}
	if err := json.Unmarshal(raw, &redacted); err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, "unmarshal config: "+err.Error(), "")
		return
	}
	redactSensitiveFields(redacted)

	resp := map[string]interface{}{
		"config":      redacted,
		"config_path": cfgPath,
		"hot_reload":  true,
	}

	w.WriteHeader(http.StatusOK)
	writeJSON(w, resp)
}

// sensitiveKeyPatterns are JSON field name substrings that should be redacted
// in API responses to avoid leaking passwords and secrets.
var sensitiveKeyPatterns = []string{
	"password", "secret", "token", "key_password", "auth_password",
	"smtp_password", "ldap_password", "client_secret",
}

// redactSensitiveFields recursively walks a JSON-decoded map and replaces
// values of keys matching sensitive patterns with "<REDACTED>".
func redactSensitiveFields(m map[string]interface{}) {
	for k, v := range m {
		lk := strings.ToLower(k)
		for _, pat := range sensitiveKeyPatterns {
			if strings.Contains(lk, pat) {
				if s, ok := v.(string); ok && s != "" {
					m[k] = "<REDACTED>"
				}
				break
			}
		}
		if sub, ok := v.(map[string]interface{}); ok {
			redactSensitiveFields(sub)
		}
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if sub, ok := item.(map[string]interface{}); ok {
					redactSensitiveFields(sub)
				}
			}
		}
	}
}

// apiUpdateConfig handles PUT /api/v1/admin/config
func (s *Server) apiUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorJSON(w, http.StatusBadRequest, "invalid JSON", "")
		return
	}
	if len(req.Config) == 0 {
		apiErrorJSON(w, http.StatusBadRequest, "config is required", "")
		return
	}

	current := s.getConfig()
	if current == nil {
		apiErrorJSON(w, http.StatusInternalServerError, "config not loaded", "")
		return
	}

	var override internal.Config
	if err := json.Unmarshal(req.Config, &override); err != nil {
		apiErrorJSON(w, http.StatusBadRequest, "invalid config: "+err.Error(), "")
		return
	}

	merged := internal.MergeConfig(current, &override)
	if err := internal.Validate(merged); err != nil {
		apiErrorJSON(w, http.StatusBadRequest, "invalid config: "+err.Error(), "")
		return
	}

	cfgPath := s.configPath
	if cfgPath == "" {
		apiErrorJSON(w, http.StatusInternalServerError, "config file path not set on server", "")
		return
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, "marshal config: "+err.Error(), "")
		return
	}

	if err := writeFileAtomic(cfgPath, data, 0600); err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, "write config: "+err.Error(), "")
		return
	}

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]string{
		"status": "ok",
		"path":   cfgPath,
	})
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	// M16 fix: unique temp file name per call (PID alone is shared by
	// concurrent calls in the same process) so parallel writes never clobber.
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
	// M16 fix: fsync the parent directory so the rename is durable across a
	// power loss (otherwise the new file may be lost leaving a half config).
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

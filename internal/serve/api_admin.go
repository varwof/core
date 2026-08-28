// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

// ─── Authentication ──────────────────────────────────────────────

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.post_required", "")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.Username == "" || req.Password == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.username_required", "")
		return
	}
	if s.loginThrottled(req.Username) {
		detail, _ := json.Marshal(map[string]any{"username": req.Username})
		_ = s.getDB().LogAudit(req.Username, r.RemoteAddr, r.Method, r.URL.Path,
			"login_failed_throttled", string(detail))
		s.apiErr(w, r, http.StatusTooManyRequests, "api.account_locked", "")
		return
	}
	user, err := s.getUserByUsername(req.Username)

	if err != nil || user == nil {
		detail, _ := json.Marshal(map[string]any{"username": req.Username})
		_ = s.getDB().LogAudit(req.Username, r.RemoteAddr, r.Method, r.URL.Path,
			"login_failed_user_not_found", string(detail))
		s.apiErr(w, r, http.StatusUnauthorized, "api.login_failed", "")
		return
	}
	// M15 fix: reject disabled accounts immediately — no token issued.
	if !user.Enabled {
		detail, _ := json.Marshal(map[string]any{"username": req.Username})
		_ = s.getDB().LogAudit(req.Username, r.RemoteAddr, r.Method, r.URL.Path,
			"login_failed_account_disabled", string(detail))
		s.apiErr(w, r, http.StatusForbidden, "api.account_disabled", "account is disabled")
		return
	}
	if user.PasswordHash != db.HashPassword(req.Password, user.Salt) {
		s.recordLoginFailure(req.Username)
		detail, _ := json.Marshal(map[string]any{"username": req.Username})
		_ = s.getDB().LogAudit(req.Username, r.RemoteAddr, r.Method, r.URL.Path,
			"login_failed_bad_password", string(detail))
		s.apiErr(w, r, http.StatusUnauthorized, "api.login_failed", "invalid credentials")
		return
	}
	s.resetLoginThrottle(req.Username)
	token, err := s.createAPIToken(user.ID, "login", "")
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.create_token_failed", "")
		return
	}
	// Web console session: deliver the token via an HttpOnly cookie (not
	// localStorage) so it is invisible to JS and immune to XSS reads.
	http.SetCookie(w, &http.Cookie{
		Name:     "pki_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(7 * 24 * 3600),
	})
	apiOK(w, map[string]interface{}{
		"token":    token.Token,
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

// apiLogout handles POST /api/v1/users/logout
func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.post_required", "")
		return
	}
	token := extractToken(r)
	if token != "" {
		if info, err := s.getToken(token); err == nil && info != nil {
			s.deleteTokenByHash(db.TokenHash(token))
		}
	}
	// Clear the HttpOnly session cookie for the web console.
	http.SetCookie(w, &http.Cookie{
		Name:     "pki_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	apiOK(w, map[string]string{"status": "logged_out"})
}

// apiUserInfo handles GET /api/v1/users/info
func (s *Server) apiUserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		s.apiErr(w, r, http.StatusUnauthorized, "api.no_token", "")
		return
	}
	info, err := s.getToken(token)
	if err != nil || info == nil {
		s.apiErr(w, r, http.StatusUnauthorized, "api.invalid_token", "")
		return
	}
	user, err := s.getUserByUsername(info.Username)
	if err != nil || user == nil {
		s.apiErr(w, r, http.StatusUnauthorized, "api.user_not_found", "")
		return
	}
	apiOK(w, map[string]interface{}{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

// apiSession handles GET /api/v1/session — current session identity probe.
// Unlike /users/info (token-only), it authenticates through the full chain
// (mTLS cert / gateway-forwarded cert / token / cookie / basic) and reports
// the bound certificate identity when present. Web consoles call this on
// startup to detect the user and their certificate (user detection).
func (s *Server) apiSession(w http.ResponseWriter, r *http.Request) {
	user, err := s.authenticate(r)
	if err != nil || user == nil {
		s.apiErr(w, r, http.StatusUnauthorized, "api.unauthorized", "")
		return
	}
	resp := map[string]interface{}{
		"authenticated": true,
		"username":      user.Username,
		"role":          user.Role,
	}
	if user.CertIdentity != nil {
		resp["cert_identity"] = map[string]interface{}{
			"serial":        user.CertIdentity.Serial,
			"issuer":        user.CertIdentity.Issuer,
			"cn":            user.CertIdentity.CN,
			"spki_hash":     user.CertIdentity.SpkiHash,
			"principal_uid": user.CertIdentity.PrincipalUid,
			"agent_id":      user.CertIdentity.AgentId,
			"not_after":     user.CertIdentity.NotAfter.UTC().Format(time.RFC3339),
		}
	}
	apiOK(w, resp)
}

func extractToken(r *http.Request) string {
	if t := r.Header.Get("X-Auth-Token"); t != "" {
		return t
	}
	if b := r.Header.Get("Authorization"); len(b) > 7 && b[:7] == "Bearer " {
		return b[7:]
	}
	if c, err := r.Cookie("pki_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// ─── User Management ──────────────────────────────────────────────

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.getDB().ListUsers()
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, users)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.username_required", "")
			return
		}
		role := req.Role
		if role == "" {
			role = "operator"
		}
		salt, err := db.GenerateSalt()
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		hash := db.HashPassword(req.Password, salt)
		if err := s.createUser(req.Username, hash, salt, role); err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, map[string]string{"status": "created", "username": req.Username})
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
	}
}

// apiUserByID handles DELETE /api/v1/users/{id}
func (s *Server) apiUserByID(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodDelete {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.delete_required", "")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_user_id", "")
		return
	}
	if err := s.deleteUser(id); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "deleted"})
}

// apiUserOperatorCert handles POST /api/v1/users/{id}/operator-cert (bind) and
// DELETE /api/v1/users/{id}/operator-cert (unbind). Binding validates the
// certificate via the same fail-closed rules used at authentication time, so a
// malformed, foreign, expired or revoked certificate is rejected immediately.
func (s *Server) apiUserOperatorCert(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_user_id", "")
		return
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			CertPEM string `json:"cert_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
			return
		}
		if req.CertPEM == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.cert_pem_required", "")
			return
		}
		scopes, err := s.validateOperatorCertPEM([]byte(req.CertPEM))
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.operator_cert_invalid", err.Error())
			return
		}
		if err := s.updateUserOperatorCert(id, req.CertPEM); err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		username := "unknown"
		if u, ok := r.Context().Value(userCtxKey).(*AuthUser); ok && u != nil {
			username = u.Username
		}
		detail, _ := json.Marshal(map[string]any{"user_id": id, "scope": scopes})
		_ = s.getDB().LogAudit(username, r.RemoteAddr, r.Method, r.URL.Path,
			"operator_cert_bind", string(detail))
		apiOK(w, map[string]any{"status": "bound", "scope": scopes})
	case http.MethodDelete:
		if err := s.updateUserOperatorCert(id, ""); err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		username := "unknown"
		if u, ok := r.Context().Value(userCtxKey).(*AuthUser); ok && u != nil {
			username = u.Username
		}
		detail, _ := json.Marshal(map[string]any{"user_id": id})
		_ = s.getDB().LogAudit(username, r.RemoteAddr, r.Method, r.URL.Path,
			"operator_cert_unbind", string(detail))
		apiOK(w, map[string]string{"status": "unbound"})
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
	}
}

// ─── Token Management ─────────────────────────────────────────────

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		userID := 0
		if u := r.URL.Query().Get("user_id"); u != "" {
			userID, _ = strconv.Atoi(u)
		}
		tokens, err := s.getDB().ListTokens(userID)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, tokens)
	case http.MethodPost:
		var req struct {
			UserID      int    `json:"user_id"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
			return
		}
		if req.UserID <= 0 {
			s.apiErr(w, r, http.StatusBadRequest, "api.user_id_required", "")
			return
		}
		token, err := s.createAPIToken(req.UserID, req.Description, "")
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, token)
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
	}
}

// apiTokenByID handles DELETE /api/v1/tokens/{id}
func (s *Server) apiTokenByID(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodDelete {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.delete_required", "")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_token_id", "")
		return
	}
	if err := s.deleteTokenByID(id); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "deleted"})
}

// ─── Audit Log ────────────────────────────────────────────────────

func (s *Server) apiAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		limit, _ = strconv.Atoi(l)
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		offset, _ = strconv.Atoi(o)
	}
	entries, err := s.getDB().QueryAudit(limit, offset)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	apiOK(w, entries)
}

// ─── RA (Registration Authority) ─────────────────────────────────

func (s *Server) apiRARequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, offset := 50, 0
		status := r.URL.Query().Get("status")
		if l := r.URL.Query().Get("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			offset, _ = strconv.Atoi(o)
		}
		reqs, err := s.getDB().ListRARequests(status, limit, offset)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, reqs)
	case http.MethodPost:
		var req struct {
			CSR     string `json:"csr"`
			CN      string `json:"cn"`
			Profile string `json:"profile"`
			CA      string `json:"ca"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
			return
		}
		id, err := s.getDB().CreateRARequest(nil, req.CN, "", req.Profile, req.CA, "api", 1)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
			return
		}
		apiOK(w, map[string]interface{}{"id": id, "status": "pending"})
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
	}
}

// apiRAAction handles POST /api/v1/ra/{id}/{action}
func (s *Server) apiRAAction(w http.ResponseWriter, r *http.Request, idStr, action string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_ra_id", "")
		return
	}
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.post_required", "")
		return
	}
	var req struct {
		Comment string `json:"comment"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if _, _, err := s.getDB().AddRAApproval(id, "api", action, req.Comment); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": action, "id": idStr})
}

// ─── Key Recovery ─────────────────────────────────────────────────

func (s *Server) apiRecoverKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.post_required", "")
		return
	}
	var req struct {
		CA     string `json:"ca"`
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.CA == "" || req.Serial == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.ca_and_serial_required", "")
		return
	}
	key, err := s.getDB().GetEscrowedKey(req.CA, req.Serial)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.key_not_found", "")
		return
	}
	apiOK(w, map[string]interface{}{
		"ca":     req.CA,
		"serial": req.Serial,
		"key":    key,
	})
}

// ─── Route Dispatch ───────────────────────────────────────────────

// ─── Version ─────────────────────────────────────────────────────

func (s *Server) apiVersion(w http.ResponseWriter, r *http.Request) {
	apiOK(w, map[string]string{
		"version": s.Version,
		"build":   "2026-07-09",
	})
}

// apiAdminDispatch dispatches admin sub-routes (users/tokens/audit/ra/keys)
func (s *Server) apiAdminDispatch(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/users":
		s.apiUsers(w, r)
	case strings.HasPrefix(path, "/users/"):
		rest := strings.TrimPrefix(path, "/users/")
		if strings.HasSuffix(rest, "/operator-cert") {
			s.apiUserOperatorCert(w, r, strings.TrimSuffix(rest, "/operator-cert"))
			return
		}
		s.apiUserByID(w, r, rest)
	case path == "/tokens":
		s.apiTokens(w, r)
	case strings.HasPrefix(path, "/tokens/"):
		s.apiTokenByID(w, r, strings.TrimPrefix(path, "/tokens/"))
	case path == "/audit":
		s.apiAuditLog(w, r)
	case path == "/ra":
		s.apiRARequests(w, r)
	case strings.HasPrefix(path, "/ra/") && strings.HasSuffix(path, "/approve"):
		rest := strings.TrimPrefix(path, "/ra/")
		idStr := strings.TrimSuffix(rest, "/approve")
		s.apiRAAction(w, r, idStr, "approve")
	case strings.HasPrefix(path, "/ra/") && strings.HasSuffix(path, "/reject"):
		rest := strings.TrimPrefix(path, "/ra/")
		idStr := strings.TrimSuffix(rest, "/reject")
		s.apiRAAction(w, r, idStr, "reject")
	case path == "/keys/recover":
		s.apiRecoverKey(w, r)
	}
}

package serve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

// apiGatewayRegister handles POST /api/v1/gateway/register.
// Gateway calls this on startup to register its address with the CA.
func (s *Server) apiGatewayRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.apiErr(w, r, http.StatusUnauthorized, "api.mtls_required",
			"mTLS client certificate required for gateway registration")
		return
	}
	// H3 fix: verify the client certificate carries an admin role.
	// Without this, any valid mTLS client could register arbitrary gateway addresses.
	user, _ := s.authenticate(r)
	if user == nil || (user.Role != "admin" && user.Role != "superadmin") {
		s.apiErr(w, r, http.StatusForbidden, "api.admin_required",
			"admin or superadmin role required for gateway registration")
		return
	}
	var req struct {
		Address string `json:"address"`
		CaName  string `json:"ca_name,omitempty"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Address == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.address_required",
			"gateway address is required")
		return
	}
	if err := s.getDB().RegisterGateway(req.Address, req.CaName); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.register_failed", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "registered", "address": req.Address})
}

// apiGatewayHeartbeat handles POST /api/v1/gateway/heartbeat.
// Gateway calls this periodically to signal liveness.
func (s *Server) apiGatewayHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.apiErr(w, r, http.StatusUnauthorized, "api.mtls_required",
			"mTLS client certificate required")
		return
	}
	// H3 fix: heartbeat also requires admin role to prevent rogue heartbeats.
	user, _ := s.authenticate(r)
	if user == nil || (user.Role != "admin" && user.Role != "superadmin") {
		s.apiErr(w, r, http.StatusForbidden, "api.admin_required",
			"admin or superadmin role required for gateway heartbeat")
		return
	}
	var req struct {
		Address string `json:"address"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Address == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.address_required", "")
		return
	}
	if err := s.getDB().HeartbeatGateway(req.Address); err != nil {
		if err.Error() == "gateway not found" {
			s.apiErr(w, r, http.StatusNotFound, "api.gateway_not_found",
				"gateway not registered; call /gateway/register first")
			return
		}
		s.apiErr(w, r, http.StatusInternalServerError, "api.heartbeat_failed", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "ok"})
}

// apiGatewayList handles GET /api/v1/gateway/list.
func (s *Server) apiGatewayList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	gateways, err := s.getDB().ListAllGateways()
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.list_failed", err.Error())
		return
	}
	apiOK(w, map[string]any{"gateways": gateways, "count": len(gateways)})
}

// apiGatewayDisconnectAgent handles POST /api/v1/gateway/disconnect-agent.
// CA calls this on each registered gateway after revoking an agent's certificates.
func (s *Server) apiGatewayDisconnectAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	s.proxyDisconnectToGateways(w, r, "agent")
}

// apiGatewayDisconnectUser handles POST /api/v1/gateway/disconnect-user.
// CA calls this on each registered gateway after a user revoke-all.
func (s *Server) apiGatewayDisconnectUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	s.proxyDisconnectToGateways(w, r, "user")
}

// proxyDisconnectToGateways iterates all active gateways and POSTs the
// disconnect request to each one's /api/v1/gateway/disconnect-{target} endpoint.
func (s *Server) proxyDisconnectToGateways(w http.ResponseWriter, r *http.Request, target string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.read_body_failed", err.Error())
		return
	}

	gateways, err := s.getDB().ListActiveGateways()
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.list_gateways_failed", err.Error())
		return
	}

	endpoint := fmt.Sprintf("/api/v1/gateway/disconnect-%s", target)
	var succeeded, failed int
	var errors []string

	client := &http.Client{Timeout: 5 * time.Second}
	for _, gw := range gateways {
		addr := gw.Address
		if !strings.HasPrefix(addr, "http") {
			addr = "https://" + addr
		}
		url := strings.TrimRight(addr, "/") + endpoint

		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("%s: %v", gw.Address, err))
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("%s: %v", gw.Address, err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			succeeded++
		} else {
			failed++
			errors = append(errors, fmt.Sprintf("%s: status %d", gw.Address, resp.StatusCode))
		}
	}

	apiOK(w, map[string]any{
		"status":       "dispatched",
		"target":       target,
		"gateway_count": len(gateways),
		"succeeded":    succeeded,
		"failed":       failed,
		"errors":       errors,
	})
}

// notifyGatewaysDisconnect is a best-effort goroutine that sends disconnect-agent
// to all registered gateways after a certificate revocation.
func (s *Server) notifyGatewaysDisconnect(target, caName, serial string) {
	gateways, err := s.getDB().ListActiveGateways()
	if err != nil || len(gateways) == 0 {
		return
	}
	payload := fmt.Sprintf(`{"target":"%s","ca":"%s","serial":"%s"}`, target, caName, serial)
	s.dispatchToGateways(gateways, "/api/v1/gateway/disconnect-agent", payload)
}

// notifyGatewaysDisconnectUser is a best-effort goroutine that sends disconnect-user
// to all registered gateways after a user revoke-all.
func (s *Server) notifyGatewaysDisconnectUser(principalUid string) {
	gateways, err := s.getDB().ListActiveGateways()
	if err != nil || len(gateways) == 0 {
		return
	}
	payload := fmt.Sprintf(`{"principal_uid":"%s"}`, principalUid)
	s.dispatchToGateways(gateways, "/api/v1/gateway/disconnect-user", payload)
}

// dispatchToGateways sends a POST request to each gateway's endpoint (best-effort).
func (s *Server) dispatchToGateways(gateways []*db.GatewayRecord, endpoint, payload string) {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, gw := range gateways {
		addr := gw.Address
		if !strings.HasPrefix(addr, "http") {
			addr = "https://" + addr
		}
		url := strings.TrimRight(addr, "/") + endpoint

		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}

package serve

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

type aicListResponse struct {
	Extensions []*db.AICExtension `json:"extensions"`
	Total      int                `json:"total"`
}

func (s *Server) apiAICList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	caName := r.URL.Query().Get("ca_name")

	exts, err := s.getDB().ListAICExtensions(caName, limit, offset)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.list_error", err.Error())
		return
	}
	total, err := s.getDB().CountAICExtensions(caName)
	if err != nil {
		total = len(exts)
	}
	apiOK(w, aicListResponse{Extensions: exts, Total: total})
}

func (s *Server) apiAIGet(w http.ResponseWriter, r *http.Request, caName, serial string) {
	ext, err := s.getAICExtensionByCert(caName, serial)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "aic.not_found", "")
		return
	}
	apiOK(w, ext)
}

func (s *Server) apiAISearchByAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	exts, err := s.getDB().SearchAICByAgentID(agentID, limit, offset)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
		return
	}
	apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
}

func (s *Server) apiAISearchByPrincipal(w http.ResponseWriter, r *http.Request, principalUID string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	exts, err := s.getDB().SearchAICByPrincipalUID(principalUID, limit, offset)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
		return
	}
	apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
}

func (s *Server) apiAISearchByCapability(w http.ResponseWriter, r *http.Request) {
	scheme := r.URL.Query().Get("scheme")
	if scheme == "" {
		s.apiErr(w, r, http.StatusBadRequest, "aic.scheme_required", "scheme query parameter required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	exts, err := s.getDB().SearchAICByCapability(scheme, limit, offset)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
		return
	}
	apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
}

func (s *Server) apiAICSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		s.apiAICList(w, r)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	puid := r.URL.Query().Get("principal_uid")
	agentID := r.URL.Query().Get("agent_id")
	scheme := r.URL.Query().Get("scheme")
	caName := r.URL.Query().Get("ca_name")

	switch {
	case puid != "":
		exts, err := s.getDB().SearchAICByPrincipalUID(puid, limit, offset)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
			return
		}
		apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
	case agentID != "":
		exts, err := s.getDB().SearchAICByAgentID(agentID, limit, offset)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
			return
		}
		apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
	case scheme != "":
		exts, err := s.getDB().SearchAICByCapability(scheme, limit, offset)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "aic.search_error", err.Error())
			return
		}
		apiOK(w, aicListResponse{Extensions: exts, Total: len(exts)})
	default:
		exts, err := s.getDB().ListAICExtensions(caName, limit, offset)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "aic.list_error", err.Error())
			return
		}
		total, err := s.getDB().CountAICExtensions(caName)
		if err != nil {
			total = len(exts)
		}
		apiOK(w, aicListResponse{Extensions: exts, Total: total})
	}
}

func (s *Server) apiAICBackfill(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermInline(w, r, PermCertIssue) {
		return
	}
	if err := ca.BackfillAICFields(s.getDB()); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.backfill_error", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "ok"})
}

func (s *Server) apiAICDelete(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if !s.requirePermInline(w, r, PermCertIssue) {
		return
	}
	if err := s.getDB().DeleteAICExtension(caName, serial); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.delete_error", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "deleted"})
}

func (s *Server) apiAICUpdate(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if !s.requirePermInline(w, r, PermCertIssue) {
		return
	}
	var req struct {
		AgentID      *string `json:"agent_id"`
		PrincipalUID *string `json:"principal_uid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	ext, err := s.getAICExtensionByCert(caName, serial)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "aic.not_found", "")
		return
	}
	if req.AgentID != nil {
		ext.AgentID = *req.AgentID
	}
	if req.PrincipalUID != nil {
		ext.PrincipalUID = *req.PrincipalUID
	}
	if err := s.getDB().UpdateAICExtension(ext); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "aic.update_error", err.Error())
		return
	}
	apiOK(w, ext)
}

package serve

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/varwof/engine/db"
)

type webhookCreateReq struct {
	URL    string `json:"url"`
	Events string `json:"events"`
}

// apiWebhookSubs handles GET/POST/DELETE /api/v1/webhooks
func (s *Server) apiWebhookSubs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.apiListWebhookSubs(w, r)
	case http.MethodPost:
		s.apiCreateWebhookSub(w, r)
	case http.MethodDelete:
		s.apiDeleteWebhookSub(w, r)
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
	}
}

// apiListWebhookSubs handles GET /api/v1/webhooks
func (s *Server) apiListWebhookSubs(w http.ResponseWriter, r *http.Request) {
	subs, err := db.ListWebhookSubs(s.getDB())
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	apiOK(w, subs)
}

// apiCreateWebhookSub handles POST /api/v1/webhooks
func (s *Server) apiCreateWebhookSub(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		s.apiErr(w, r, http.StatusUnsupportedMediaType, "api.content_type_required", "")
		return
	}
	var req webhookCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.URL == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.url_required", "")
		return
	}
	sub, err := db.CreateWebhookSub(s.getDB(), req.URL, req.Events)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	apiOK(w, sub)
}

// apiDeleteWebhookSub handles DELETE /api/v1/webhooks
func (s *Server) apiDeleteWebhookSub(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.id_required", "")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_id", err.Error())
		return
	}
	if err := db.DeleteWebhookSub(s.getDB(), id); err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.internal_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

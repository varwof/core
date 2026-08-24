// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

type jsonTrustAnchor struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	HashID    string `json:"hash_id"`
	Subject   string `json:"subject"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Issuer    string `json:"issuer"`
	Trusted   bool   `json:"trusted"`
	Source    string `json:"source"`
}

func trustAnchorToJSON(a *db.TrustAnchor) jsonTrustAnchor {
	return jsonTrustAnchor{
		ID:        a.ID,
		Name:      a.Name,
		HashID:    a.HashID,
		Subject:   a.Subject,
		NotBefore: a.NotBefore.Format(time.RFC3339),
		NotAfter:  a.NotAfter.Format(time.RFC3339),
		Issuer:    a.Issuer,
		Trusted:   a.Trusted,
		Source:    a.Source,
	}
}

// apiTrustList handles GET /api/v1/trust
func (s *Server) apiTrustList(w http.ResponseWriter, r *http.Request) {
	filter := &db.TrustAnchorFilter{}

	if r.URL.Query().Get("trusted") != "" {
		v := r.URL.Query().Get("trusted") == "true"
		filter.Trusted = &v
	}
	if r.URL.Query().Get("source") != "" {
		filter.Source = r.URL.Query().Get("source")
	}
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		filter.Page, _ = strconv.Atoi(pageStr)
	}
	if sizeStr := r.URL.Query().Get("size"); sizeStr != "" {
		filter.Size, _ = strconv.Atoi(sizeStr)
	}
	if r.URL.Query().Get("hash_id") != "" {
		filter.HashID = r.URL.Query().Get("hash_id")
	}

	anchors, err := s.getDB().ListTrustAnchors(filter)
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	list := make([]jsonTrustAnchor, 0, len(anchors))
	for _, a := range anchors {
		list = append(list, trustAnchorToJSON(a))
	}
	apiOK(w, list)
}

// apiTrustGet handles GET /api/v1/trust/{hashID}
func (s *Server) apiTrustGet(w http.ResponseWriter, r *http.Request, hashID string) {
	anchor, err := s.getDB().GetTrustAnchor(hashID)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.trust_not_found", "")
		return
	}
	apiOK(w, trustAnchorToJSON(anchor))
}

// apiTrustSet handles PATCH /api/v1/trust/{hashID}
func (s *Server) apiTrustSet(w http.ResponseWriter, r *http.Request, hashID string) {
	var req struct {
		Trusted bool `json:"trusted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if err := s.getDB().UpdateTrustAnchorTrusted(hashID, req.Trusted); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.update_error", err.Error())
		return
	}
	apiOK(w, map[string]bool{"trusted": req.Trusted})
}

// apiTrustDelete handles DELETE /api/v1/trust/{hashID}
func (s *Server) apiTrustDelete(w http.ResponseWriter, r *http.Request, hashID string) {
	if err := s.getDB().DeleteTrustAnchor(hashID); err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.trust_not_found", err.Error())
		return
	}
	apiOK(w, map[string]string{"status": "deleted"})
}

// apiTrustImport handles POST /api/v1/trust/import
func (s *Server) apiTrustImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req struct {
		URL       string `json:"url,omitempty"`
		PEMBundle string `json:"pem_bundle,omitempty"`
		Rebase    bool   `json:"rebase,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	var pemData []byte
	source := "manual"

	if req.PEMBundle != "" {
		pemData = []byte(req.PEMBundle)
		source = "manual"
	} else {
		u := req.URL
		if u == "" {
			u = ca.DefaultCACertURL
		}
		source = "curl"
		var err error
		pemData, err = ca.FetchCACertBundle(u)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.fetch_error", err.Error())
			return
		}
	}

	if req.Rebase {
		if err := s.getDB().DeleteTrustAnchorsBySource(source); err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.rebase_error", err.Error())
			return
		}
	}

	result, err := ca.ImportTrustBundle(s.getDB(), pemData, source)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.import_error", err.Error())
		return
	}

	apiOK(w, map[string]interface{}{
		"imported": result.Imported,
		"skipped":  result.Skipped,
		"total":    result.Total,
		"source":   source,
	})
}

// apiTrustStats handles GET /api/v1/trust/stats
func (s *Server) apiTrustStats(w http.ResponseWriter, r *http.Request) {
	total, trusted, untrusted, err := s.getDB().TrustAnchorStats()
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	// Source breakdown
	filter := &db.TrustAnchorFilter{}
	all, err := s.getDB().ListTrustAnchors(filter)
	sources := make(map[string]int)
	if err == nil {
		for _, a := range all {
			sources[a.Source]++
		}
	}

	apiOK(w, map[string]interface{}{
		"total":     total,
		"trusted":   trusted,
		"untrusted": untrusted,
		"sources":   sources,
	})
}

// dispatchTrustAPI handles /trust/... routes within serveAPI.
// dispatchTrustAPI dispatches trust sub-routes (list/get/set/delete/import/stats)
func (s *Server) dispatchTrustAPI(w http.ResponseWriter, r *http.Request, path string) {
	// path is already trimmed prefix like "/trust" or "/trust/..."
	path = strings.TrimPrefix(path, "/trust")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "" || path == "/":
		s.apiTrustList(w, r)
	case path == "/import":
		s.apiTrustImport(w, r)
	case path == "/stats":
		s.apiTrustStats(w, r)
	case strings.HasPrefix(path, "/"):
		hashID := strings.TrimPrefix(path, "/")
		switch r.Method {
		case http.MethodGet:
			s.apiTrustGet(w, r, hashID)
		case http.MethodPatch:
			s.apiTrustSet(w, r, hashID)
		case http.MethodDelete:
			s.apiTrustDelete(w, r, hashID)
		default:
			s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		}
	default:
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
	}
}

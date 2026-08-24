// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/varwof/core/auth"
)

// permCheckRequest is the request body for POST /api/v1/permissions/check.
type permCheckRequest struct {
	PEM        string          `json:"pem"`
	Permission auth.Permission `json:"permission"`
}

// permCheckResponse is the response body for POST /api/v1/permissions/check.
type permCheckResponse struct {
	HasPerm bool     `json:"has_permission"`
	Role    string   `json:"role,omitempty"`
	Roles   []string `json:"roles_from_cert,omitempty"`
}

// apiPermissionCheck checks whether a certificate has a specified permission.
// The request body contains a PEM-encoded certificate and the permission name to check.
// Returns whether the certificate's OU role has that permission.
func (s *Server) apiPermissionCheck(w http.ResponseWriter, r *http.Request) {
	var req permCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorJSON(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	block, _ := pem.Decode([]byte(req.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		apiErrorJSON(w, http.StatusBadRequest, "invalid PEM certificate", "")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		apiErrorJSON(w, http.StatusBadRequest, "failed to parse certificate", err.Error())
		return
	}

	// Extract core roles
	roles := auth.ExtractRoles(cert, auth.NSCore)
	resp := permCheckResponse{
		Roles: auth.ExtractRoles(cert, auth.NSGateway),
	}
	resp.Roles = append(roles, resp.Roles...)

	// Check each role for the specified permission
	for _, role := range roles {
		if auth.HasPerm(role, req.Permission) {
			resp.HasPerm = true
			resp.Role = role
			break
		}
	}

	apiOK(w, resp)
}

// apiPermissionRoles returns all defined roles and the permission matrix.
func (s *Server) apiPermissionRoles(w http.ResponseWriter, r *http.Request) {
	names := auth.RoleNames()
	matrix := make(map[string][]auth.Permission, len(names))
	for _, name := range names {
		if p := auth.GetPolicy(); p != nil {
			grants := p.RoleGrants(name)
			perms := make([]auth.Permission, len(grants))
			for i, g := range grants {
				perms[i] = auth.Permission(g)
			}
			matrix[name] = perms
		} else {
			matrix[name] = auth.RolePermissions[name]
		}
	}

	apiOK(w, map[string]any{
		"roles":       names,
		"permissions": matrix,
	})
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/varwof/core/internal/ca"
)

type jsonSubCA struct {
	ID           int64   `json:"id"`
	Name         string  `json:"name"`
	ParentCA     string  `json:"parent_ca"`
	CertPEM      string  `json:"cert_pem,omitempty"`
	Subject      string  `json:"subject"`
	NotBefore    string  `json:"not_before"`
	NotAfter     string  `json:"not_after"`
	KeyAlgorithm string  `json:"key_algorithm"`
	Fingerprint  string  `json:"fingerprint"`
	Status       string  `json:"status"`
	Protocol     string  `json:"protocol"`
	KeyUsage     string  `json:"key_usage"`
	MaxPathLen   int     `json:"max_path_len"`
	CreatedAt    string  `json:"created_at"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *int    `json:"revoke_reason,omitempty"`
}

type createSubCARequest struct {
	Name             string   `json:"name"`
	ParentCA         string   `json:"parent_ca"`
	KeyType          string   `json:"key_type,omitempty"`
	Validity         string   `json:"validity,omitempty"`
	MaxPathLen       int      `json:"max_path_len,omitempty"`
	KeyUsage         []string `json:"key_usage,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	PermittedDomains []string `json:"permitted_domains,omitempty"`
	ExcludedDomains  []string `json:"excluded_domains,omitempty"`
	AdminCertPEM     string   `json:"admin_cert_pem,omitempty"`
}

type createSubCAResponse struct {
	Name        string `json:"name"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem,omitempty"`
	SerialHex   string `json:"serial_number"`
	Fingerprint string `json:"fingerprint"`
}

// apiCreateSubCA handles POST /api/v1/sub-cas
func (s *Server) apiCreateSubCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req createSubCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	// Only superadmin can create sub-CAs (framework operation, scope-exempt).
	cert, err := s.adminCertFromRequest(r, "")
	if err != nil {
		s.apiErr(w, r, http.StatusUnauthorized, "sub_ca.unauthorized", err.Error())
		return
	}
	if ouToRole(cert.Subject.OrganizationalUnit) != "superadmin" {
		s.apiErr(w, r, http.StatusForbidden, "api.forbidden_role",
			"only superadmin can create sub-CAs")
		return
	}

	// Validate required fields
	if req.Name == "" {
		s.apiErr(w, r, http.StatusBadRequest, "sub_ca.name_required", "")
		return
	}
	if req.ParentCA == "" {
		s.apiErr(w, r, http.StatusBadRequest, "sub_ca.parent_ca_required", "")
		return
	}

	// Parse validity duration
	validity := 10 * 365 * 24 * time.Hour // Default 10 years
	if req.Validity != "" {
		var err error
		validity, err = time.ParseDuration(req.Validity)
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "sub_ca.invalid_validity", err.Error())
			return
		}
	}

	// Get parent CA
	database := s.getDB()
	parentMeta, err := database.GetCAMeta(req.ParentCA)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "sub_ca.parent_ca_not_found", req.ParentCA)
		return
	}

	parentCert, err := parseCertDER(parentMeta.CertDER)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "sub_ca.invalid_parent_cert", err.Error())
		return
	}

	// Get parent CA key (from config or key backend)
	parentKey, err := s.getParentCAKey(req.ParentCA)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "sub_ca.parent_key_error", err.Error())
		return
	}

	// Create sub-CA
	serverCfg := s.getConfig()
	cfg := &ca.SubCAConfig{
		Name:             req.Name,
		ParentCA:         req.ParentCA,
		KeyType:          req.KeyType,
		Validity:         validity,
		MaxPathLen:       req.MaxPathLen,
		KeyUsage:         req.KeyUsage,
		Protocol:         req.Protocol,
		PermittedDomains: req.PermittedDomains,
		ExcludedDomains:  req.ExcludedDomains,
		CRLBaseURL:       serverCfg.CRL.CRLBaseURL,
	}

	result, err := ca.IssueSubCA(database, cfg, parentCert, parentKey)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "sub_ca.creation_failed", err.Error())
		return
	}

	resp := createSubCAResponse{
		Name:        result.Name,
		CertPEM:     string(result.CertPEM),
		KeyPEM:      string(result.KeyPEM),
		SerialHex:   result.SerialHex,
		Fingerprint: result.Fingerprint,
	}

	writeJSON(w, resp)
}

// apiListSubCAs handles GET /api/v1/sub-cas
func (s *Server) apiListSubCAs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// Verify admin certificate (list: no single target CA)
	if err := s.verifyAdminCert(r, ""); err != nil {
		s.apiErr(w, r, http.StatusUnauthorized, "sub_ca.unauthorized", err.Error())
		return
	}

	protocol := r.URL.Query().Get("protocol")
	database := s.getDB()

	subCAs, err := ca.ListSubCAs(database, protocol)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "sub_ca.list_failed", err.Error())
		return
	}

	list := make([]jsonSubCA, 0, len(subCAs))
	for _, subCA := range subCAs {
		jsonSCA := jsonSubCA{
			ID:           subCA.ID,
			Name:         subCA.Name,
			ParentCA:     subCA.ParentCA,
			Subject:      subCA.Subject,
			NotBefore:    subCA.NotBefore.Format(time.RFC3339),
			NotAfter:     subCA.NotAfter.Format(time.RFC3339),
			KeyAlgorithm: subCA.KeyAlgorithm,
			Fingerprint:  subCA.Fingerprint,
			Status:       subCA.Status,
			Protocol:     subCA.Protocol,
			KeyUsage:     subCA.KeyUsage,
			MaxPathLen:   subCA.MaxPathLen,
			CreatedAt:    subCA.CreatedAt.Format(time.RFC3339),
		}
		if subCA.RevokedAt != nil {
			t := subCA.RevokedAt.Format(time.RFC3339)
			jsonSCA.RevokedAt = &t
		}
		if subCA.RevokeReason != nil {
			jsonSCA.RevokeReason = subCA.RevokeReason
		}
		list = append(list, jsonSCA)
	}

	writeJSON(w, list)
}

// apiGetSubCA handles GET /api/v1/sub-ca/{name}
func (s *Server) apiGetSubCA(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// Verify admin certificate: scope must cover the requested sub-CA
	if err := s.verifyAdminCert(r, name); err != nil {
		s.apiErr(w, r, http.StatusUnauthorized, "sub_ca.unauthorized", err.Error())
		return
	}

	database := s.getDB()
	subCA, err := ca.GetSubCA(database, name)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "sub_ca.not_found", name)
		return
	}

	jsonSCA := jsonSubCA{
		ID:           subCA.ID,
		Name:         subCA.Name,
		ParentCA:     subCA.ParentCA,
		CertPEM:      encodeCertPEM(subCA.CertDER),
		Subject:      subCA.Subject,
		NotBefore:    subCA.NotBefore.Format(time.RFC3339),
		NotAfter:     subCA.NotAfter.Format(time.RFC3339),
		KeyAlgorithm: subCA.KeyAlgorithm,
		Fingerprint:  subCA.Fingerprint,
		Status:       subCA.Status,
		Protocol:     subCA.Protocol,
		KeyUsage:     subCA.KeyUsage,
		MaxPathLen:   subCA.MaxPathLen,
		CreatedAt:    subCA.CreatedAt.Format(time.RFC3339),
	}
	if subCA.RevokedAt != nil {
		t := subCA.RevokedAt.Format(time.RFC3339)
		jsonSCA.RevokedAt = &t
	}
	if subCA.RevokeReason != nil {
		jsonSCA.RevokeReason = subCA.RevokeReason
	}

	writeJSON(w, jsonSCA)
}

// apiRevokeSubCA handles POST /api/v1/sub-ca/{name}/revoke
func (s *Server) apiRevokeSubCA(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records so recently issued certs of this sub-CA
	// are visible to the DB revoke UPDATE.
	s.FlushRecordBuffer()

	// Verify admin certificate: scope must cover the target sub-CA
	if err := s.verifyAdminCert(r, name); err != nil {
		s.apiErr(w, r, http.StatusUnauthorized, "sub_ca.unauthorized", err.Error())
		return
	}

	var req struct {
		Reason int `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Default reason: unspecified
		req.Reason = 0
	}

	database := s.getDB()
	if err := ca.RevokeSubCA(database, name, req.Reason); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "sub_ca.revoke_failed", err.Error())
		return
	}

	writeJSON(w, map[string]string{"status": "revoked", "name": name})
}

// adminCertFromRequest validates the admin certificate carried by the request
// (X-Admin-Cert header or mTLS peer cert) and returns it. When targetCA is
// non-empty, the certificate's management scope (SAN URI urn:pki:ca:<scope>
// and/or OID 1.3.6.1.4.1.66257.1.5.1) must cover targetCA; an empty targetCA
// skips the scope check (e.g. listing sub-CAs). Scope is enforced in all
// permission modes.
// adminCertTrustPool builds a trust pool from the PKI's CA certificates and
// DB trust anchors, used to chain-verify admin certificates presented via the
// X-Admin-Cert header (H9 fix: without a pool, a self-signed or expired
// attacker certificate could pass as an "admin certificate").
func (s *Server) adminCertTrustPool() (*x509.CertPool, error) {
	cfg := s.getConfig()
	certPaths := make(map[string]string, len(cfg.CAs))
	for name, caCfg := range cfg.CAs {
		if caCfg.Cert != "" {
			certPaths[name] = caCfg.Cert
		}
	}
	return ca.LoadTrustPool(certPaths, s.getDB())
}

func (s *Server) adminCertFromRequest(r *http.Request, targetCA string) (*x509.Certificate, error) {
	// Check for admin certificate in header
	adminCertPEM := r.Header.Get("X-Admin-Cert")
	if adminCertPEM != "" {
		// Chain-verify against the PKI trust pool first (H9 fix: without it a
		// self-signed/expired attacker certificate could pass as an admin cert).
		pool, err := s.adminCertTrustPool()
		if err != nil {
			return nil, err
		}
		cert, err := ca.ValidateAdminCertFromPEMWithPool([]byte(adminCertPEM), pool, "")
		if err != nil {
			return nil, err
		}
		// Superadmin is a framework role: scope check is exempt (may manage
		// any sub-CA regardless of the certificate's Management CA scope).
		if ouToRole(cert.Subject.OrganizationalUnit) == "superadmin" {
			targetCA = ""
		}
		return cert, ca.ValidateAdminCertWithTarget(cert, nil, targetCA)
	}

	// Check for mTLS client certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		if ouToRole(cert.Subject.OrganizationalUnit) == "superadmin" {
			targetCA = ""
		}
		if err := ca.ValidateAdminCertWithTarget(cert, nil, targetCA); err != nil {
			return nil, err
		}
		return cert, nil
	}

	return nil, ca.ErrAdminCertRequired
}

// verifyAdminCert verifies that the request has a valid admin certificate.
func (s *Server) verifyAdminCert(r *http.Request, targetCA string) error {
	_, err := s.adminCertFromRequest(r, targetCA)
	return err
}

// getParentCAKey retrieves the private key for a parent CA.
func (s *Server) getParentCAKey(caName string) (crypto.Signer, error) {
	cfg := s.getConfig()

	// Try to get key from config
	if caCfg, ok := cfg.CAs[caName]; ok {
		if caCfg.Key != "" {
			keyPEM, err := os.ReadFile(caCfg.Key)
			if err != nil {
				return nil, err
			}
			return parsePrivateKey(keyPEM)
		}
	}

	return nil, errKeyNotConfigured
}

// parseCertDER parses a DER-encoded certificate.
func parseCertDER(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// encodeCertPEM encodes a DER-encoded certificate to PEM.
func encodeCertPEM(der []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

// parsePrivateKey parses a PEM-encoded private key.
func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		signer, ok := key.(crypto.Signer)
		if ok {
			if err := ca.CheckPublicKeyStrength(signer.Public()); err != nil {
				return nil, fmt.Errorf("weak key: %w", err)
			}
			return signer, nil
		}
	}

	// Try ECDSA
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		signer, ok := key.(crypto.Signer)
		if ok {
			if err := ca.CheckPublicKeyStrength(signer.Public()); err != nil {
				return nil, fmt.Errorf("weak key: %w", err)
			}
			return signer, nil
		}
	}

	// Try RSA
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		signer, ok := key.(crypto.Signer)
		if ok {
			if err := ca.CheckPublicKeyStrength(signer.Public()); err != nil {
				return nil, fmt.Errorf("weak key: %w", err)
			}
			return signer, nil
		}
	}

	return nil, fmt.Errorf("unsupported private key format")
}

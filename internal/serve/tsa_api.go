// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/tsa"
)

// TSA management API handlers.

// apiTSACert handles GET /api/v1/tsa/cert
func (s *Server) apiTSACert(w http.ResponseWriter, r *http.Request) {
	rc := s.GetTSAConfig()
	if rc == nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "tsa.not_configured", "")
		return
	}
	info := rc.CertInfo()
	if info == nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "tsa.no_signer_cert", "")
		return
	}
	apiOK(w, info)
}

// apiTSACertRenew handles POST /api/v1/tsa/cert/renew
func (s *Server) apiTSACertRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rc := s.GetTSAConfig()
	if rc == nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "tsa.not_configured", "")
		return
	}
	cfg := s.getConfig()
	if cfg.TSA.CoreURL == "" {
		s.apiErr(w, r, http.StatusBadRequest, "tsa.no_core_url", "core_url not configured")
		return
	}
	renewCfg := buildTSARenewalConfig(cfg)
	if err := tsa.ForceRenewSignerCert(rc, renewCfg); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "tsa.renew_failed", err.Error())
		return
	}
	apiOK(w, map[string]interface{}{
		"status":    "renewed",
		"cert_info": rc.CertInfo(),
	})
}

// apiTSACertRotate handles POST /api/v1/tsa/cert/rotate
func (s *Server) apiTSACertRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rc := s.GetTSAConfig()
	if rc == nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "tsa.not_configured", "")
		return
	}
	cfg := s.getConfig()
	if cfg.TSA.CoreURL == "" {
		s.apiErr(w, r, http.StatusBadRequest, "tsa.no_core_url", "core_url not configured")
		return
	}
	renewCfg := buildTSARenewalConfig(cfg)
	if err := tsa.RotateSignerCert(rc, renewCfg); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "tsa.rotate_failed", err.Error())
		return
	}
	apiOK(w, map[string]interface{}{
		"status":    "rotated",
		"cert_info": rc.CertInfo(),
	})
}

// apiTSACA handles GET /api/v1/tsa/ca
func (s *Server) apiTSACA(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if cfg.TSA.Chain == "" {
		s.apiErr(w, r, http.StatusNotFound, "tsa.no_chain", "")
		return
	}
	c, err := tsax509LoadCertFile(cfg.TSA.Chain)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "tsa.chain_load_error", err.Error())
		return
	}
	apiOK(w, map[string]interface{}{
		"serial_number": c.SerialNumber.String(),
		"subject":       c.Subject.String(),
		"issuer":        c.Issuer.String(),
		"not_before":    c.NotBefore.UTC().Format(time.RFC3339),
		"not_after":     c.NotAfter.UTC().Format(time.RFC3339),
		"is_ca":         c.IsCA,
	})
}

// apiTSACARenew handles POST /api/v1/tsa/ca/renew
func (s *Server) apiTSACARenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// TSA sub-CA renewal requires manual Root CA approval.
	apiOK(w, map[string]interface{}{
		"status":  "approval_required",
		"message": "TSA sub-CA renewal requires Root CA approval. Use 'pki issue --ca root --profile sub-ca' to generate a new TSA sub-CA certificate.",
	})
}

// buildTSARenewalConfig creates a tsa.RenewalConfig from the server config.
func buildTSARenewalConfig(cfg *internal.Config) *tsa.RenewalConfig {
	rc := &tsa.RenewalConfig{
		CoreURL:       cfg.TSA.CoreURL,
		CertFile:      cfg.TSA.SignerCert,
		KeyFile:       cfg.TSA.SignerKey,
		CACertFile:    cfg.TSA.TLSCACert,
		CAName:        cfg.TSA.CAName,
		ValidityDays:  cfg.TSA.ValidityDays,
		TLSClientCert: cfg.TSA.TLSClientCert,
		TLSClientKey:  cfg.TSA.TLSClientKey,
	}
	if cfg.TSA.RenewalWindow != "" {
		if d, err := time.ParseDuration(cfg.TSA.RenewalWindow); err == nil {
			rc.RenewalWindow = d
		}
	}
	return rc
}

// tsax509LoadCertFile loads a certificate from a PEM file (local helper to
// avoid importing crypto/x509 directly in this file's hot path).
func tsax509LoadCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

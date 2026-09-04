// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/engine"
)

// csrSignReq is the request for POST /api/v1/csr/sign.
type csrSignReq struct {
	CSRPEM       string   `json:"csr_pem"`
	CAName       string   `json:"ca,omitempty"`
	Profile      string   `json:"profile,omitempty"`
	ValidityDays int      `json:"validity,omitempty"`
	CommonName   string   `json:"cn,omitempty"`
	SANs         []string `json:"sans,omitempty"`
}

// csrSignResp is the response for POST /api/v1/csr/sign.
type csrSignResp struct {
	CertificatePEM string `json:"certificate_pem"`
	CACertPEM      string `json:"ca_cert_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	SerialNumber   string `json:"serial_number"`
	CommonName     string `json:"common_name"`
}

// apiCSRSign handles POST /api/v1/csr/sign
func (s *Server) apiCSRSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req csrSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	if req.CSRPEM == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.csr_required", "")
		return
	}

	cfg := s.getConfig()

	caName := req.CAName
	if caName == "" {
		caName = cfg.Defaults.CA
	}

	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found", "")
		return
	}

	if s.rl != nil {
		ip := requestIP(r.RemoteAddr)
		if !s.rl.AllowCA(ip, caName) {
			s.apiErr(w, r, http.StatusTooManyRequests, "api.too_many_requests", "")
			return
		}
	}

	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.ca_key_not_available", err.Error())
		return
	}

	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr", "")
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr", err.Error())
		return
	}
	// RFC 2986: reject CSRs whose self-signature does not verify — the requester
	// must prove control of the private key corresponding to the CSR public key.
	if err := csr.CheckSignature(); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr_signature", err.Error())
		return
	}
	// RFC 2986 §4.1: the only defined CSR version is 0 (v1).
	if csr.Version != 0 {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr_version", fmt.Sprintf("unsupported CSR version %d", csr.Version))
		return
	}

	profileName := req.Profile
	if profileName == "" {
		profileName = cfg.Defaults.Profile
	}

	validity := time.Duration(365) * 24 * time.Hour
	if req.ValidityDays > 0 {
		validity = time.Duration(req.ValidityDays) * 24 * time.Hour
	} else if cfg.Defaults.CertValidity != "" {
		if d, err := time.ParseDuration(cfg.Defaults.CertValidity); err == nil {
			validity = d
		}
	}

	cn := req.CommonName
	if cn == "" {
		cn = csr.Subject.CommonName
	}

	policyMappings, err := ca.ParsePolicyMappings(cfg.Defaults.PolicyMappings)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_policy_mappings", err.Error())
		return
	}

	signCfg := &ca.SignConfig{
		DB:                    s.getDB(),
		SkipDB:                s.addCertRecordEnabled(), // Memory engine/buffered batch persistence: sign only, no DB write
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                caName,
		Profile:               ca.Profile(profileName),
		Hash:                  cfg.Defaults.Hash,
		SubjectPubKey:         csr.PublicKey,
		CommonName:            cn,
		Validity:              validity,
		CRLBaseURL:            cfg.CRL.CRLBaseURL,
		OCSPURL:               cfg.Defaults.OCSPURL,
		IssuerURL:             cfg.Defaults.IssuerURL,
		IssuerAltNames:        cfg.Defaults.IssuerAltNames,
		SubjectInfoAccess:     cfg.Defaults.SubjectInfoAccess,
		PolicyOIDs:            cfg.Defaults.PolicyOIDs,
		PolicyMappings:        policyMappings,
		RequireExplicitPolicy: cfg.Defaults.RequireExplicitPolicy,
		InhibitPolicyMapping:  cfg.Defaults.InhibitPolicyMapping,
		InhibitAnyPolicy:      cfg.Defaults.InhibitAnyPolicy,
		PolicyFile:            cfg.Policy,
		RequirePolicy:         s.requirePolicy(),
		RequireTLSServerSAN:   s.requireTLSServerSAN(),
	}

	for _, san := range req.SANs {
		san = strings.TrimSpace(san)
		if san != "" {
			signCfg.SANs = append(signCfg.SANs, san)
		}
	}

	for _, dns := range csr.DNSNames {
		signCfg.SANs = append(signCfg.SANs, "DNS:"+dns)
	}
	for _, ip := range csr.IPAddresses {
		signCfg.SANs = append(signCfg.SANs, "IP:"+ip.String())
	}

	result, err := ca.Sign(signCfg)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.sign_failed", err.Error())
		return
	}
	// Memory engine/buffered batch persistence mode: return on successful signing, records managed
	// by the engine (in-memory authority, async batch persistence) or RecordBuffer (WAL protected,
	// max 500ms latency). Backpressure 503 when write pipeline is full; client can retry (this
	// signing was not persisted, no side effects).
	if err := s.addCertRecord(result.Record); err != nil {
		if errors.Is(err, engine.ErrBackpressure) {
			s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests",
				"write pipeline full, retry later")
			return
		}
		s.apiErr(w, r, http.StatusInternalServerError, "api.persist_failed", err.Error())
		return
	}

	recordCertIssued(caName, profileName)
	s.auditLog(r, "csr_sign",
		fmt.Sprintf("ca=%s profile=%s serial=%s cn=%q", caName, profileName, result.SerialHex, cn))

	certPEM := string(ca.CertToPEM(result.CertDER))

	var chainPEM string
	if caCfg.Chain != "" {
		chainRaw, err := os.ReadFile(caCfg.Chain)
		if err == nil {
			chainPEM = string(chainRaw)
		}
	}

	caCertPEM := string(ca.CertToPEM(issuerCert.Raw))

	resp := csrSignResp{
		CertificatePEM: certPEM,
		CACertPEM:      caCertPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   result.SerialHex,
		CommonName:     cn,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

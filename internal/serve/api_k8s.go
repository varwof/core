package serve

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal/ca"
)

type k8sSignReq struct {
	CSRPEM       string   `json:"csr_pem"`
	CAName       string   `json:"ca_name,omitempty"`
	Profile      string   `json:"profile,omitempty"`
	ValidityDays int      `json:"validity_days,omitempty"`
	CommonName   string   `json:"common_name,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	KeyType      string   `json:"key_type,omitempty"`
}

type k8sSignResp struct {
	CertificatePEM string `json:"certificate_pem"`
	CACertPEM      string `json:"ca_cert_pem"`
	ChainPEM       string `json:"chain_pem"`
	SerialNumber   string `json:"serial_number"`
}

// apiK8sSign handles POST /api/v1/k8s/sign
func (s *Server) apiK8sSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// C1 fix: endpoint disabled by default — requires explicit k8s_enabled: true in config.
	cfg := s.getConfig()
	if cfg.K8sEnabled == nil || !*cfg.K8sEnabled {
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		return
	}

	var req k8sSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	if req.CSRPEM == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.csr_required", "")
		return
	}

	caName := req.CAName
	if caName == "" {
		caName = cfg.Defaults.CA
	}

	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found", "")
		return
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

	certPEM := string(ca.CertToPEM(result.CertDER))

	var chainPEM string
	if caCfg.Chain != "" {
		chainRaw, err := os.ReadFile(caCfg.Chain)
		if err == nil {
			chainPEM = string(chainRaw)
		}
	}

	caCertPEM := string(ca.CertToPEM(issuerCert.Raw))

	resp := k8sSignResp{
		CertificatePEM: certPEM,
		CACertPEM:      caCertPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   result.SerialHex,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

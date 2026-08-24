package serve

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

// certUploadReq is the body for POST /api/v1/certs/upload. It registers an
// externally-issued certificate (e.g. a NAS device certificate) into the PKI
// inventory for lifecycle tracking, without holding its private key.
type certUploadReq struct {
	CertPEM    string `json:"cert_pem"`
	CAName     string `json:"ca_name"`     // logical group / issuing CA bucket; defaults to cert issuer CN
	DeviceType string `json:"device_type"` // e.g. "nas", "vpn", "generic"
	DeviceName string `json:"device_name"` // friendly name, stored in subject_o-less profile tag
}

// certUploadResp is returned on success.
type certUploadResp struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
	CAName       string `json:"ca_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Fingerprint  string `json:"fingerprint"`
}

// apiUploadCert handles POST /api/v1/certs/upload
func (s *Server) apiUploadCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req certUploadReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.CertPEM == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.cert_required", "")
		return
	}

	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_cert", "expected PEM CERTIFICATE block")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_cert", err.Error())
		return
	}

	caName := req.CAName
	if caName == "" {
		caName = cert.Issuer.CommonName
	}
	if caName == "" {
		caName = "external"
	}

	// Reject obviously broken validity windows.
	if !cert.NotAfter.After(cert.NotBefore) {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_cert", "notAfter must be after notBefore")
		return
	}

	profile := "uploaded"
	if req.DeviceType != "" {
		profile = "uploaded-" + strings.ToLower(strings.TrimSpace(req.DeviceType))
	}

	keyAlgo, keySize := keyInfo(cert.PublicKey)
	ski := hex.EncodeToString(cert.SubjectKeyId)
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	fp := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(fp[:])

	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, e := range cert.EmailAddresses {
		sans = append(sans, e)
	}
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}
	sanStr := strings.Join(sans, ",")

	subjectO := ""
	subjectC := ""
	if len(cert.Subject.Organization) > 0 {
		subjectO = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Country) > 0 {
		subjectC = cert.Subject.Country[0]
	}

	record := &db.CertRecord{
		SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
		CAName:       caName,
		Status:       "valid",
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      cert.Raw,
		Fingerprint:  fingerprint,
		SubjectO:     subjectO,
		SubjectC:     subjectC,
		IssuerDN:     cert.Issuer.String(),
		KeyAlgo:      keyAlgo,
		KeySize:      keySize,
		SigAlgo:      cert.SignatureAlgorithm.String(),
		SKI:          ski,
		AKI:          aki,
		SAN:          sanStr,
		Profile:      profile,
	}

	database := s.getDB()
	if err := database.InsertCert(record); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			s.apiErr(w, r, http.StatusConflict, "api.cert_exists", err.Error())
			return
		}
		s.apiErr(w, r, http.StatusInternalServerError, "api.upload_failed", err.Error())
		return
	}

	if database != nil {
		detail := fmt.Sprintf("ca=%s cn=%s serial=%s device_type=%s device_name=%s",
			caName, cert.Subject.CommonName, record.SerialNumber, req.DeviceType, req.DeviceName)
		_ = database.LogAudit("upload", r.RemoteAddr, r.Method, r.URL.Path, "cert_upload", detail)
	}

	resp := certUploadResp{
		SerialNumber: record.SerialNumber,
		CommonName:   cert.Subject.CommonName,
		CAName:       caName,
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint:  fingerprint,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func keyInfo(pub interface{}) (algo string, size int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

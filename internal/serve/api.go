// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/core/internal/secrets"
	"github.com/varwof/engine/db"
	p12 "software.sslmate.com/src/go-pkcs12"
)

var errKeyNotConfigured = fmt.Errorf("CA key not configured")

func (s *Server) acceptLang(r *http.Request) string {
	return i18n.DetectLang(s.getConfig().Locale, r.Header.Get("Accept-Language"))
}

func (s *Server) apiErr(w http.ResponseWriter, r *http.Request, code int, key string, detail string) {
	msg := key
	if s.bundle != nil {
		msg = s.bundle.T(s.acceptLang(r), key)
	}
	apiErrorJSON(w, code, msg, detail)
}

type apiErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func apiErrorJSON(w http.ResponseWriter, code int, msg, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(apiErr{Code: code, Message: msg, Detail: detail})
}

func apiOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

type jsonCA struct {
	Name         string `json:"name"`
	Subject      string `json:"subject"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	KeyAlgorithm string `json:"key_algorithm"`
	Fingerprint  string `json:"fingerprint"`
	CertPEM      string `json:"cert_pem"`
}

type jsonCert struct {
	SerialNumber string  `json:"serial_number"`
	CAName       string  `json:"ca_name"`
	Status       string  `json:"status"`
	Subject      string  `json:"subject"`
	CommonName   string  `json:"common_name"`
	NotBefore    string  `json:"not_before"`
	NotAfter     string  `json:"not_after"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *int    `json:"revoke_reason,omitempty"`
	Fingerprint  string  `json:"fingerprint"`
	CertPEM      string  `json:"cert_pem,omitempty"`
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v1") {
		path = strings.TrimPrefix(path, "/api/v1")
	} else {
		path = strings.TrimPrefix(path, "/api")
	}
	path = strings.TrimSuffix(path, "/")
	slog.Debug("api", "method", r.Method, "path", r.URL.Path)

	switch {
	case path == "/certs/batch":
		s.apiBatchIssue(w, r)
	case path == "/certs/upload":
		s.apiUploadCert(w, r)
	case path == "/certs/async":
		s.apiAsyncSubmit(w, r)
	case strings.HasPrefix(path, "/certs/async/"):
		s.apiAsyncStatus(w, r)
	case path == "/webhooks":
		s.apiWebhookSubs(w, r)
	case path == "/dashboard":
		s.apiDashboard(w, r)
	case path == "/dashboard/events":
		s.apiDashboardSSE(w, r)
	case path == "/stats/events":
		s.apiStatsSSE(w, r)
	case path == "/stats":
		s.apiStats(w, r)
	case path == "/cas/import":
		s.apiImportCA(w, r)
	case path == "/cas":
		s.apiListCAs(w, r)
	case path == "/cas/tree":
		s.apiCATree(w, r)
	case strings.HasSuffix(path, "/rotation") && strings.HasPrefix(path, "/ca/"):
		parts := strings.Split(strings.TrimPrefix(path, "/ca/"), "/")
		s.apiCARotationInfo(w, r, parts[0])
	case strings.HasSuffix(path, "/rotate") && strings.HasPrefix(path, "/ca/"):
		parts := strings.Split(strings.TrimPrefix(path, "/ca/"), "/")
		s.apiCARotate(w, r, parts[0])
	case strings.HasPrefix(path, "/ca/"):
		name := strings.TrimPrefix(path, "/ca/")
		s.apiGetCA(w, r, name)
	case path == "/certs/report.pdf":
		s.apiPDFReport(w, r)
	case path == "/reports/compliance":
		s.apiComplianceReport(w, r)
	case path == "/k8s/sign":
		s.apiK8sSign(w, r)
	case path == "/csr/sign":
		s.apiCSRSign(w, r)
	case path == "/certs":
		if r.Method == http.MethodPost {
			s.apiIssueCert(w, r)
		} else {
			s.apiListCerts(w, r)
		}
	case path == "/cert/by-key":
		s.apiFindCertByKey(w, r)
	case strings.HasPrefix(path, "/cert/") && (strings.HasSuffix(path, "/revoke") || strings.HasSuffix(path, "/renew") || strings.HasSuffix(path, "/export") || strings.HasSuffix(path, "/re-sign")):
		rest := strings.TrimPrefix(path, "/cert/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 {
			s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		} else if strings.HasSuffix(path, "/revoke") {
			s.apiRevokeCert(w, r, parts[0], parts[1])
		} else if strings.HasSuffix(path, "/renew") {
			s.apiRenewCert(w, r, parts[0], parts[1])
		} else if strings.HasSuffix(path, "/re-sign") {
			s.apiReSignCert(w, r, parts[0], parts[1])
		} else {
			s.apiExportCert(w, r, parts[0], parts[1])
		}
	case strings.HasPrefix(path, "/cert/"):
		rest := strings.TrimPrefix(path, "/cert/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 2 {
			s.apiGetCert(w, r, parts[0], parts[1])
		} else {
			s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		}
	case strings.HasPrefix(path, "/crl/") && strings.HasSuffix(path, "/generate"):
		name := strings.TrimPrefix(path, "/crl/")
		name = strings.TrimSuffix(name, "/generate")
		s.apiGenerateCRL(w, r, name)
	case strings.HasPrefix(path, "/crl/"):
		name := strings.TrimPrefix(path, "/crl/")
		s.apiGetCRL(w, r, name)
	case strings.HasPrefix(path, "/cross-cert/revoke"):
		s.apiCrossCertRevoke(w, r)
	case strings.HasPrefix(path, "/cross-cert/issue"):
		s.apiCrossCertIssue(w, r)
	case path == "/cross-certs":
		s.apiListCrossCerts(w, r)
	case path == "/verify/cert":
		s.apiVerifyCert(w, r)
	case path == "/agent/register":
		s.apiAgentRegister(w, r)
	case path == "/aic/issue":
		s.apiIssueAIC(w, r)
	case path == "/version":
		s.apiVersion(w, r)
	case path == "/certs/revoke-by-principal":
		s.apiRevokeByPrincipal(w, r)
	case path == "/certs/revoke-batch":
		s.apiRevokeCertsBatch(w, r)
	case path == "/user/revoke-all":
		s.apiUserRevokeAll(w, r)
	case path == "/users/login":
		s.apiLogin(w, r)
	case path == "/users/logout":
		s.apiLogout(w, r)
	case path == "/users/info":
		s.apiUserInfo(w, r)
	case path == "/session":
		s.apiSession(w, r)
	case path == "/users" || strings.HasPrefix(path, "/users/"):
		s.apiAdminDispatch(w, r, path)
	case path == "/tokens" || strings.HasPrefix(path, "/tokens/"):
		s.apiAdminDispatch(w, r, path)
	case path == "/admin/config":
		s.apiConfig(w, r)
	case path == "/audit":
		s.apiAdminDispatch(w, r, path)
	case path == "/ra" || strings.HasPrefix(path, "/ra/"):
		s.apiAdminDispatch(w, r, path)
	case strings.HasPrefix(path, "/keys/"):
		s.apiAdminDispatch(w, r, path)
	case strings.HasPrefix(path, "/trust"):
		s.dispatchTrustAPI(w, r, path)
	case path == "/dns/healthz":
		s.apiDNSHealth(w, r)
	case path == "/dns/records":
		s.apiDNSList(w, r)
	case strings.HasPrefix(path, "/dns/acme-challenge/"):
		s.apiDNSACME(w, r)
	case strings.HasPrefix(path, "/dns/cert/"):
		s.apiDNSCERT(w, r)
	case path == "/dns-query":
		s.apiDNSQuery(w, r)
	case path == "/permissions/roles":
		s.apiPermissionRoles(w, r)
	case path == "/permissions/check":
		s.apiPermissionCheck(w, r)
	case path == "/gateway/register":
		s.apiGatewayRegister(w, r)
	case path == "/gateway/heartbeat":
		s.apiGatewayHeartbeat(w, r)
	case path == "/gateway/list":
		s.apiGatewayList(w, r)
	case path == "/gateway/disconnect-agent":
		s.apiGatewayDisconnectAgent(w, r)
	case path == "/gateway/disconnect-user":
		s.apiGatewayDisconnectUser(w, r)
	case path == "/sub-cas":
		if r.Method == http.MethodPost {
			s.apiCreateSubCA(w, r)
		} else {
			s.apiListSubCAs(w, r)
		}
	case strings.HasPrefix(path, "/sub-ca/") && strings.HasSuffix(path, "/revoke-all"):
		name := strings.TrimPrefix(path, "/sub-ca/")
		name = strings.TrimSuffix(name, "/revoke-all")
		s.apiRevokeSubCAAll(w, r, name)
	case strings.HasPrefix(path, "/sub-ca/") && strings.HasSuffix(path, "/revoke"):
		name := strings.TrimPrefix(path, "/sub-ca/")
		name = strings.TrimSuffix(name, "/revoke")
		s.apiRevokeSubCA(w, r, name)
	case strings.HasPrefix(path, "/sub-ca/"):
		name := strings.TrimPrefix(path, "/sub-ca/")
		s.apiGetSubCA(w, r, name)
	case path == "/tsa/cert":
		s.apiTSACert(w, r)
	case path == "/tsa/cert/renew":
		s.apiTSACertRenew(w, r)
	case path == "/tsa/cert/rotate":
		s.apiTSACertRotate(w, r)
	case path == "/tsa/ca":
		s.apiTSACA(w, r)
	case path == "/tsa/ca/renew":
		s.apiTSACARenew(w, r)
	default:
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
	}
}

// apiListCAs handles GET /api/v1/cas
func (s *Server) apiListCAs(w http.ResponseWriter, r *http.Request) {
	metas, err := s.getDB().ListCAMetas()
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	if wantsCSV(r) {
		header := []string{"name", "subject", "not_before", "not_after", "key_algorithm", "fingerprint"}
		rows := make([][]string, 0, len(metas))
		for _, m := range metas {
			rows = append(rows, []string{
				m.Name, m.Subject,
				m.NotBefore.Format(time.RFC3339),
				m.NotAfter.Format(time.RFC3339),
				m.KeyAlgorithm, m.Fingerprint,
			})
		}
		writeCSV(w, header, rows, "cas.csv")
		return
	}
	list := make([]jsonCA, 0, len(metas))
	for _, m := range metas {
		list = append(list, caMetaToJSON(m))
	}
	writeJSON(w, list)
}

// apiGetCA handles GET /api/v1/ca/{name}
func (s *Server) apiGetCA(w http.ResponseWriter, r *http.Request, name string) {
	meta, err := s.getDB().GetCAMeta(name)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found", "")
		return
	}
	writeJSON(w, caMetaToJSON(meta))
}

// apiListCerts handles GET /api/v1/certs
func (s *Server) apiListCerts(w http.ResponseWriter, r *http.Request) {
	caName := r.URL.Query().Get("ca")
	status := r.URL.Query().Get("status")
	cn := r.URL.Query().Get("cn")

	if caName == "" {
		caName = s.getConfig().Defaults.CA
	}

	var (
		all []*db.CertRecord
		err error
	)
	if wantsCSV(r) {
		// CSV export semantics: export all matching certificates by default, not subject to pagination.
		all, err = s.getDB().ListCertsFiltered(caName, status, cn)
	} else {
		limit, offset := 50, 0
		if l := r.URL.Query().Get("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			offset, _ = strconv.Atoi(o)
		}
		all, err = s.getDB().ListCertsFilteredPage(caName, status, cn, limit, offset)
	}
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	list := make([]jsonCert, 0, len(all))
	for _, c := range all {
		list = append(list, certToJSON(c, false))
	}
	if list == nil {
		list = []jsonCert{}
	}

	if wantsCSV(r) {
		header := []string{"serial_number", "ca_name", "status", "common_name", "subject", "not_before", "not_after", "revoked_at", "revoke_reason", "fingerprint"}
		rows := make([][]string, 0, len(list))
		for _, c := range list {
			revoked := ""
			if c.RevokedAt != nil {
				revoked = *c.RevokedAt
			}
			reason := ""
			if c.RevokeReason != nil {
				reason = fmt.Sprintf("%d", *c.RevokeReason)
			}
			rows = append(rows, []string{
				c.SerialNumber, c.CAName, c.Status, c.CommonName,
				c.Subject, c.NotBefore, c.NotAfter, revoked, reason, c.Fingerprint,
			})
		}
		writeCSV(w, header, rows, "certs.csv")
		return
	}

	writeJSON(w, list)
}

// apiGetCert handles GET /api/v1/cert/{ca}/{serial}
func (s *Server) apiGetCert(w http.ResponseWriter, r *http.Request, caName, serial string) {
	rec, err := s.getCertRecord(caName, serial)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.cert_not_found", "")
		return
	}
	accept := r.Header.Get("Accept")
	switch {
	case strings.Contains(accept, "application/x-pem-file"):
		w.Header().Set("Content-Type", "application/x-pem-file")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.CertDER})
		w.Write(pemBytes)
	case strings.Contains(accept, "application/pkix-cert"):
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(rec.CertDER)
	default:
		apiOK(w, certToJSON(rec, true))
	}
}

func (s *Server) loadCAKey(caName string) (*x509.Certificate, crypto.Signer, error) {
	rs, err := s.rotatingSigner(caName)
	if err != nil {
		return nil, nil, err
	}
	// M8 fix: read the active cert+key from a single atomic snapshot so the
	// returned issuer certificate and signing key always belong together.
	// Returning rs.Cert() + rs (which signs with whatever is active at Sign()
	// time) was a TOCTOU: a rotation between the two reads produced signatures
	// under a new key with an old issuer certificate (chain inconsistency).
	if k := rs.Active(); k != nil && k.Cert != nil && k.Key != nil {
		return k.Cert, k.Key, nil
	}
	return nil, nil, errKeyNotConfigured
}

// resolvePassword resolves the CA key password using the precedence chain:
// per-CA env → global env → secrets file → config value.
func (s *Server) resolvePassword(caName, configPassword string) string {
	return secrets.ResolveCAKeyPassword(caName, configPassword)
}

type caTreeNode struct {
	Name       string        `json:"name"`
	Subject    string        `json:"subject"`
	IssuerName string        `json:"issuer_name,omitempty"`
	Children   []*caTreeNode `json:"children,omitempty"`
	Depth      int           `json:"depth"`
}

// apiCATree handles GET /api/v1/cas/tree
func (s *Server) apiCATree(w http.ResponseWriter, r *http.Request) {
	s.caTreeMu.Lock()
	if s.caTreeData != nil && time.Now().Before(s.caTreeData.expiresAt) {
		data := s.caTreeData.data
		s.caTreeMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	s.caTreeMu.Unlock()

	metas, err := s.getDB().ListCAMetas()
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	type caInfo struct {
		name    string
		subject string
		issuer  string
	}

	cas := make([]caInfo, 0, len(metas))
	subjectToName := make(map[string]string)
	for _, m := range metas {
		cert, parseErr := x509.ParseCertificate(m.CertDER)
		if parseErr != nil {
			continue
		}
		subj := cert.Subject.String()
		iss := cert.Issuer.String()
		cas = append(cas, caInfo{name: m.Name, subject: subj, issuer: iss})
		subjectToName[subj] = m.Name
	}

	nameToNode := make(map[string]*caTreeNode)
	for _, ci := range cas {
		nameToNode[ci.name] = &caTreeNode{
			Name:    ci.name,
			Subject: ci.subject,
		}
	}

	var roots []*caTreeNode

	for _, ci := range cas {
		node := nameToNode[ci.name]
		issuerName := ""
		if ci.subject != ci.issuer {
			if pn, ok := subjectToName[ci.issuer]; ok {
				issuerName = pn
			}
		}
		if issuerName == "" {
			node.Depth = 0
			roots = append(roots, node)
		} else {
			node.IssuerName = issuerName
			if parent := nameToNode[issuerName]; parent != nil {
				parent.Children = append(parent.Children, node)
			} else {
				node.Depth = 0
				roots = append(roots, node)
			}
		}
	}

	var setDepth func(node *caTreeNode, depth int)
	setDepth = func(node *caTreeNode, depth int) {
		node.Depth = depth
		for _, child := range node.Children {
			setDepth(child, depth+1)
		}
	}
	for _, root := range roots {
		setDepth(root, 0)
	}

	body, err := json.Marshal(roots)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.marshal_tree_failed", "")
		return
	}

	s.caTreeMu.Lock()
	s.caTreeData = &caTreeCacheEntry{
		data:      body,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	s.caTreeMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// apiGetCRL handles GET /api/v1/crl/{name}
func (s *Server) apiGetCRL(w http.ResponseWriter, r *http.Request, caName string) {
	meta, err := s.getDB().GetCAMeta(caName)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found", "")
		return
	}
	caCert, err := x509.ParseCertificate(meta.CertDER)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.parse_ca_failed", "")
		return
	}
	_, caKey, err := s.loadCAKey(caName)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.ca_key_not_available", "")
		return
	}

	cfg := s.getConfig()
	partition := -1
	total := cfg.CRL.Partitions
	if pStr := r.URL.Query().Get("partition"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			partition = p
		}
	}
	if tStr := r.URL.Query().Get("total"); tStr != "" {
		if t, err := strconv.Atoi(tStr); err == nil && t > 0 {
			total = t
		}
	}
	if total <= 1 {
		total = 1
	}

	crlDER, err := ca.GenerateCRL(&ca.CRLConfig{
		DB:                   s.getDB(),
		RevokedEntriesSource: s.revokedEntriesSource(),
		CACert:               caCert,
		CAKey:                caKey,
		CAName:               caName,
		ValidityDays:         cfg.CRL.ValidityDays,
		ThisUpdate:           time.Now(),
		Partition:            partition,
		TotalPartitions:      total,
		NumberStore:          s.crlNumberStore(),
	})
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	filename := caName + ".crl"
	if partition >= 0 && total > 1 {
		filename = ca.CRLFilename(caName, partition, total)
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write(crlDER)
}

// apiImportCA handles POST /api/v1/cas/import
func (s *Server) apiImportCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req struct {
		Name        string `json:"name"`
		CertPEM     string `json:"cert_pem"`
		KeyPEM      string `json:"key_pem"`
		P12Base64   string `json:"p12_base64"`
		P12Password string `json:"p12_password"`
		KeyPassword string `json:"key_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.Name == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.name_required", "")
		return
	}

	if req.KeyPassword == "" {
		req.KeyPassword = os.Getenv("PKI_KEY_PASSWORD")
	}

	var certPEM, keyPEM []byte
	var err error

	if req.P12Base64 != "" {
		pfxData, decErr := base64.StdEncoding.DecodeString(req.P12Base64)
		if decErr != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_p12", decErr.Error())
			return
		}
		certPEM, keyPEM, err = extractP12Bytes(pfxData, req.P12Password)
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.p12_extract_error", err.Error())
			return
		}
	} else {
		if req.CertPEM == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.cert_pem_required", "")
			return
		}
		if req.KeyPEM == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.key_pem_required", "")
			return
		}
		certPEM = []byte(req.CertPEM)
		keyPEM = []byte(req.KeyPEM)
	}

	record, err := ca.ImportExternalCA(s.getDB(), req.Name, certPEM, keyPEM, req.KeyPassword)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.import_ca_error", err.Error())
		return
	}

	// M12: importing a CA (with its private key) must be audited.
	s.auditLog(r, "ca_import",
		fmt.Sprintf("name=%s fingerprint=%s", record.Name, record.Fingerprint))

	apiOK(w, map[string]interface{}{
		"success":     true,
		"name":        record.Name,
		"fingerprint": record.Fingerprint,
		"subject":     record.Subject,
		"not_after":   record.NotAfter.Format(time.RFC3339),
		"key_stored":  len(record.KeyEncrypted) > 0,
	})
}

// apiVerifyCert handles POST /api/v1/verify/cert
func (s *Server) apiVerifyCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	var req struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.CertPEM == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.cert_pem_required", "")
		return
	}

	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_pem", "")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_cert", err.Error())
		return
	}

	cfg := s.getConfig()
	caCertPaths := make(map[string]string)
	for name, caCfg := range cfg.CAs {
		caCertPaths[name] = caCfg.Cert
	}

	pool, sources, err := ca.LoadTrustPoolWithSources(caCertPaths, s.getDB())
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_trust_error", err.Error())
		return
	}

	result, err := ca.VerifyCertificate(cert, pool, sources)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.verify_error", err.Error())
		return
	}

	apiOK(w, result)
}

func extractP12Bytes(pfxData []byte, password string) (certPEM, keyPEM []byte, err error) {
	priv, cert, chain, err := p12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, c := range chain {
		cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		certPEM = append(certPEM, cpem...)
	}
	return certPEM, keyPEM, nil
}

func caMetaToJSON(m *db.CAMeta) jsonCA {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.CertDER})
	return jsonCA{
		Name:         m.Name,
		Subject:      m.Subject,
		NotBefore:    m.NotBefore.Format(time.RFC3339),
		NotAfter:     m.NotAfter.Format(time.RFC3339),
		KeyAlgorithm: m.KeyAlgorithm,
		Fingerprint:  m.Fingerprint,
		CertPEM:      string(pemBytes),
	}
}

func certToJSON(c *db.CertRecord, includePEM bool) jsonCert {
	j := jsonCert{
		SerialNumber: c.SerialNumber,
		CAName:       c.CAName,
		Status:       c.Status,
		Subject:      c.Subject,
		CommonName:   c.CommonName,
		NotBefore:    c.NotBefore.Format(time.RFC3339),
		NotAfter:     c.NotAfter.Format(time.RFC3339),
		Fingerprint:  c.Fingerprint,
	}
	if c.RevokedAt != nil {
		s := c.RevokedAt.UTC().Format(time.RFC3339)
		j.RevokedAt = &s
	}
	if c.RevokeReason != nil {
		j.RevokeReason = c.RevokeReason
	}
	if includePEM && len(c.CertDER) > 0 {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.CertDER})
		j.CertPEM = string(pemBytes)
	}
	return j
}

func wantsCSV(r *http.Request) bool {
	return r.URL.Query().Get("format") == "csv" || strings.Contains(r.Header.Get("Accept"), "text/csv")
}

func writeCSV(w http.ResponseWriter, header []string, rows [][]string, filename string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write([]byte{0xef, 0xbb, 0xbf})
	cw := csv.NewWriter(w)
	cw.Write(header)
	for _, row := range rows {
		cw.Write(row)
	}
	cw.Flush()
}

func writeJSON(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

type batchReqItem struct {
	CN       string `json:"cn"`
	SAN      string `json:"san,omitempty"`
	Profile  string `json:"profile,omitempty"`
	CA       string `json:"ca,omitempty"`
	Validity int    `json:"validity,omitempty"`
	KeyType  string `json:"key_type,omitempty"`
}

type batchReq struct {
	Requests []batchReqItem `json:"requests"`
	Fast     bool           `json:"fast,omitempty"` // true=sign only, no DB write
}

type batchRespItem struct {
	Serial string `json:"serial,omitempty"`
	CN     string `json:"cn"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// apiBatchIssue handles POST /api/v1/certs/batch
func (s *Server) apiBatchIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		s.apiErr(w, r, http.StatusUnsupportedMediaType, "api.content_type_json", "")
		return
	}

	var req batchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	// H2 fix: reject empty batch to prevent requests[0] panic.
	if len(req.Requests) == 0 {
		s.apiErr(w, r, http.StatusBadRequest, "api.batch_empty", "requests array is empty")
		return
	}

	cfg := s.getConfig()
	n := len(req.Requests)
	results := make([]batchRespItem, 0, n)
	records := make([]*db.CertRecord, 0, n)
	persist := !req.Fast

	// Parallel issuance: worker pool
	type signJob struct {
		item batchReqItem
		idx  int
	}
	type signJobResult struct {
		idx    int
		resp   batchRespItem
		record *db.CertRecord
	}

	jobs := make(chan signJob, n)
	jobResults := make(chan signJobResult, n)

	// H2 fix: determine the effective CA and validate all items use the same CA.
	// Reject mixed-CA batches — each item's CA must match the first item's CA (or be empty = same CA).
	firstItem := req.Requests[0]
	batchCAName := firstItem.CA
	if batchCAName == "" {
		batchCAName = cfg.Defaults.CA
	}
	for i, item := range req.Requests {
		itemCA := item.CA
		if itemCA == "" {
			itemCA = cfg.Defaults.CA
		}
		if itemCA != batchCAName {
			s.apiErr(w, r, http.StatusBadRequest, "api.batch_mixed_ca",
				fmt.Sprintf("item %d: CA %q differs from batch CA %q; batch requests must use a single CA", i, itemCA, batchCAName))
			return
		}
	}

	// H2 fix: validate CA scope for batch issuance.
	user, _ := s.authenticate(r)
	if user != nil && !checkCAScope(user, r, PermCertIssue, cfg) {
		s.apiErr(w, r, http.StatusForbidden, "api.ca_scope_denied",
			fmt.Sprintf("CA %q not in your authorized scope", batchCAName))
		return
	}

	caName := batchCAName
	if caName == "" {
		caName = cfg.Defaults.CA
	}
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		results = append(results, batchRespItem{CN: caName, Status: "error", Error: fmt.Sprintf("CA %q not found", caName)})
		apiOK(w, results)
		return
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		results = append(results, batchRespItem{Status: "error", Error: fmt.Sprintf("load CA: %v", err)})
		apiOK(w, results)
		return
	}

	// Worker pool (12 concurrency)
	concurrency := 12
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				item := job.item
				keyType := item.KeyType
				if keyType == "" {
					keyType = cfg.Defaults.KeyType
				}
				privKey, err := ca.GenerateKey(keyType)
				if err != nil {
					jobResults <- signJobResult{job.idx, batchRespItem{CN: item.CN, Status: "error", Error: fmt.Sprintf("generate key: %v", err)}, nil}
					continue
				}
				profileName := item.Profile
				if profileName == "" {
					profileName = cfg.Defaults.Profile
				}
				validity := item.Validity
				if validity == 0 {
					validity = 365
				}

				signCfg := &ca.SignConfig{
					DB: s.getDB(), CAKey: issuerKey, CACert: issuerCert,
					CAName: caName, Profile: ca.Profile(profileName),
					SkipDB:        true,
					Hash:          cfg.Defaults.Hash,
					SubjectPubKey: privKey.Public(),
					CommonName:    item.CN, Validity: time.Duration(validity) * 24 * time.Hour,
					CRLBaseURL: cfg.CRL.CRLBaseURL, OCSPURL: cfg.Defaults.OCSPURL,
					IssuerURL:  cfg.Defaults.IssuerURL,
					DefaultOrg: cfg.Defaults.DefaultOrg, DefaultCountry: cfg.Defaults.DefaultCountry,
				}
				if item.SAN != "" {
					for _, s := range strings.Split(item.SAN, ",") {
						s = strings.TrimSpace(s)
						if s != "" {
							signCfg.SANs = append(signCfg.SANs, s)
						}
					}
				}
				result, err := ca.Sign(signCfg)
				if err != nil {
					jobResults <- signJobResult{job.idx, batchRespItem{CN: item.CN, Status: "error", Error: err.Error()}, nil}
					continue
				}
				var rec *db.CertRecord
				if persist {
					rec = buildBatchRecord(result, signCfg)
				}
				jobResults <- signJobResult{job.idx,
					batchRespItem{Serial: result.SerialHex, CN: item.CN, Status: "ok"}, rec}
			}
		}()
	}

	// Send jobs
	for idx, item := range req.Requests {
		jobs <- signJob{item, idx}
	}
	close(jobs)

	// Wait for workers to finish
	wg.Wait()
	close(jobResults)

	// Collect results in original order
	orderedResults := make([]batchRespItem, n)
	for r := range jobResults {
		orderedResults[r.idx] = r.resp
		if r.record != nil {
			records = append(records, r.record)
		}
	}
	results = orderedResults

	// Batch write to DB (uses engine pipeline when memory engine is enabled, maintaining in-memory authority consistency)
	if persist && len(records) > 0 {
		if s.getEngine() != nil {
			for _, rec := range records {
				if err := s.addCertRecord(rec); err != nil {
					slog.Warn("batch persist (engine)", "ca", rec.CAName, "serial", rec.SerialNumber, "error", err)
				}
			}
		} else if _, err := s.getDB().BulkInsertCertRecords(records); err != nil {
			slog.Warn("batch persist", "n", len(records), "error", err)
		}
	}

	apiOK(w, results)
}

type jsonCrossCert struct {
	IssuerCA     string  `json:"issuer_ca"`
	SubjectCA    string  `json:"subject_ca"`
	SerialNumber string  `json:"serial_number"`
	Status       string  `json:"status"`
	NotBefore    string  `json:"not_before"`
	NotAfter     string  `json:"not_after"`
	CertPEM      string  `json:"cert_pem,omitempty"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *int    `json:"revoke_reason,omitempty"`
}

// apiListCrossCerts handles GET /api/v1/cross-certs
func (s *Server) apiListCrossCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	issuerCA := r.URL.Query().Get("issuer")
	var records []*db.CrossCertRecord
	var err error
	if issuerCA != "" {
		records, err = s.getDB().ListCrossCerts(issuerCA)
	} else {
		records, err = s.getDB().ListCrossCertsAll()
	}
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	list := make([]jsonCrossCert, 0, len(records))
	for _, r := range records {
		list = append(list, crossCertToJSON(r, false))
	}
	if list == nil {
		list = []jsonCrossCert{}
	}
	writeJSON(w, list)
}

type crossCertIssueReq struct {
	Issuer   string `json:"issuer"`
	Target   string `json:"target"`
	Validity int    `json:"validity,omitempty"`
}

// apiCrossCertIssue handles POST /api/v1/cross-cert/issue
func (s *Server) apiCrossCertIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	var req crossCertIssueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.Issuer == "" || req.Target == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.issuer_and_target_required", "")
		return
	}
	validity := req.Validity
	if validity <= 0 {
		validity = 3650
	}

	cfg := s.getConfig()
	caCfg, ok := cfg.CAs[req.Issuer]
	if !ok {
		s.apiErr(w, r, http.StatusBadRequest, "api.issuer_ca_not_found", "")
		return
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(req.Issuer, caCfg.Password))
	if err != nil {
		apiErrorJSON(w, http.StatusInternalServerError, "load issuer CA", err.Error())
		return
	}

	targetMeta, err := s.getDB().GetCAMeta(req.Target)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.target_ca_not_found", "")
		return
	}

	result, err := ca.CrossSign(s.getDB(), issuerCert, issuerKey, req.Issuer, targetMeta, time.Duration(validity)*24*time.Hour, nil)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.cross_sign_failed", err.Error())
		return
	}

	// M12: cross-certificate issuance must be audited.
	s.auditLog(r, "cross_cert_issue",
		fmt.Sprintf("issuer=%s target=%s serial=%s", req.Issuer, req.Target, result.SerialHex))

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.CertDER})
	apiOK(w, jsonCrossCert{
		IssuerCA:     req.Issuer,
		SubjectCA:    req.Target,
		SerialNumber: result.SerialHex,
		Status:       "V",
		NotBefore:    result.Cert.NotBefore.Format(time.RFC3339),
		NotAfter:     result.Cert.NotAfter.Format(time.RFC3339),
		CertPEM:      string(pemBytes),
	})
}

// apiCrossCertRevoke handles POST /api/v1/cross-cert/revoke
func (s *Server) apiCrossCertRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	type revokeReq struct {
		Issuer string `json:"issuer"`
		Serial string `json:"serial"`
		Reason string `json:"reason,omitempty"`
	}
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.Issuer == "" || req.Serial == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.issuer_and_serial_required", "")
		return
	}
	reason, err := ca.ParseRevokeReason(req.Reason)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_reason", err.Error())
		return
	}
	if err := s.getDB().RevokeCrossCert(req.Issuer, req.Serial, reason); err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_failed", err.Error())
		return
	}
	// M12: cross-certificate revocation must be audited.
	s.auditLog(r, "cross_cert_revoke",
		fmt.Sprintf("issuer=%s serial=%s reason=%d", req.Issuer, req.Serial, reason))
	apiOK(w, map[string]string{"status": "ok"})
}

func crossCertToJSON(r *db.CrossCertRecord, includePEM bool) jsonCrossCert {
	j := jsonCrossCert{
		IssuerCA:     r.IssuerCA,
		SubjectCA:    r.SubjectCA,
		SerialNumber: r.SerialNumber,
		Status:       r.Status,
		NotBefore:    r.NotBefore.Format(time.RFC3339),
		NotAfter:     r.NotAfter.Format(time.RFC3339),
	}
	if r.RevokedAt != nil {
		s := r.RevokedAt.UTC().Format(time.RFC3339)
		j.RevokedAt = &s
	}
	if r.RevokeReason != nil {
		j.RevokeReason = r.RevokeReason
	}
	if includePEM && len(r.CertDER) > 0 {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.CertDER})
		j.CertPEM = string(pemBytes)
	}
	return j
}

// buildBatchRecord builds a CertRecord from a SignResult (for batch insertion).
func buildBatchRecord(result *ca.SignResult, cfg *ca.SignConfig) *db.CertRecord {
	cert := result.Cert
	return &db.CertRecord{
		SerialNumber: result.SerialHex,
		CAName:       cfg.CAName,
		Status:       "V",
		Subject:      cert.Subject.String(),
		CommonName:   cfg.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      result.CertDER,
		Profile:      string(cfg.Profile),
	}
}

// ---- Aggregator adapter ----

// aggregatorSigner implements the ca.CertSigner interface, called by CertAggregator.
type aggregatorSigner struct {
	s *Server
}

func (as *aggregatorSigner) SignBatch(items []*ca.AggregatorReq, caName string) []*ca.AggregatorResult {
	cfg := as.s.getConfig()
	results := make([]*ca.AggregatorResult, len(items))

	if len(items) == 0 {
		return results
	}

	// Load CA signer (reuses cache from first load)
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		for i := range items {
			results[i] = &ca.AggregatorResult{Err: fmt.Errorf("CA %q not found", caName)}
		}
		return results
	}

	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, as.s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		for i := range items {
			results[i] = &ca.AggregatorResult{Err: fmt.Errorf("load CA: %w", err)}
		}
		return results
	}

	// Issue each certificate
	for i, item := range items {
		keyType := item.KeyType
		if keyType == "" {
			keyType = cfg.Defaults.KeyType
		}
		privKey, err := ca.GenerateKey(keyType)
		if err != nil {
			results[i] = &ca.AggregatorResult{Err: fmt.Errorf("generate key: %w", err)}
			continue
		}

		profileName := item.Profile
		if profileName == "" {
			profileName = cfg.Defaults.Profile
		}

		signCfg := &ca.SignConfig{
			DB:            as.s.getDB(),
			CAKey:         issuerKey,
			CACert:        issuerCert,
			CAName:        caName,
			Profile:       ca.Profile(profileName),
			Hash:          cfg.Defaults.Hash,
			SubjectPubKey: privKey.Public(),
			CommonName:    item.CN,
			Validity:      365 * 24 * time.Hour,
			CRLBaseURL:    cfg.CRL.CRLBaseURL,
			OCSPURL:       cfg.Defaults.OCSPURL,
			IssuerURL:     cfg.Defaults.IssuerURL,
		}

		if item.SAN != "" {
			signCfg.SANs = strings.Split(item.SAN, ",")
		}

		result, err := ca.Sign(signCfg)
		if err != nil {
			results[i] = &ca.AggregatorResult{Err: err}
			continue
		}

		results[i] = &ca.AggregatorResult{
			Serial: result.SerialHex,
			Cert:   result.Cert,
		}
	}

	// Batch write to DB
	records := make([]*db.CertRecord, 0, len(items))
	for i, r := range results {
		if r.Err == nil && r.Cert != nil {
			records = append(records, &db.CertRecord{
				SerialNumber: r.Serial,
				CAName:       caName,
				Status:       "active",
				Subject:      r.Cert.Subject.String(),
				CommonName:   items[i].CN,
				NotBefore:    r.Cert.NotBefore,
				NotAfter:     r.Cert.NotAfter,
				CertDER:      r.Cert.Raw,
				Profile:      items[i].Profile,
			})
		}
	}
	if len(records) > 0 {
		if as.s.getEngine() != nil {
			for _, rec := range records {
				if err := as.s.addCertRecord(rec); err != nil {
					slog.Warn("aggregator batch persist (engine)", "ca", rec.CAName, "serial", rec.SerialNumber, "error", err)
				}
			}
		} else if _, err := as.s.getDB().BulkInsertCertRecords(records); err != nil {
			slog.Warn("aggregator batch persist", "n", len(records), "error", err)
		}
	}

	return results
}

// ---- Async issuance ----

// asyncJobProcessor implements the ca.JobProcessor interface, issuing certificates in parallel.
type asyncJobProcessor struct {
	s   *Server
	sem chan struct{}
}

func newAsyncJobProcessor(s *Server, concurrency int) *asyncJobProcessor {
	if concurrency <= 0 {
		concurrency = 12
	}
	return &asyncJobProcessor{s: s, sem: make(chan struct{}, concurrency)}
}

func (p *asyncJobProcessor) Process(items []ca.JobRequestItem) []ca.JobResultItem {
	if len(items) == 0 {
		return nil
	}

	cfg := p.s.getConfig()
	first := items[0]
	caName := first.CA
	if caName == "" {
		caName = cfg.Defaults.CA
	}
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		err := fmt.Sprintf("CA %q not found", caName)
		r := make([]ca.JobResultItem, len(items))
		for i := range r {
			r[i] = ca.JobResultItem{CN: items[i].CN, Status: "error", Error: err}
		}
		return r
	}

	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, p.s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		err := fmt.Sprintf("load CA: %v", err)
		r := make([]ca.JobResultItem, len(items))
		for i := range r {
			r[i] = ca.JobResultItem{CN: items[i].CN, Status: "error", Error: err}
		}
		return r
	}

	results := make([]ca.JobResultItem, len(items))
	var wg sync.WaitGroup
	for idx, item := range items {
		wg.Add(1)
		p.sem <- struct{}{}
		go func(idx int, item ca.JobRequestItem) {
			defer wg.Done()
			defer func() { <-p.sem }()

			keyType := item.KeyType
			if keyType == "" {
				keyType = cfg.Defaults.KeyType
			}
			privKey, err := ca.GenerateKey(keyType)
			if err != nil {
				results[idx] = ca.JobResultItem{CN: item.CN, Status: "error", Error: fmt.Sprintf("generate key: %v", err)}
				return
			}

			profileName := item.Profile
			if profileName == "" {
				profileName = cfg.Defaults.Profile
			}

			signCfg := &ca.SignConfig{
				DB: p.s.getDB(), CAKey: issuerKey, CACert: issuerCert,
				CAName: caName, Profile: ca.Profile(profileName),
				Hash: cfg.Defaults.Hash, SubjectPubKey: privKey.Public(),
				CommonName: item.CN,
				Validity:   365 * 24 * time.Hour,
				CRLBaseURL: cfg.CRL.CRLBaseURL, OCSPURL: cfg.Defaults.OCSPURL,
				IssuerURL:  cfg.Defaults.IssuerURL,
				DefaultOrg: cfg.Defaults.DefaultOrg, DefaultCountry: cfg.Defaults.DefaultCountry,
			}
			if item.SAN != "" {
				signCfg.SANs = strings.Split(item.SAN, ",")
			}

			result, err := ca.Sign(signCfg)
			if err != nil {
				results[idx] = ca.JobResultItem{CN: item.CN, Status: "error", Error: err.Error()}
				return
			}
			results[idx] = ca.JobResultItem{Serial: result.SerialHex, CN: item.CN, Status: "ok"}
		}(idx, item)
	}
	wg.Wait()

	// Batch write to DB
	records := make([]*db.CertRecord, 0, len(items))
	for i, r := range results {
		if r.Status == "ok" && r.Serial != "" {
			records = append(records, &db.CertRecord{
				SerialNumber: r.Serial, CAName: caName, Status: "active",
				Subject: "", CommonName: items[i].CN,
				NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
				Profile: items[i].Profile,
			})
		}
	}
	if len(records) > 0 {
		if p.s.getEngine() != nil {
			for _, rec := range records {
				if err := p.s.addCertRecord(rec); err != nil {
					slog.Warn("async batch persist (engine)", "ca", rec.CAName, "serial", rec.SerialNumber, "error", err)
				}
			}
		} else if _, err := p.s.getDB().BulkInsertCertRecords(records); err != nil {
			slog.Warn("async batch persist", "n", len(records), "error", err)
		}
	}
	return results
}

// apiAsyncSubmit submits an async issuance job.
func (s *Server) apiAsyncSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	var req ca.JobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if len(req.Items) == 0 {
		s.apiErr(w, r, http.StatusBadRequest, "api.empty_request", "")
		return
	}
	jobID := s.asyncQueue.Submit(req.Items)
	apiOK(w, map[string]any{"job_id": jobID, "total": len(req.Items)})
}

// apiAsyncStatus queries the status of an asynchronous job.
func (s *Server) apiAsyncStatus(w http.ResponseWriter, r *http.Request) {
	// Extract job_id from path: /api/v1/certs/async/{job_id}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/certs/async/")
	id = strings.TrimPrefix(id, "/api/certs/async/")
	if id == "" || id == r.URL.Path {
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		return
	}
	job := s.asyncQueue.GetJob(id)
	if job == nil {
		s.apiErr(w, r, http.StatusNotFound, "api.job_not_found", id)
		return
	}
	apiOK(w, job)
}

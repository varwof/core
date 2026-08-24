// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bufio"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/engine/db"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher so streaming handlers (SSE) keep working
// behind the access-log middleware.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so WebSocket upgrades through the
// access-log middleware do not fail with "http: ResponseWriter does not
// implement http.Hijacker".
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

// ReadFrom implements io.ReaderFrom so large static responses served through
// accessLog use the kernel sendfile/io.Copy fast path instead of the slow
// buffered path.
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{r.ResponseWriter}, src)
}

// Unwrap returns the underlying ResponseWriter for ResponseController access
// (Go 1.20+).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start)
		slog.Info("access", "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur", dur.String())
	})
}

type healthStatus struct {
	Status     string `json:"status"`
	Version    string `json:"version,omitempty"`
	DB         string `json:"db"`
	TSASigner  string `json:"tsa_signer,omitempty"`
	OCSPSigner string `json:"ocsp_signer,omitempty"`
	CRLStatus  string `json:"crl_status,omitempty"`
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		v := s.Version
		if v == "" {
			v = "pki/1.0"
		}
		hs := healthStatus{Version: v}

		if err := s.getDB().Ping(); err != nil {
			// M17 fix: do not leak raw driver errors on a public endpoint.
			hs.DB = "error"
		} else {
			hs.DB = "ok"
		}

		cfg := s.getConfig()
		if cfg.TSA.SignerCert != "" {
			if _, err := checkCertFile(cfg.TSA.SignerCert); err != nil {
				hs.TSASigner = "error"
			} else {
				hs.TSASigner = "ok"
			}
		}
		if cfg.OCSP.SignerCert != "" {
			if _, err := checkCertFile(cfg.OCSP.SignerCert); err != nil {
				hs.OCSPSigner = "error"
			} else {
				hs.OCSPSigner = "ok"
			}
		}

		// Verify the signing *private keys* can actually load (a present cert
		// does not prove the matching key is available for signing).
		if cfg.TSA.SignerKey != "" {
			if _, err := checkKeyFile(cfg.TSA.SignerKey); err != nil {
				hs.TSASigner = "key error"
			}
		}
		if cfg.OCSP.SignerKey != "" {
			if _, err := checkKeyFile(cfg.OCSP.SignerKey); err != nil {
				hs.OCSPSigner = "key error"
			}
		}

		// Verify CRL freshness: if a CRL output dir is configured, the most
		// recent CRL must exist and not be expired.
		hs.CRLStatus = checkCRLFreshness(cfg.CRL.OutputDir)

		hs.Status = "ok"
		if hs.DB != "ok" || (cfg.TSA.SignerCert != "" && hs.TSASigner != "ok") || (cfg.OCSP.SignerCert != "" && hs.OCSPSigner != "ok") || hs.CRLStatus != "ok" {
			hs.Status = "degraded"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hs)

	case "/readyz":
		if err := s.getDB().Ping(); err != nil {
			s.apiErr(w, r, http.StatusServiceUnavailable, "api.not_ready", "")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ready"))
	}
}

func (s *Server) tmplFuncs(r *http.Request) template.FuncMap {
	lang := i18n.DetectLang(s.getConfig().Locale, r.Header.Get("Accept-Language"))
	return template.FuncMap{
		"timefmt": func(t time.Time) string { return t.Format("2006-01-02") },
		"hex":     func(b []byte) string { return fmt.Sprintf("%X", b) },
		"t":       func(key string, args ...any) string { return s.bundle.T(lang, key, args...) },
	}
}

func checkCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a valid PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// checkKeyFile verifies a PEM private key (RSA/EC/PKCS8) can be parsed. It does
// not require the matching key password since the server loads these keys at
// startup; for password-protected keys the parse error is reported so the
// health endpoint surfaces key-loading regressions that a cert-only check
// would miss.
func checkKeyFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key")
}

// checkCRLFreshness reports whether a fresh, unexpired CRL exists under dir.
// Returns "ok" if no directory is configured (CRL not in use), "ok" if the
// newest *.crl file parses and is not yet expired, otherwise an error string.
func checkCRLFreshness(dir string) string {
	if dir == "" {
		return "ok"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// M17 fix: avoid leaking the absolute CRL directory path on a public endpoint.
		return "error: cannot read CRL directory"
	}
	var newest *x509.RevocationList
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			// DER-encoded CRL without PEM header is also valid.
			block = &pem.Block{Type: "CRL", Bytes: data}
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return fmt.Sprintf("parse error: %v", err)
		}
		if newest == nil || crl.ThisUpdate.After(newest.ThisUpdate) {
			newest = crl
		}
	}
	if newest == nil {
		return "error: no CRL found"
	}
	if time.Now().After(newest.NextUpdate) {
		return fmt.Sprintf("expired: nextUpdate=%s", newest.NextUpdate.Format(time.RFC3339))
	}
	return "ok"
}

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed web
var webFS embed.FS

type pageData struct {
	Title  string
	Lang   string
	CAs    []caSummary
	CA     *caDetail
	Certs  []certRow
	Config configInfo
}

type configInfo struct {
	DefaultCA string
	Version   string
}

type caSummary struct {
	Name         string
	Subject      string
	NotAfter     string
	KeyAlgorithm string
	Fingerprint  string
	CertCount    int
}

type caDetail struct {
	Name         string
	Subject      string
	NotBefore    string
	NotAfter     string
	KeyAlgorithm string
	Fingerprint  string
	CertPEM      string
	CertCount    int
	Certs        []certRow
}

type certRow struct {
	SerialNumber string
	CommonName   string
	Status       string
	NotBefore    string
	NotAfter     string
	CAName       string
	StatusBadge  string
}

func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("base").Funcs(s.tmplFuncs(r)).ParseFS(templateFS, "templates/*.html"))
	s.renderTemplate(tmpl, w, "dashboard.html", nil)
}

func (s *Server) serveTopology(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("base").Funcs(s.tmplFuncs(r)).ParseFS(templateFS, "templates/*.html"))
	s.renderTemplate(tmpl, w, "topology.html", nil)
}

func (s *Server) renderTemplate(tmpl *template.Template, w http.ResponseWriter, name string, data any) {
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template error", "name", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	tmpl := template.Must(template.New("base").Funcs(s.tmplFuncs(r)).ParseFS(templateFS, "templates/*.html"))

	ver := s.Version
	if ver == "" {
		ver = "pki/1.0"
	}
	lang := i18n.DetectLang(s.getConfig().Locale, r.Header.Get("Accept-Language"))
	data := pageData{
		Lang: lang,
		Config: configInfo{
			DefaultCA: s.getConfig().Defaults.CA,
			Version:   ver,
		},
	}

	switch {
	case path == "/":
		s.buildIndex(&data)
		tmpl.ExecuteTemplate(w, "index.html", data)

	case path == "/cas":
		s.buildCAList(&data)
		tmpl.ExecuteTemplate(w, "cas.html", data)

	case strings.HasPrefix(path, "/ca/"):
		name := strings.TrimPrefix(path, "/ca/")
		s.buildCADetail(&data, name)
		tmpl.ExecuteTemplate(w, "ca.html", data)

	case path == "/certs" || strings.HasPrefix(path, "/cert/"):
		caName := r.URL.Query().Get("ca")
		status := r.URL.Query().Get("status")
		cn := r.URL.Query().Get("cn")

		if strings.HasPrefix(path, "/cert/") {
			rest := strings.TrimPrefix(path, "/cert/")
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) == 2 {
				s.buildCertDetail(&data, parts[0], parts[1])
				tmpl.ExecuteTemplate(w, "cert.html", data)
				return
			}
		}

		s.buildCertList(&data, caName, status, cn)
		tmpl.ExecuteTemplate(w, "certs.html", data)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/pki")

	// Locale endpoint: return full locale JSON for detected language
	if path == "/locale.json" {
		lang := i18n.DetectLang(s.getConfig().Locale, r.Header.Get("Accept-Language"))
		locale := s.bundle.Locale(lang)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(locale)
		return
	}

	if path == "" || path == "/" || path == "/index.html" {
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		lang := i18n.DetectLang(s.getConfig().Locale, r.Header.Get("Accept-Language"))
		locale := s.bundle.Locale(lang)
		localeJSON, _ := json.Marshal(locale)
		html := strings.ReplaceAll(string(data), `<!--LOCALE_DATA-->`,
			`<script>window.__LOCALE__=`+string(localeJSON)+`;</script>`)
		html = strings.ReplaceAll(html, `lang="zh-CN"`, `lang="`+lang+`"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}
	// Try webFS first (app.js, style.css), fall back to staticFS
	if data, err := webFS.ReadFile("web" + path); err == nil {
		ct := "text/plain"
		if strings.HasSuffix(path, ".js") {
			ct = "application/javascript; charset=utf-8"
		}
		if strings.HasSuffix(path, ".css") {
			ct = "text/css; charset=utf-8"
		}
		if strings.HasSuffix(path, ".svg") {
			ct = "image/svg+xml"
		}
		w.Header().Set("Content-Type", ct)
		w.Write(data)
		return
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	r2 := *r
	r2.URL = new(url.URL)
	*r2.URL = *r.URL
	r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/pki")
	http.FileServer(http.FS(sub)).ServeHTTP(w, &r2)
}

func (s *Server) buildIndex(data *pageData) {
	metas, _ := s.getDB().ListCAMetas()
	now := time.Now()
	for _, m := range metas {
		count, _ := countCerts(s.getDB(), m.Name, "")
		cs := caSummary{
			Name:         m.Name,
			Subject:      m.Subject,
			NotAfter:     m.NotAfter.Format("2006-01-02"),
			KeyAlgorithm: m.KeyAlgorithm,
			Fingerprint:  m.Fingerprint,
			CertCount:    count,
		}
		if now.After(m.NotAfter) {
			cs.NotAfter += s.bundle.T(data.Lang, "template.expired_suffix")
		}
		data.CAs = append(data.CAs, cs)
	}
	data.Title = s.bundle.T(data.Lang, "template.title_index")
}

func (s *Server) buildCAList(data *pageData) {
	s.buildIndex(data)
	data.Title = s.bundle.T(data.Lang, "template.title_cas")
}

func (s *Server) buildCADetail(data *pageData, name string) {
	meta, err := s.getDB().GetCAMeta(name)
	if err != nil {
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: meta.CertDER})
	count, _ := countCerts(s.getDB(), name, "")
	certs, _ := listCertRows(s.getDB(), name, "", "")
	data.CA = &caDetail{
		Name:         meta.Name,
		Subject:      meta.Subject,
		NotBefore:    meta.NotBefore.Format("2006-01-02"),
		NotAfter:     meta.NotAfter.Format("2006-01-02"),
		KeyAlgorithm: meta.KeyAlgorithm,
		Fingerprint:  meta.Fingerprint,
		CertPEM:      string(pemBytes),
		CertCount:    count,
		Certs:        certs,
	}
	data.Title = s.bundle.T(data.Lang, "template.title_ca_detail", name)
}

func (s *Server) buildCertList(data *pageData, caName, status, cn string) {
	if caName == "" {
		caName = s.getConfig().Defaults.CA
	}
	certs, _ := listCertRows(s.getDB(), caName, status, cn)
	data.Certs = certs
	data.Title = s.bundle.T(data.Lang, "template.title_certs")
}

func (s *Server) buildCertDetail(data *pageData, caName, serial string) {
	rec, err := s.getCertRecord(caName, serial)
	if err != nil {
		return
	}
	data.Certs = []certRow{certRecordToRow(rec)}
	data.Title = s.bundle.T(data.Lang, "template.title_cert_detail")
}

func countCerts(d *db.DB, caName, status string) (int, error) {
	return d.CountCertsByCA(caName, status)
}

func listCertRows(d *db.DB, caName, status, cn string) ([]certRow, error) {
	all, err := d.ListCertsFiltered(caName, status, cn)
	if err != nil {
		return nil, err
	}
	rows := make([]certRow, 0, len(all))
	for _, c := range all {
		rows = append(rows, certRecordToRow(c))
	}
	return rows, nil
}

func certRecordToRow(c *db.CertRecord) certRow {
	badge := "valid"
	if c.Status == "R" {
		badge = "revoked"
	} else if c.Status == "E" {
		badge = "expired"
	}
	return certRow{
		SerialNumber: c.SerialNumber,
		CommonName:   c.CommonName,
		Status:       c.Status,
		NotBefore:    c.NotBefore.Format("2006-01-02"),
		NotAfter:     c.NotAfter.Format("2006-01-02"),
		CAName:       c.CAName,
		StatusBadge:  badge,
	}
}

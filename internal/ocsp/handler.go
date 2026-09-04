// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ocsp

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

var oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

const (
	ocspStatusMalformed   = 1
	ocspStatusInternal    = 2
	ocspStatusTryLater    = 3
	ocspStatusSigRequired = 5
	ocspStatusUnauth      = 6
)

type Config struct {
	DB         *db.DB
	Engine     func() *engine.Engine // optional memory engine getter; when non-nil and returns non-nil, status reads prefer it and fall back to DB
	CACert     *x509.Certificate
	CAName     string
	SignerCert *x509.Certificate
	SignerKey  crypto.Signer
	NextUpdate time.Duration
	// MetricsHook, if set, is invoked with (caName, status) for each produced
	// OCSP response, where status is one of "good", "revoked", "unknown".
	MetricsHook func(caName, status string)
	// CacheFile, when set, points to a persisted response cache that is loaded
	// at startup and re-saved after each new response is produced. This lets a
	// cold OCSP node (or a node that never contacts the CA database) serve
	// verified responses from disk without hammering the shared store.
	CacheFile string
}

func (c *Config) nextUpdate(now time.Time) time.Time {
	if c.NextUpdate > 0 {
		return now.Add(c.NextUpdate)
	}
	return now.Add(24 * time.Hour)
}

// getCertStatus returns the certificate status. When the memory engine is set
// it prefers the in-memory index and falls back to the DB on a miss, so
// certificates written out-of-band (CLI direct DB access) stay visible.
func (c *Config) getCertStatus(caName, serialHex string) (*db.CertStatus, error) {
	if c.Engine != nil {
		if e := c.Engine(); e != nil {
			st, err := e.GetCertStatus(caName, serialHex)
			if err == nil {
				return st, nil
			}
			if !errors.Is(err, engine.ErrNotFound) {
				slog.Warn("ocsp: engine status lookup failed, falling back to DB", "ca", caName, "serial", serialHex, "error", err)
			}
		}
	}
	if c.DB == nil {
		return nil, engine.ErrNotFound
	}
	return c.DB.GetCertStatus(caName, serialHex)
}

// GetCertStatus resolves certificate status using the same engine→DB fallback
// policy as the OCSP responder. It is the shared status source for both the
// wire handler and the OCSP staple provider.
func GetCertStatus(db *db.DB, engineFn func() *engine.Engine, caName, serialHex string) (*db.CertStatus, error) {
	cfg := &Config{DB: db, Engine: engineFn}
	return cfg.getCertStatus(caName, serialHex)
}

type Handler struct {
	config *Config
	cache  *Cache
}

func NewHandler(cfg *Config) *Handler {
	h := &Handler{config: cfg}
	if cfg.CacheFile != "" {
		h.cache = NewCache(100000, 24*time.Hour)
		if err := h.cache.Load(cfg.CacheFile); err != nil {
			slog.Warn("ocsp: cache load failed, starting empty", "file", cfg.CacheFile, "error", err)
		}
	}
	return h
}

// Close flushes the persisted cache (if any). Safe to call multiple times.
func (h *Handler) Close() {
	if h.cache != nil && h.config.CacheFile != "" {
		if err := h.cache.Save(h.config.CacheFile); err != nil {
			slog.Warn("ocsp: cache save on close failed", "file", h.config.CacheFile, "error", err)
		}
	}
}

func writeOCSPError(w http.ResponseWriter, status int) {
	resp := ocspResponse{ResponseStatus: asn1.Enumerated(status)}
	der, err := asn1.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(der)
}

type ocspResponse struct {
	ResponseStatus asn1.Enumerated
}

func (h *Handler) SetCache(cache *Cache) {
	h.cache = cache
}

// PurgeCert invalidates all cached responses for a certificate serial. It is
// called by the serve layer on revocation so clients are not served stale
// "good" responses from a cache whose entries can live for up to 24h. The
// persisted cache (when configured) is immediately re-saved so cold OCSP nodes
// stop serving the stale entry across restarts too.
func (h *Handler) PurgeCert(serial string) {
	if serial == "" || h.cache == nil {
		return
	}
	h.cache.PurgeSerial(serial)
	if h.config.CacheFile != "" {
		if err := h.cache.Save(h.config.CacheFile); err != nil {
			slog.Warn("ocsp: cache purge save failed", "file", h.config.CacheFile, "error", err)
		}
	}
}

func cacheKey(reqDER []byte) string {
	h := sha256.Sum256(reqDER)
	return hex.EncodeToString(h[:])
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var reqDER []byte

	accept := r.Header.Get("Accept")
	if accept != "" && accept != "*/*" && !strings.Contains(accept, "application/ocsp-response") {
		writeOCSPError(w, ocspStatusMalformed)
		return
	}

	switch r.Method {
	case http.MethodPost:
		// RFC 6960 A.1: the OCSP request SHALL contain a Content-Type of
		// 'application/ocsp-request'.
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/ocsp-request" && ct != "application/ocsp-request+pem" {
			writeOCSPError(w, ocspStatusMalformed)
			return
		}
		// M5 security fix (memory DoS): bound the request body. OCSP requests are
		// small DER blobs; an unauthenticated attacker must not be able to exhaust
		// heap with an arbitrarily large POST body.
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		r.Body.Close()
		if err != nil {
			writeOCSPError(w, ocspStatusMalformed)
			return
		}
		reqDER = body
	case http.MethodGet:
		// RFC 6960 A.1 / RFC 5019 §5: OCSP GET encodes the request as a
		// base64 URL path suffix (GET /ocsp/<base64>). Fall back to the
		// legacy ?query= form for backwards compatibility.
		q := strings.TrimPrefix(r.URL.Path, "/")
		if idx := strings.LastIndex(q, "/"); idx >= 0 {
			q = q[idx+1:]
		}
		if q == "" {
			q = r.URL.Query().Get("query")
		}
		if q == "" {
			writeOCSPError(w, ocspStatusMalformed)
			return
		}
		var err error
		reqDER, err = base64.URLEncoding.DecodeString(q)
		if err != nil {
			// Try standard base64 (no padding) as fallback.
			reqDER, err = base64.RawURLEncoding.DecodeString(q)
			if err != nil {
				writeOCSPError(w, ocspStatusMalformed)
				return
			}
		}
	default:
		writeOCSPError(w, ocspStatusMalformed)
		return
	}

	// Extract serial for audit and cache key
	serialHex := "unknown"
	if ocspReq, parseErr := ocsp.ParseRequest(reqDER); parseErr == nil {
		serialHex = fmt.Sprintf("%040X", ocspReq.SerialNumber)
	}

	if h.cache != nil {
		key := cacheKey(reqDER)
		if cached, ok := h.cache.Get(key); ok {
			auditOCSPQuery(h.config.DB, r, serialHex, "cache-hit")
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(cached)
			return
		}
	}

	respDER, err := h.handle(reqDER)
	if err != nil {
		auditOCSPQuery(h.config.DB, r, serialHex, "error")
		slog.Error("ocsp: handle", "serial", serialHex, "err", err)
		writeOCSPError(w, ocspStatusInternal)
		return
	}

	if h.cache != nil {
		key := cacheKey(reqDER)
		h.cache.PurgeSerial(serialHex)
		h.cache.SetWithSerial(key, serialHex, respDER)
		if h.config.CacheFile != "" {
			// Best-effort persistence so a crash does not lose recent
			// responses; failures are logged, never block the request.
			go func() {
				if err := h.cache.Save(h.config.CacheFile); err != nil {
					slog.Warn("ocsp: cache save failed", "file", h.config.CacheFile, "error", err)
				}
			}()
		}
	}

	auditOCSPQuery(h.config.DB, r, serialHex, "success")

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respDER)
}

func auditOCSPQuery(database *db.DB, r *http.Request, serial, status string) {
	if database == nil {
		return
	}
	detail := fmt.Sprintf("serial=%s status=%s", serial, status)
	database.LogAudit("ocsp", r.RemoteAddr, r.Method, "/ocsp", "ocsp_query", detail)
}

type rawTBSRequest struct {
	Version     int           `asn1:"explicit,tag:0,default:0,optional"`
	Requestor   asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList []asn1.RawValue
	Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type rawOCSPReq struct {
	TBSRequest rawTBSRequest
	Signature  asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

func extractNonce(reqDER []byte) []byte {
	var raw rawOCSPReq
	if _, err := asn1.Unmarshal(reqDER, &raw); err != nil {
		return nil
	}
	for _, ext := range raw.TBSRequest.Extensions {
		if ext.Id.Equal(oidOCSPNonce) {
			return ext.Value
		}
	}
	return nil
}

func extractRequestorName(reqDER []byte) string {
	var raw rawOCSPReq
	if _, err := asn1.Unmarshal(reqDER, &raw); err != nil {
		return ""
	}
	if raw.TBSRequest.Requestor.FullBytes == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw.TBSRequest.Requestor.FullBytes)
}

func (h *Handler) handle(reqDER []byte) ([]byte, error) {
	ocspReq, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	// RFC 6960 §4.1.1 / §3.2: validate issuerNameHash/issuerKeyHash against
	// the configured CA to prevent cross-CA request confusion. The hash
	// algorithms match golang.org/x/crypto/ocsp.CreateRequest:
	//   issuerNameHash = SHA-1(RawSubject)
	//   issuerKeyHash  = SHA-1(RightAlign(rawPublicKeyBits))
	if h.config.CACert != nil {
		expectedNameHash := sha1.Sum(h.config.CACert.RawSubject)
		if !bytes.Equal(ocspReq.IssuerNameHash, expectedNameHash[:]) {
			return nil, fmt.Errorf("OCSP request issuerNameHash does not match configured CA")
		}
		var pubInfo struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(h.config.CACert.RawSubjectPublicKeyInfo, &pubInfo); err != nil {
			return nil, fmt.Errorf("unmarshal CA SPKI: %w", err)
		}
		expectedKeyHash := sha1.Sum(pubInfo.PublicKey.RightAlign())
		if !bytes.Equal(ocspReq.IssuerKeyHash, expectedKeyHash[:]) {
			return nil, fmt.Errorf("OCSP request issuerKeyHash does not match configured CA")
		}
	}

	// Extract nonce for echo
	nonce := extractNonce(reqDER)

	serialHex := fmt.Sprintf("%040X", ocspReq.SerialNumber)

	caName := h.config.CAName
	if caName == "" {
		caName = "issuing"
	}
	record, err := h.config.getCertStatus(caName, serialHex)
	if err != nil {
		// Certificate not in database
		now := time.Now()
		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   h.config.nextUpdate(now),
			// RFC 5019 §2.2.2: a response signed by a delegate of the issuing CA
			// must carry the responder certificate for in-band validation.
			Certificate: h.config.SignerCert,
		}
		if nonce != nil {
			template.ExtraExtensions = []pkix.Extension{{Id: oidOCSPNonce, Value: nonce}}
		}
		if h.config.MetricsHook != nil {
			h.config.MetricsHook(caName, "unknown")
		}
		return ocsp.CreateResponse(h.config.CACert, h.config.SignerCert, template, h.config.SignerKey)
	}

	now := time.Now()
	// P0: expired cert check — expired non-revoked certs return unknown
	if record.NotAfter.Before(now) && record.Status == "V" {
		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   h.config.nextUpdate(now),
			Certificate:  h.config.SignerCert,
		}
		if nonce != nil {
			template.ExtraExtensions = []pkix.Extension{{Id: oidOCSPNonce, Value: nonce}}
		}
		if h.config.MetricsHook != nil {
			h.config.MetricsHook(caName, "expired")
		}
		return ocsp.CreateResponse(h.config.CACert, h.config.SignerCert, template, h.config.SignerKey)
	}

	template := ocsp.Response{
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   h.config.nextUpdate(now),
		Certificate:  h.config.SignerCert,
	}
	if nonce != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: oidOCSPNonce, Value: nonce}}
	}

	status := "unknown"
	switch record.Status {
	case "V":
		template.Status = ocsp.Good
		status = "good"
	case "R":
		template.Status = ocsp.Revoked
		status = "revoked"
		if record.RevokedAt != nil {
			template.RevokedAt = *record.RevokedAt
		}
		if record.RevokeReason != nil {
			template.RevocationReason = *record.RevokeReason
		}
	default:
		template.Status = ocsp.Unknown
	}

	if h.config.MetricsHook != nil {
		h.config.MetricsHook(caName, status)
	}
	return ocsp.CreateResponse(h.config.CACert, h.config.SignerCert, template, h.config.SignerKey)
}

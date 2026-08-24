// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ocsp

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

// StapleProvider generates and caches OCSP stapling responses (RFC 6066)
// for leaf certificates, ready to be attached to
// tls.Certificate.OCSPStaple. It is the missing half of the Must-Staple
// extension (2.5.29.24): signing a certificate with Must-Staple signals the
// TLS server must serve a staple, and this provider supplies it.
//
// The provider resolves certificate status through the same engine→DB
// fallback as the wire OCSP responder, so a server embedding it reuses the
// CA's authoritative status without running its own responder.
type StapleProvider struct {
	caName     string
	caCert     *x509.Certificate
	signerCert *x509.Certificate
	signerKey  crypto.Signer
	nextUpdate time.Duration

	db       *db.DB
	engineFn func() *engine.Engine

	mu        sync.RWMutex
	staples   map[string][]byte // serial hex → DER OCSP response
	stop      chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

// StapleProviderConfig carries the inputs for a StapleProvider.
type StapleProviderConfig struct {
	// CAName is the issuing CA name whose certificates are stapled.
	CAName string
	// CACert is the issuing CA certificate (the responder issuer).
	CACert *x509.Certificate
	// SignerCert / SignerKey identify the OCSP responder signing the staple.
	SignerCert *x509.Certificate
	SignerKey  crypto.Signer
	// NextUpdate is the OCSP response validity window (default 24h).
	NextUpdate time.Duration
	// DB is the status source (engine preferred via Engine).
	DB *db.DB
	// Engine, when non-nil and returning a non-nil engine, is the preferred
	// in-memory status source (engine → DB fallback, same as the responder).
	Engine func() *engine.Engine
}

// NewStapleProvider builds a provider. The status source (DB) may be nil only
// if every status is pre-warmed via Refresh ahead of serving.
func NewStapleProvider(cfg StapleProviderConfig) *StapleProvider {
	if cfg.NextUpdate <= 0 {
		cfg.NextUpdate = 24 * time.Hour
	}
	return &StapleProvider{
		caName:     cfg.CAName,
		caCert:     cfg.CACert,
		signerCert: cfg.SignerCert,
		signerKey:  cfg.SignerKey,
		nextUpdate: cfg.NextUpdate,
		db:         cfg.DB,
		engineFn:   cfg.Engine,
		staples:    make(map[string][]byte),
		stop:       make(chan struct{}),
	}
}

// buildResponse resolves status and produces a signed OCSP response for the
// leaf certificate. A certificate that is not in the store yields a "good"
// response with Unknown fallback? No: unknown status is returned as-is so the
// TLS client treats it as unknown (fail-closed at the client's policy).
func (p *StapleProvider) buildResponse(cert *x509.Certificate) ([]byte, error) {
	serialHex := fmt.Sprintf("%040X", cert.SerialNumber)
	record, err := GetCertStatus(p.db, p.engineFn, p.caName, serialHex)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) || isNoRows(err) {
			// Certificate unknown to the CA: staple "unknown" so clients do
			// not hard-fail on a missing staple for a legitimately unknown cert.
			now := time.Now()
			tmpl := ocsp.Response{
				Status:       ocsp.Unknown,
				SerialNumber: cert.SerialNumber,
				ThisUpdate:   now,
				NextUpdate:   now.Add(p.nextUpdate),
			}
			return ocsp.CreateResponse(p.caCert, p.signerCert, tmpl, p.signerKey)
		}
		return nil, fmt.Errorf("ocsp staple: resolve status: %w", err)
	}

	now := time.Now()
	tmpl := ocsp.Response{
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(p.nextUpdate),
	}
	status := "unknown"
	switch record.Status {
	case "V":
		if record.NotAfter.Before(now) {
			tmpl.Status = ocsp.Unknown
			status = "expired"
		} else {
			tmpl.Status = ocsp.Good
			status = "good"
		}
	case "R":
		tmpl.Status = ocsp.Revoked
		status = "revoked"
		if record.RevokedAt != nil {
			tmpl.RevokedAt = *record.RevokedAt
		}
		if record.RevokeReason != nil {
			tmpl.RevocationReason = *record.RevokeReason
		}
	default:
		tmpl.Status = ocsp.Unknown
	}
	if status == "revoked" {
		// A revoked cert must never be stapled as good; the TLS client's
		// validation will reject the handshake per RFC 6066. The response is
		// still produced and cached so the failure is deterministic.
	}
	return ocsp.CreateResponse(p.caCert, p.signerCert, tmpl, p.signerKey)
}

func isNoRows(err error) bool {
	return err != nil && (err.Error() == "sql: no rows in result set" ||
		err.Error() == "no rows in result set")
}

// Refresh generates (and caches) the staple for cert, returning its DER.
func (p *StapleProvider) Refresh(cert *x509.Certificate) ([]byte, error) {
	der, err := p.buildResponse(cert)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.staples[fmt.Sprintf("%040X", cert.SerialNumber)] = der
	p.mu.Unlock()
	return der, nil
}

// Staple returns the cached staple DER for a certificate, or nil if the cert
// has not been refreshed (or its status is unknown/expired with no cached
// value). The caller should attach it to tls.Certificate.OCSPStaple.
func (p *StapleProvider) Staple(cert *x509.Certificate) []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.staples[fmt.Sprintf("%040X", cert.SerialNumber)]
}

// Warm pre-computes staples for a set of leaf certificates.
func (p *StapleProvider) Warm(certs []*x509.Certificate) {
	for _, c := range certs {
		if _, err := p.Refresh(c); err != nil {
			slog.Warn("ocsp staple: warm failed", "serial", fmt.Sprintf("%X", c.SerialNumber), "error", err)
		}
	}
}

// Start launches a background refresh loop for the given certificates.
// Close must be called to stop it.
func (p *StapleProvider) Start(interval time.Duration, certs func() []*x509.Certificate) {
	if interval <= 0 {
		interval = time.Hour
	}
	p.once.Do(func() {
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					for _, c := range certs() {
						if _, err := p.Refresh(c); err != nil {
							slog.Warn("ocsp staple: refresh failed", "serial", fmt.Sprintf("%X", c.SerialNumber), "error", err)
						}
					}
				case <-p.stop:
					return
				}
			}
		}()
	})
}

// Close stops the background refresh loop. Safe to call multiple times.
func (p *StapleProvider) Close() {
	p.closeOnce.Do(func() {
		close(p.stop)
	})
}

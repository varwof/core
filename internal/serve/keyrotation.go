// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/varwof/core/internal/ca"
)

// ─────────────────────────────────────────────────────────────────────
// C7: CA master key rotation (dual-signing transition window)
//
// Server keeps a per-CA *ca.RotatingSigner registry. Every issuance path
// goes through rotatingSigner() so a rotation atomically affects all future
// signatures with zero interruption. The management API lets an operator
// inspect rotation state and perform a rotation by supplying the new CA
// certificate + private key (PEM files or inline).
// ─────────────────────────────────────────────────────────────────────

// rotatingSigner returns the RotatingSigner for a CA, creating and caching it
// from the configured cert/key files on first use.
func (s *Server) rotatingSigner(caName string) (*ca.RotatingSigner, error) {
	cfg := s.getConfig()
	caCfg, ok := cfg.CAs[caName]
	if !ok || caCfg.Cert == "" || caCfg.Key == "" {
		return nil, errKeyNotConfigured
	}

	key := "rot:" + caName
	if v, ok := s.rotationMu.Load(key); ok {
		return v.(*ca.RotatingSigner), nil
	}

	cert, signer, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		return nil, fmt.Errorf("load signer for %s: %w", caName, err)
	}
	rs := ca.NewRotatingSigner(cert, signer)
	actual, _ := s.rotationMu.LoadOrStore(key, rs)
	return actual.(*ca.RotatingSigner), nil
}

// rotatingSignerState returns serializable state for the management API.
func (s *Server) rotatingSignerState(caName string) map[string]any {
	rs, err := s.rotatingSigner(caName)
	if err != nil {
		return map[string]any{
			"ca":      caName,
			"error":   err.Error(),
			"rotated": false,
		}
	}
	out := map[string]any{
		"ca":      caName,
		"rotated": false,
	}
	if active := rs.Active(); active != nil && active.Cert != nil {
		c := active.Cert
		out["subject"] = c.Subject.String()
		out["serial"] = fmt.Sprintf("%x", c.SerialNumber)
		out["not_before"] = c.NotBefore.Format(time.RFC3339)
		out["not_after"] = c.NotAfter.Format(time.RFC3339)
		out["expires_in"] = time.Until(c.NotAfter).Round(time.Second).String()
		out["needs_rotation"] = rs.NeedsRotation(7 * 24 * time.Hour)
	}
	if legacy := rs.Legacy(); legacy != nil && legacy.Cert != nil {
		out["legacy_subject"] = legacy.Cert.Subject.String()
		out["legacy_serial"] = fmt.Sprintf("%x", legacy.Cert.SerialNumber)
		out["transition_active"] = true
	}
	return out
}

// apiCARotationInfo handles GET /api/v1/cas/{name}/rotation
func (s *Server) apiCARotationInfo(w http.ResponseWriter, r *http.Request, name string) {
	writeJSON(w, s.rotatingSignerState(name))
}

// apiCARotate handles POST /api/v1/cas/{name}/rotate
//
// Request body (JSON):
//
//	{ "cert_pem": "<new CA certificate PEM>", "key_pem": "<new private key PEM>" }
//	  or
//	{ "cert": "/path/to/new-ca.pem", "key": "/path/to/new-ca.key" }
//
// On success the active signing key is atomically swapped; the previous key is
// retained as legacy for the transition window.
func (s *Server) apiCARotate(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
		Cert    string `json:"cert"`
		Key     string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}

	certPEM := req.CertPEM
	keyPEM := req.KeyPEM
	if certPEM == "" && req.Cert != "" {
		data, err := os.ReadFile(req.Cert)
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.rotate_read_cert", err.Error())
			return
		}
		certPEM = string(data)
	}
	if keyPEM == "" && req.Key != "" {
		data, err := os.ReadFile(req.Key)
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.rotate_read_key", err.Error())
			return
		}
		keyPEM = string(data)
	}
	if certPEM == "" || keyPEM == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_missing", "cert/key required")
		return
	}

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_invalid_cert", "invalid CA certificate PEM")
		return
	}
	newCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_invalid_cert", err.Error())
		return
	}
	if !newCert.IsCA {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_not_ca", "new certificate is not a CA certificate")
		return
	}

	newKey, err := ca.ParsePrivateKey([]byte(keyPEM), "")
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_invalid_key", err.Error())
		return
	}
	signer, ok := newKey.(crypto.Signer)
	if !ok {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_invalid_key", "private key is not a signer")
		return
	}

	rs, err := s.rotatingSigner(name)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.ca_key_not_available", err.Error())
		return
	}

	if !publicKeysEqual(newCert.PublicKey, signer.Public()) {
		s.apiErr(w, r, http.StatusBadRequest, "api.rotate_key_mismatch", "certificate public key does not match private key")
		return
	}

	oldSerial := ""
	if old := rs.Active(); old != nil && old.Cert != nil {
		oldSerial = fmt.Sprintf("%x", old.Cert.SerialNumber)
	}

	rs.Rotate(newCert, signer)

	writeJSON(w, map[string]any{
		"status":     "rotated",
		"ca":         name,
		"old_serial": oldSerial,
		"new_serial": fmt.Sprintf("%x", newCert.SerialNumber),
		"active":     s.rotatingSignerState(name),
	})
}

func publicKeysEqual(a, b any) bool {
	switch apk := a.(type) {
	case *ecdsa.PublicKey:
		bpk, ok := b.(*ecdsa.PublicKey)
		return ok && apk.Equal(bpk)
	case *rsa.PublicKey:
		bpk, ok := b.(*rsa.PublicKey)
		return ok && apk.Equal(bpk)
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// StartCARotationMonitor periodically checks every configured CA's active
// certificate for approaching expiry and logs a warning, so operators rotate
// the CA master key before it lapses (rotation itself is performed via the
// POST /api/v1/ca/{name}/rotate API). Returns a stop function.
func (s *Server) StartCARotationMonitor(interval time.Duration) func() {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	stopCh := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() { close(stopCh) })
	}

	slog.Info("serve: CA rotation monitor started", "interval", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				s.checkCARotations()
			}
		}
	}()
	return stop
}

// checkCARotations inspects every configured CA and logs warnings for those
// approaching expiry or already expired.
func (s *Server) checkCARotations() {
	cfg := s.getConfig()
	for name := range cfg.CAs {
		rs, err := s.rotatingSigner(name)
		if err != nil {
			continue
		}
		if c := rs.Cert(); c != nil && time.Now().After(c.NotAfter) {
			slog.Error("serve: CA master key EXPIRED, issuance will fail",
				"ca", name, "not_after", c.NotAfter.Format(time.RFC3339))
			continue
		}
		if rs.NeedsRotation(7 * 24 * time.Hour) {
			slog.Warn("serve: CA master key approaching expiry, rotate via POST /api/v1/ca/{name}/rotate",
				"ca", name, "not_after", rs.NotAfter().Format(time.RFC3339),
				"days_left", time.Until(rs.NotAfter()).Round(time.Hour).String())
		}
	}
}

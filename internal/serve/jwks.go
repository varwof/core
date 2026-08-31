// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/x509"
	"log/slog"
	"net/http"

	"github.com/varwof/core/internal/ca"
)

// serveJWKS handles GET /.well-known/jwks.json. It exposes the public keys of
// every configured CA as a JWK Key Set (RFC 7517), binding each key's kid to
// the certificate's SPKI hash so X.509 chain verification and AIC-JWT JWS
// verification anchor to the same trust root.
func (s *Server) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	cfg := s.getConfig()
	certs := make([]*x509.Certificate, 0, len(cfg.CAs))
	for name, caCfg := range cfg.CAs {
		if caCfg.Cert == "" {
			continue
		}
		cert, _, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(name, caCfg.Password))
		if err != nil {
			slog.Warn("jwks: skip CA (load failed)", "ca", name, "error", err)
			continue
		}
		certs = append(certs, cert)
	}

	data, err := ca.BuildJWKSJSON(certs)
	if err != nil {
		slog.Error("jwks: build failed", "error", err)
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}
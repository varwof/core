// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/secrets"
	"github.com/varwof/types/aicjwt"
)

const (
	aicJWTIssuer = "varwof-core"
)

// buildAICJWTResolver returns the AIC-JWT provisioner resolver. Issuer keys
// are the configured CAs (kid = certificate SPKI hash), so AIC-JWT and X.509
// verification anchor to the same trust root. Validation runs the full draft
// pipeline (types/aicjwt.Validate). When the request also presents an mTLS
// client certificate, the certificate key must match the token's cnf.jkt
// (RFC 7800) thumbprint — dual-carrier coherence check.
//
// Representative tokens are rejected: they require PrincipalAuthorization
// material the core server does not resolve yet (authorized mode only).
func buildAICJWTResolver(cfg *internal.Config) func(token string, r *http.Request) (*provisioner.AuthResult, error) {
	return func(token string, r *http.Request) (*provisioner.AuthResult, error) {
		keys := caJWTIssuerKeys(cfg)
		if len(keys) == 0 {
			return nil, errors.New("aic-jwt: no configured CA issuers")
		}

		dec, err := aicjwt.Validate(token, aicjwt.VerifyOptions{
			Now:              time.Now(),
			IssuerKeys:       keys,
			ExpectedIssuer:   aicJWTIssuer,
			ExpectedAudience: []string{aicJWTIssuer},
		})
		if err != nil {
			return nil, fmt.Errorf("aic-jwt: validate: %w", err)
		}

		// Re-parse the payload for the claims surfaced to RBAC.
		_, pb, _, err := aicjwt.ParseCompact(token)
		if err != nil {
			return nil, fmt.Errorf("aic-jwt: parse: %w", err)
		}
		var claims aicjwt.OuterClaims
		if err := json.Unmarshal(pb, &claims); err != nil {
			return nil, fmt.Errorf("aic-jwt: payload: %w", err)
		}

		// Dual-carrier coherence: an mTLS certificate presented alongside the
		// token must belong to the token's bound key.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if claims.Cnf == nil || claims.Cnf.Jkt == "" {
				return nil, errors.New("aic-jwt: mTLS + token require cnf.jkt binding")
			}
			certJWK, err := aicjwt.CertToJWK(r.TLS.PeerCertificates[0])
			if err != nil {
				return nil, fmt.Errorf("aic-jwt: peer cert to JWK: %w", err)
			}
			thumb, err := aicjwt.JWKThumbprint(certJWK)
			if err != nil {
				return nil, fmt.Errorf("aic-jwt: peer thumbprint: %w", err)
			}
			if thumb != claims.Cnf.Jkt {
				return nil, errors.New("aic-jwt: mTLS certificate key does not match token cnf.jkt")
			}
		}

		caps := make([]string, 0, len(dec.Capabilities))
		for _, c := range dec.Capabilities {
			if c.ID == "" {
				continue
			}
			caps = append(caps, c.Scheme+":"+c.ID)
		}
		principal := aicjwt.Principal{}
		if claims.Aic != nil {
			principal = claims.Aic.Principal
		}
		return &provisioner.AuthResult{
			AICJWT: &provisioner.AICJWTIdentity{
				Principal:    principal,
				Issuer:       claims.Iss,
				TokenID:      claims.Jti,
				Capabilities: caps,
			},
		}, nil
	}
}

// caJWTIssuerKeys builds the kid → public key map for every configured CA
// (kid = base64url SHA-256 of the certificate SPKI).
func caJWTIssuerKeys(cfg *internal.Config) map[string]crypto.PublicKey {
	keys := make(map[string]crypto.PublicKey)
	for name, caCfg := range cfg.CAs {
		if caCfg.Cert == "" {
			continue
		}
		cert, _, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, secrets.ResolveCAKeyPassword(name, caCfg.Password))
		if err != nil {
			slog.Warn("aic-jwt: skip issuer (load failed)", "ca", name, "error", err)
			continue
		}
		keys[ca.SPKISHA256(cert)] = cert.PublicKey
	}
	return keys
}
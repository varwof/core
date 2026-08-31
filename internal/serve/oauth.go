// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/types/aicjwt"
)

// oauthIssuerID is the OAuth authorization-server identity. It matches the
// AIC-JWT iss/aud defaults used by ca.SignJWT and the L2 AIC-JWT resolver,
// so every carrier anchors to the same trust root.
const oauthIssuerID = "varwof-core"

// oauthTokenTypeX509Cert is the RFC 8693 subject_token_type used when the
// subject credential is an X.509 AIC certificate.
const oauthTokenTypeX509Cert = "urn:ietf:params:oauth:token-type:x509-cert"

// oauthDefaultLifetime is the exchanged-token lifetime when the subject
// certificate carries no requested lifetime (1h).
const oauthDefaultLifetime = 3600 * time.Second

// oauthIssuer builds the reference OAuth Issuer bound to the configured
// default CA (same private key as X.509 issuance and JWKS publication).
func (s *Server) oauthIssuer() (*oauthIssuer, *x509.Certificate, error) {
	cfg := s.getConfig()
	caName := cfg.Defaults.CA
	caCfg, ok := cfg.CAs[caName]
	if !ok || caCfg.Cert == "" {
		return nil, nil, fmt.Errorf("oauth: default CA %q not configured", caName)
	}
	cert, signer, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		return nil, nil, fmt.Errorf("oauth: load default CA: %w", err)
	}
	alg, err := ca.JWSToAlg(cert.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth: derive alg: %w", err)
	}
	return newOAuthIssuer(oauthIssuerID, ca.SPKISHA256(cert), signer, alg, nil), cert, nil
}

// serveOAuthToken handles POST /oauth/token (RFC 6749 §3.2). Supported
// flows (reference layer):
//   - RFC 8693 token exchange: subject_token = x509 AIC certificate
//     (x509→JWT bridge) or a principal AIC-JWT (JWT→JWT).
//   - RFC 7523 JWT bearer: client_assertion = AIC-JWT.
//   - RFC 9068: the issued access token is itself an AIC-JWT carrying cnf.jkt.
//
// Proof of possession for the issued token's cnf binding comes from the
// mTLS client certificate or a DPoP proof (RFC 9449).
func (s *Server) serveOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_request", "malformed form body")
		return
	}

	req := oauthTokenRequest{
		GrantType:           r.Form.Get("grant_type"),
		Code:                r.Form.Get("code"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		ClientID:            r.Form.Get("client_id"),
		ClientAssertion:     r.Form.Get("client_assertion"),
		ClientAssertionType: r.Form.Get("client_assertion_type"),
		SubjectToken:        r.Form.Get("subject_token"),
		SubjectTokenType:    r.Form.Get("subject_token_type"),
		ActorToken:          r.Form.Get("actor_token"),
		ActorTokenType:      r.Form.Get("actor_token_type"),
		Scope:               r.Form.Get("scope"),
		Resource:            r.Form.Get("resource"),
		RequestedActor:      r.Form.Get("requested_actor"),
		CodeVerifier:        r.Form.Get("code_verifier"),
	}
	if req.GrantType == "" {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_request", "grant_type is required")
		return
	}

	// x509 → AIC-JWT exchange: the subject credential is an X.509 AIC
	// certificate; the exchanged token is minted by the same CA via
	// ca.SignJWT (full AIC validation, shared trust root).
	if req.GrantType == GrantTypeTokenExchange &&
		req.SubjectTokenType == oauthTokenTypeX509Cert {
		s.oauthExchangeX509(w, r, req.SubjectToken)
		return
	}

	issuer, caCert, err := s.oauthIssuer()
	if err != nil {
		slog.Error("oauth: issuer", "error", err)
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", "")
		return
	}

	// RFC 7523 JWT bearer: the client authenticates with an AIC-JWT as
	// client_assertion. Core treats the assertion as an AIC-JWT (not a DA
	// JWT), validates it against the CA trust root, then mints a fresh
	// RFC 9068 access token bound to the presented key.
	if req.GrantType == GrantTypeJWTBearer {
		s.oauthJWTBearer(w, r, req, issuer, caCert)
		return
	}

	// The remaining grant types (authorization_code, non-x509 token
	// exchange) are not implemented by core's token endpoint.
	s.apiErr(w, r, http.StatusBadRequest, "oauth.unsupported_grant_type",
		fmt.Sprintf("grant_type %q is not supported", req.GrantType))
	return
}

// oauthJWTBearer implements RFC 7523 JWT-bearer in core's adaptation:
// client_assertion is an AIC-JWT issued by the same CA. It is validated
// with the full draft pipeline against the CA trust root, and a fresh
// RFC 9068 access token is minted bound to the presented PoP key.
func (s *Server) oauthJWTBearer(w http.ResponseWriter, r *http.Request, req oauthTokenRequest, issuer *oauthIssuer, caCert *x509.Certificate) {
	if req.ClientAssertion == "" || req.ClientAssertionType != AssertionTypeJWT {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_request", "client_assertion with type jwt-bearer required")
		return
	}
	agentPub, err := oauthPresenterKey(r)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_request", err.Error())
		return
	}

	dec, err := aicjwt.Validate(req.ClientAssertion, aicjwt.VerifyOptions{
		Now:              time.Now(),
		ExpectedIssuer:   oauthIssuerID,
		ExpectedAudience: []string{oauthIssuerID},
		IssuerKeys:       issuer.IssuerKeys(),
	})
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", fmt.Sprintf("invalid client_assertion: %v", err))
		return
	}

	// Faithfully carry over the assertion's identity claims.
	_, pb, _, err := aicjwt.ParseCompact(req.ClientAssertion)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", "unreadable client_assertion")
		return
	}
	var outer aicjwt.OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", "unreadable client_assertion")
		return
	}
	principal := aicjwtPrincipalFromOuter(outer)
	keyHash := principalKeyHashOf(outer)

	// Mint a fresh access token from the validated assertion's identity.
	res, err := ca.SignJWT(&ca.SignConfig{
		CAKey: issuer.Key, CACert: caCert, SubjectPubKey: agentPub, Validity: time.Hour,
		AIC: &ca.AICConfig{
			AgentId:        oauthAgentIDOf(outer, dec.Actor),
			PrincipalUid:   ca.PrincipalUid{Version: 1, Realm: principal.Realm, Identifier: principal.ID, KeyHash: keyHash},
			DelegationMode: ca.DelegationAuthorized,
			Capabilities:   oauthCapabilitiesOf(dec.Capabilities),
			DelegationAuthorization: &ca.DelegationAuthorization{
				Reason:            ca.Reason{ReasonCode: "ROTATION", Description: "oauth jwt-bearer"},
				Nonce:             make([]byte, 32),
				Timestamp:         time.Now().Add(-time.Minute),
				RequestedLifetime: int(time.Hour.Seconds()),
			},
		},
	}, ca.JWTSignOptions{})
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", fmt.Sprintf("issue access token: %v", err))
		return
	}
	resp := oauthTokenResponse{
		AccessToken: res.Token,
		TokenType:   TokenTypeBearer,
		ExpiresIn:   res.Claims.Exp - res.Claims.Iat,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// oauthAgentIDOf derives the agent id for re-issuance.
func oauthAgentIDOf(outer aicjwt.OuterClaims, actor string) string {
	if outer.Sub != "" {
		return outer.Sub
	}
	if actor != "" {
		return actor
	}
	return "agent"
}

// aicjwtPrincipalFromOuter returns the assertion's AIC principal.
func aicjwtPrincipalFromOuter(o aicjwt.OuterClaims) aicjwt.Principal {
	if o.Aic != nil {
		return o.Aic.Principal
	}
	return aicjwt.Principal{Realm: "r", ID: o.Sub}
}

// principalKeyHashOf decodes the assertion principal's key_hash (base64url)
// into bytes for the core PrincipalUid.
func principalKeyHashOf(o aicjwt.OuterClaims) []byte {
	if o.Aic == nil {
		return nil
	}
	kh, err := base64.RawURLEncoding.DecodeString(o.Aic.Principal.KeyHash)
	if err != nil {
		return nil
	}
	return kh
}

// oauthCapabilitiesOf converts AIC-JWT capabilities to the core ca form.
func oauthCapabilitiesOf(caps []aicjwt.Capability) []ca.Capability {
	out := make([]ca.Capability, 0, len(caps))
	for _, c := range caps {
		out = append(out, ca.Capability{SchemeId: c.Scheme, CapabilityId: c.ID, Parameters: []byte(c.Params)})
	}
	return out
}

// oauthExchangeX509 performs the x509→AIC-JWT token exchange.
func (s *Server) oauthExchangeX509(w http.ResponseWriter, r *http.Request, subjectToken string) {
	issuer, caCert, err := s.oauthIssuer()
	if err != nil {
		slog.Error("oauth: issuer", "error", err)
		s.apiErr(w, r, http.StatusInternalServerError, "api.internal_error", "")
		return
	}

	sc, err := oauthSignConfigFromCert(issuer, caCert, subjectToken)
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", err.Error())
		return
	}

	res, err := ca.SignJWT(sc, ca.JWTSignOptions{})
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "oauth.invalid_grant", err.Error())
		return
	}
	resp := oauthTokenResponse{
		AccessToken: res.Token,
		TokenType:   TokenTypeBearer,
		ExpiresIn:   res.Claims.Exp - res.Claims.Iat,
		Scope:       oauthScopeOf(sc.AIC.Capabilities),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// oauthSignConfigFromCert validates the x509 AIC subject certificate and
// builds the SignConfig that mints its AIC-JWT equivalent.
func oauthSignConfigFromCert(issuer *oauthIssuer, caCert *x509.Certificate, subjectToken string) (*ca.SignConfig, error) {
	block, _ := pem.Decode([]byte(subjectToken))
	if block == nil {
		return nil, errors.New("subject_token is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse subject certificate: %w", err)
	}
	aic, err := ca.ParseAIC(cert)
	if err != nil || aic == nil {
		return nil, errors.New("subject certificate has no AIC extension")
	}

	// The exchanged token must be signed by the same CA that issued the
	// certificate (subject issuer must match the configured default CA).
	if string(cert.RawIssuer) != string(caCert.RawSubject) {
		return nil, errors.New("subject certificate was not issued by the configured default CA")
	}

	da := aic.DelegationAuthorization
	validity := time.Duration(da.RequestedLifetime) * time.Second
	if da.RequestedLifetime < 1 {
		validity = oauthDefaultLifetime
	}

	return &ca.SignConfig{
		CAKey:         issuer.Key,
		CACert:        caCert,
		SubjectPubKey: cert.PublicKey,
		Validity:      validity,
		AIC: &ca.AICConfig{
			AgentId:                 aic.AgentId,
			PrincipalUid:            aic.PrincipalUid,
			DelegationMode:          aic.DelegationMode,
			Capabilities:            aic.Capabilities,
			DelegationAuthorization: &da,
		},
	}, nil
}

// oauthPresenterKey returns the proof-of-possession key for cnf binding:
// the mTLS client certificate, or a verified DPoP presenter key.
func oauthPresenterKey(r *http.Request) (crypto.PublicKey, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].PublicKey, nil
	}
	if dpop := r.Header.Get("DPoP"); dpop != "" {
		pub, err := oauthVerifyDPoP(dpop, "", r.Method, r.URL.String(), time.Now(), oauthNewMemNonceStore())
		if err != nil {
			return nil, fmt.Errorf("invalid DPoP proof: %w", err)
		}
		return pub, nil
	}
	return nil, errors.New("missing proof of possession (mTLS certificate or DPoP proof)")
}

// oauthScopeOf renders capabilities as an OAuth scope string (scheme:id).
func oauthScopeOf(caps []ca.Capability) string {
	parts := make([]string, 0, len(caps))
	for _, c := range caps {
		if c.CapabilityId == "" {
			continue
		}
		parts = append(parts, c.FullID())
	}
	return strings.Join(parts, " ")
}

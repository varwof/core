// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// OAuth protocol reference layer (RFC 7523 / RFC 8693 / RFC 9068 /
// RFC 9449) inlined from the standalone aic-jwt reference
// implementation so core does not depend on that module. The AIC-JWT
// claims/JWS/validation engine stays in types/aicjwt (single source of
// truth); this file only adds the thin OAuth token-endpoint protocol
// surface core needs:
//
//   - Issuer: minimal authorization-server identity (id/kid/alg/key),
//     IssuerKeys() for trust-root publication, and HandleTokenRequest
//     dispatching grant_type.
//   - VerifyDPoP: RFC 9449 proof-of-possession verification.
//   - memNonceStore: replay guard for DPoP proof jti.

package serve

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/types/aicjwt"
)

// OAuth grant and token type identifiers (RFC 6749 §3.2, RFC 7523,
// RFC 8693, RFC 9068).
const (
	GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTypeAuthCode      = "authorization_code"
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	AssertionTypeJWT       = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	TokenTypeAIC           = "urn:ietf:params:oauth:token-type:aic+jwt"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeBearer        = "Bearer"
)

// TokenRequest models the OAuth token endpoint request parameters.
type oauthTokenRequest struct {
	GrantType           string
	Code                string
	RedirectURI         string
	ClientID            string
	ClientAssertion     string
	ClientAssertionType string
	SubjectToken        string
	SubjectTokenType    string
	ActorToken          string
	ActorTokenType      string
	Scope               string
	Resource            string
	RequestedActor      string
	CodeVerifier        string
}

// oauthTokenResponse models the token endpoint response (RFC 6749 §5.1).
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// oauthIssuer is a minimal authorization-server identity bound to a CA
// signing key. kid identifies the key in the same way core publishes it
// (base64url SHA-256 of the certificate SPKI).
type oauthIssuer struct {
	ID  string
	Key crypto.Signer
	Kid string
	Alg string
}

// newOAuthIssuer builds an issuer identity.
func newOAuthIssuer(id, kid string, key crypto.Signer, alg string, _ map[string]crypto.PublicKey) *oauthIssuer {
	return &oauthIssuer{ID: id, Key: key, Kid: kid, Alg: alg}
}

// IssuerKeys returns the issuer's public key under its kid.
func (is *oauthIssuer) IssuerKeys() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{is.Kid: is.Key.Public()}
}

// oauthDPoPClaims is the RFC 9449 proof payload.
type oauthDPoPClaims struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Ath string `json:"ath,omitempty"`
}

// oauthVerifyDPoP verifies an RFC 9449 DPoP proof bound to htm/htu and
// (optionally) the access token via ath. Returns the presenter key.
func oauthVerifyDPoP(proof, accessToken, htm, htu string, now time.Time, replay aicjwt.NonceStore) (crypto.PublicKey, error) {
	hb, pb, _, err := aicjwt.ParseCompact(proof)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	var hdr aicjwt.Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("dpop: header malformed")
	}
	if hdr.JWK == nil {
		return nil, fmt.Errorf("dpop: header jwk required")
	}
	pub, err := aicjwt.JWKToPublic(*hdr.JWK)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if err := aicjwt.VerifyCompact(proof, hdr.Alg, pub); err != nil {
		return nil, fmt.Errorf("dpop: signature invalid: %w", err)
	}
	var c oauthDPoPClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("dpop: payload malformed")
	}
	if c.Htm != htm {
		return nil, fmt.Errorf("dpop: htm mismatch")
	}
	if c.Htu != htu {
		return nil, fmt.Errorf("dpop: htu mismatch")
	}
	if c.Ath != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != c.Ath {
			return nil, fmt.Errorf("dpop: ath mismatch")
		}
	}
	if now.Sub(time.Unix(c.Iat, 0)) > 5*time.Minute || time.Unix(c.Iat, 0).Sub(now) > 5*time.Minute {
		return nil, fmt.Errorf("dpop: iat outside freshness window")
	}
	if replay != nil {
		if err := replay.CheckAndAdd(c.Jti); err != nil {
			return nil, fmt.Errorf("dpop: proof replay: %w", err)
		}
	}
	return pub, nil
}

// memNonceStore is an in-memory replay guard (used by oauthPresenterKey
// for DPoP proofs).
type memNonceStore struct {
	m map[string]bool
}

// CheckAndAdd records the nonce; a repeated nonce is rejected.
func (s *memNonceStore) CheckAndAdd(nonce string) error {
	if s.m == nil {
		s.m = map[string]bool{}
	}
	if s.m[nonce] {
		return &aicjwt.NonceReuseError{Nonce: nonce}
	}
	s.m[nonce] = true
	return nil
}

// oauthNewMemNonceStore returns a fresh in-memory nonce store.
func oauthNewMemNonceStore() aicjwt.NonceStore {
	return &memNonceStore{m: map[string]bool{}}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// OIDCName is the built-in OIDC provisioner name.
	OIDCName = "oidc"

	// clockLeeway absorbs small clock skew between this server and the OIDC
	// provider when checking exp/nbf (RFC 7519 §4.1.4/4.1.5).
	clockLeeway = 5 * time.Minute
)

// OIDCConfig configures the OIDC provisioner.
type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	JWKSEndpoint string `json:"jwks_endpoint,omitempty"` // defaults to IssuerURL + "/.well-known/jwks.json"
	ClaimMapping struct {
		Subject string `json:"subject,omitempty"` // JWT claim to use as username (default "email")
		Role    string `json:"role,omitempty"`    // JWT claim to use as role (default "sub")
	} `json:"claim_mapping,omitempty"`
	RoleOverride string `json:"role_override,omitempty"` // static role if set (e.g. "operator")
}

// OIDCProvisioner validates JWT tokens from an OIDC provider.
type OIDCProvisioner struct {
	config     OIDCConfig
	mu         sync.RWMutex
	jwksCache  *jwksCache
	httpClient *http.Client
}

// NewOIDCProvisioner creates an OIDC provisioner.
func NewOIDCProvisioner(cfg OIDCConfig) *OIDCProvisioner {
	if cfg.ClaimMapping.Subject == "" {
		cfg.ClaimMapping.Subject = "email"
	}
	jwksURL := cfg.JWKSEndpoint
	if jwksURL == "" {
		jwksURL = strings.TrimRight(cfg.IssuerURL, "/") + "/.well-known/jwks.json"
	}
	return &OIDCProvisioner{
		config:     cfg,
		jwksCache:  &jwksCache{url: jwksURL, ttl: 5 * time.Minute},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *OIDCProvisioner) Name() string { return OIDCName }
func (p *OIDCProvisioner) Type() string { return "oidc" }

func (p *OIDCProvisioner) Authenticate(r *http.Request) (*AuthResult, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return nil, nil
	}

	claims, err := p.verifyJWT(token)
	if err != nil {
		return nil, nil
	}

	subject := claimValue(claims, p.config.ClaimMapping.Subject)
	if subject == "" {
		return nil, nil
	}

	role := p.config.RoleOverride
	if role == "" {
		role = claimValue(claims, p.config.ClaimMapping.Role)
	}
	if role == "" {
		role = "read"
	}

	subClaim := claimValue(claims, "sub")
	username := subject
	if username == "" {
		username = subClaim
	}

	return &AuthResult{
		Username:    username,
		Role:        role,
		Permissions: rolePerms(role),
	}, nil
}

// ---- JWT verification (stdlib only) ----

type jwksCache struct {
	url       string
	ttl       time.Duration
	mu        sync.RWMutex
	keys      []jwkKey
	expiresAt time.Time
}

type jwkKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Use string   `json:"use"`
	X5c []string `json:"x5c,omitempty"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

func (c *jwksCache) get(httpClient *http.Client) ([]jwkKey, error) {
	c.mu.RLock()
	if len(c.keys) > 0 && time.Now().Before(c.expiresAt) {
		keys := c.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if len(c.keys) > 0 && time.Now().Before(c.expiresAt) {
		return c.keys, nil
	}

	resp, err := httpClient.Get(c.url)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	c.keys = jwks.Keys
	c.expiresAt = time.Now().Add(c.ttl)
	return c.keys, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func (p *OIDCProvisioner) verifyJWT(raw string) (map[string]interface{}, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT: not 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}
	if hdr.Alg == "" || hdr.Alg == "none" {
		return nil, errors.New("JWT algorithm not allowed")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	// Verify expiration (required — fail closed on missing exp)
	exp, hasExp := claims["exp"]
	if !hasExp {
		return nil, errors.New("JWT missing exp")
	}
	var expFloat float64
	switch v := exp.(type) {
	case float64:
		expFloat = v
	case int64:
		expFloat = float64(v)
	case int:
		expFloat = float64(v)
	case json.Number:
		expFloat, _ = v.Float64()
	}
	if expFloat <= 0 || time.Now().After(time.Unix(int64(expFloat), 0).Add(clockLeeway)) {
		return nil, errors.New("JWT expired or invalid exp")
	}

	// Verify not-before (optional but enforced when present, with leeway).
	if nbf, ok := claims["nbf"]; ok {
		var nbfFloat float64
		switch v := nbf.(type) {
		case float64:
			nbfFloat = v
		case int64:
			nbfFloat = float64(v)
		case int:
			nbfFloat = float64(v)
		case json.Number:
			nbfFloat, _ = v.Float64()
		}
		if nbfFloat > 0 && time.Now().Add(clockLeeway).Before(time.Unix(int64(nbfFloat), 0)) {
			return nil, errors.New("JWT not yet valid (nbf in the future)")
		}
	}

	// Verify issuer (required — fail closed on missing issuer)
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" || iss != p.config.IssuerURL {
		return nil, fmt.Errorf("JWT issuer %q does not match %q", iss, p.config.IssuerURL)
	}

	// Verify audience — M22 fix: fail-closed when aud is missing or client_id is unconfigured.
	clientID := p.config.ClientID
	if clientID == "" {
		return nil, fmt.Errorf("OIDC client_id not configured — cannot verify audience (fail-closed)")
	}
	aud, ok := claims["aud"]
	if !ok {
		return nil, fmt.Errorf("JWT missing audience claim — refusing to authenticate (fail-closed)")
	}
	switch v := aud.(type) {
	case string:
		if v != clientID {
			return nil, fmt.Errorf("JWT audience %q does not match client_id %q", v, clientID)
		}
	case []interface{}:
		found := false
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("JWT audience does not include client_id %q", clientID)
		}
	default:
		return nil, fmt.Errorf("JWT audience has unexpected type %T", aud)
	}

	// Find matching JWK key — fail closed if JWKS unavailable.
	keys, err := p.jwksCache.get(p.httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	var matchedKey *jwkKey
	for _, k := range keys {
		if k.Kid == hdr.Kid {
			matchedKey = &k
			break
		}
	}
	if matchedKey == nil {
		// Fail closed: never accept a token whose kid has no matching JWK.
		return nil, fmt.Errorf("no JWK matching kid %q", hdr.Kid)
	}

	// Verify signature — the JWT alg must come from an allowlist AND be
	// consistent with the selected JWK key type/curve (RFC 7515 §4.1.1,
	// RFC 7518 §3). Never derive the algorithm from the unverified header alone.
	hash, ecAlg, err := expectedHash(hdr.Alg, matchedKey)
	if err != nil {
		return nil, err
	}

	signingInput := parts[0] + "." + parts[1]
	switch matchedKey.Kty {
	case "RSA":
		if err := verifyRSASignature(signingInput, sigBytes, matchedKey, hash); err != nil {
			return nil, fmt.Errorf("RSA signature verification: %w", err)
		}
	case "EC":
		if hdr.Alg != ecAlg {
			return nil, fmt.Errorf("JWT alg %q does not match EC curve %q", hdr.Alg, matchedKey.Crv)
		}
		if err := verifyECDSASignature(signingInput, sigBytes, matchedKey, hash); err != nil {
			return nil, fmt.Errorf("ECDSA signature verification: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q — only RSA and EC are accepted", matchedKey.Kty)
	}

	return claims, nil
}

// expectedHash validates that alg is on the allowlist and is algorithmically
// consistent with the resolved JWK key type/curve (RFC 7515 §4.1.1, RFC 7518
// §3.1 / §3.4). On success it returns the hash to use and, for EC keys, the
// algorithm string matched to the curve. Any mismatch is rejected.
func expectedHash(alg string, key *jwkKey) (crypto.Hash, string, error) {
	switch key.Kty {
	case "RSA":
		if alg != "RS256" {
			return 0, "", fmt.Errorf("JWT alg %q not allowed for RSA key (expect RS256)", alg)
		}
		return crypto.SHA256, "", nil
	case "EC":
		switch alg {
		case "ES256":
			if key.Crv != "P-256" {
				return 0, "", fmt.Errorf("JWT alg ES256 does not match EC curve %q", key.Crv)
			}
			return crypto.SHA256, "ES256", nil
		case "ES384":
			if key.Crv != "P-384" {
				return 0, "", fmt.Errorf("JWT alg ES384 does not match EC curve %q", key.Crv)
			}
			return crypto.SHA384, "ES384", nil
		case "ES512":
			if key.Crv != "P-521" {
				return 0, "", fmt.Errorf("JWT alg ES512 does not match EC curve %q", key.Crv)
			}
			return crypto.SHA512, "ES512", nil
		default:
			return 0, "", fmt.Errorf("JWT alg %q not allowed for EC key (expect ES256/ES384/ES512)", alg)
		}
	default:
		return 0, "", fmt.Errorf("unsupported JWK key type %q", key.Kty)
	}
}

func verifyRSASignature(signingInput string, sig []byte, key *jwkKey, hash crypto.Hash) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("decode RSA e: %w", err)
	}
	e := int(binary.BigEndian.Uint32(append(make([]byte, 4-len(eBytes)), eBytes...)))

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	d := hash.New()
	d.Write([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, hash, d.Sum(nil), sig)
}

func verifyECDSASignature(signingInput string, sig []byte, key *jwkKey, hash crypto.Hash) error {
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return fmt.Errorf("decode EC y: %w", err)
	}

	var curve elliptic.Curve
	var sigSize int
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
		sigSize = 32
	case "P-384":
		curve = elliptic.P384()
		sigSize = 48
	case "P-521":
		curve = elliptic.P521()
		sigSize = 66
	default:
		return fmt.Errorf("unsupported EC curve: %s", key.Crv)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// JOSE ECDSA signatures are raw fixed-width R||S (RFC 7518 §3.4), each
	// exactly the curve's coordinate size in octets. Reject malformed lengths.
	if len(sig) != 2*sigSize {
		return fmt.Errorf("ECDSA signature length %d does not match curve %s (expect %d)", len(sig), key.Crv, 2*sigSize)
	}

	d := hash.New()
	d.Write([]byte(signingInput))
	digest := d.Sum(nil)

	r := new(big.Int).SetBytes(sig[:sigSize])
	s := new(big.Int).SetBytes(sig[sigSize:])

	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("ECDSA signature invalid")
	}
	return nil
}

func claimValue(claims map[string]interface{}, path string) string {
	if path == "" {
		return ""
	}
	if v, ok := claims[path]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

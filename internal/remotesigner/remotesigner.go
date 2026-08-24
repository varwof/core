// Package remotesigner provides a crypto.Signer that delegates signing
// to a remote pki-hsm-proxy instance over HTTP.
package remotesigner

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// RemoteSigner implements crypto.Signer by delegating to a pki-hsm-proxy endpoint.
type RemoteSigner struct {
	endpoint string // e.g. "https://127.0.0.1:8445"
	keyAlias string // key alias on the HSM
	pub      crypto.PublicKey
	client   *http.Client
}

// Config configures a RemoteSigner.
type Config struct {
	Endpoint  string // HSM proxy URL (e.g. "https://127.0.0.1:8445")
	KeyAlias  string // key alias on the HSM
	TLSCert   string // client TLS cert for mTLS
	TLSKey    string // client TLS key for mTLS
	CACert    string // CA cert to verify remote signer TLS certificate (Tier 3)
	AuthToken string // Bearer token for API auth
}

// New creates a RemoteSigner and fetches the public key from the HSM proxy.
func New(cfg Config) (*RemoteSigner, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}
	if cfg.KeyAlias == "" {
		return nil, fmt.Errorf("key_alias is required")
	}
	// H13 fix: reject non-HTTPS endpoints — Bearer token and signing digest
	// would be transmitted in cleartext, enabling MITM attacks.
	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		return nil, fmt.Errorf("endpoint must use https:// (got %q) — plaintext signing requests are not allowed", cfg.Endpoint)
	}

	// Build HTTP client (with optional mTLS)
	transport := &http.Transport{}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.CACert != "" {
		caPEM, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid PEM in CA cert file")
		}
		tlsCfg.RootCAs = pool
	}
	transport.TLSClientConfig = tlsCfg

	rs := &RemoteSigner{
		endpoint: cfg.Endpoint,
		keyAlias: cfg.KeyAlias,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}

	// Set auth header helper
	rs.client.Transport = &authTransport{
		inner:     transport,
		authToken: cfg.AuthToken,
	}

	// Fetch public key from HSM proxy
	if err := rs.fetchPublicKey(); err != nil {
		return nil, fmt.Errorf("fetch public key: %w", err)
	}

	return rs, nil
}

// authTransport adds Bearer token to requests.
type authTransport struct {
	inner     http.RoundTripper
	authToken string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.authToken)
	}
	return t.inner.RoundTrip(req)
}

// fetchPublicKey retrieves the public key from the HSM proxy.
func (s *RemoteSigner) fetchPublicKey() error {
	resp, err := s.client.Get(s.endpoint + "/v1/pubkey?alias=" + url.QueryEscape(s.keyAlias))
	if err != nil {
		return fmt.Errorf("GET pubkey: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET pubkey: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	pemData, err := base64.StdEncoding.DecodeString(result.PublicKey)
	if err != nil {
		return fmt.Errorf("decode pubkey base64: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("no PEM block in pubkey response")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse pubkey: %w", err)
	}
	s.pub = pub
	return nil
}

// Public returns the public key.
func (s *RemoteSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest by delegating to the HSM proxy.
func (s *RemoteSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"key_alias": s.keyAlias,
		"hash":      base64.StdEncoding.EncodeToString(digest),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := s.client.Post(s.endpoint+"/v1/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("POST sign: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature base64: %w", err)
	}
	return sig, nil
}

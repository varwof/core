package tsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// RuntimeConfig holds the TSA signing configuration in a hot-swappable container.
// The handler reads from the atomic pointer on every request; the renewal loop
// writes a new config when the signer certificate is renewed.
type RuntimeConfig struct {
	inner atomic.Pointer[TSAConfig]
}

// NewRuntimeConfig creates a RuntimeConfig from an initial TSAConfig.
func NewRuntimeConfig(cfg *TSAConfig) *RuntimeConfig {
	rc := &RuntimeConfig{}
	rc.inner.Store(cfg)
	return rc
}

// Load returns the current TSAConfig. Never returns nil after construction.
func (rc *RuntimeConfig) Load() *TSAConfig {
	if rc == nil {
		return &TSAConfig{}
	}
	return rc.inner.Load()
}

// Store atomically replaces the current TSAConfig.
func (rc *RuntimeConfig) Store(cfg *TSAConfig) {
	rc.inner.Store(cfg)
}

// SignerCertInfo returns metadata about the current signer certificate.
type SignerCertInfo struct {
	SerialNumber string `json:"serial_number"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	HasChain     bool   `json:"has_chain"`
}

// CertInfo returns metadata about the current signer certificate.
func (rc *RuntimeConfig) CertInfo() *SignerCertInfo {
	if rc == nil {
		return nil
	}
	cfg := rc.Load()
	if cfg == nil || cfg.SignerCert == nil {
		return nil
	}
	c := cfg.SignerCert
	return &SignerCertInfo{
		SerialNumber: c.SerialNumber.String(),
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		NotBefore:    c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     c.NotAfter.UTC().Format(time.RFC3339),
		HasChain:     len(cfg.Chain) > 0,
	}
}

// RenewalConfig controls the automatic signer certificate renewal loop.
type RenewalConfig struct {
	// CoreURL is the Varwof Core API base URL (e.g., "https://pki.example.com").
	CoreURL string
	// CertFile is the path to the current signer certificate PEM.
	CertFile string
	// KeyFile is the path to the current signer private key PEM.
	KeyFile string
	// CACertFile is the CA certificate for mTLS to Varwof Core.
	CACertFile string
	// CAName is the CA name to issue from (e.g., "tsa").
	CAName string
	// ValidityDays is the validity period for new certificates.
	ValidityDays int
	// RenewalWindow is how far before expiry to trigger renewal.
	RenewalWindow time.Duration
	// CheckInterval is how often to check for renewal need.
	CheckInterval time.Duration
	// TLSClientCert is the mTLS client certificate for API calls.
	TLSClientCert string
	// TLSClientKey is the mTLS client key for API calls.
	TLSClientKey string
}

// SignerRenewLoop periodically checks the TSA signer certificate and renews
// it via the Varwof Core API before expiry. It atomically swaps the new cert/key
// into the RuntimeConfig without interrupting service.
//
// The loop stops when stopCh is closed.
func SignerRenewLoop(rc *RuntimeConfig, renewCfg *RenewalConfig, stopCh <-chan struct{}) {
	if renewCfg == nil || renewCfg.CoreURL == "" {
		slog.Warn("tsa: renewal loop not started: no core_url configured")
		return
	}
	if renewCfg.CheckInterval <= 0 {
		renewCfg.CheckInterval = 30 * time.Second
	}
	if renewCfg.RenewalWindow <= 0 {
		renewCfg.RenewalWindow = 2 * time.Hour
	}
	if renewCfg.ValidityDays <= 0 {
		renewCfg.ValidityDays = 365
	}

	slog.Info("tsa: renewal loop started",
		"core_url", renewCfg.CoreURL,
		"check_interval", renewCfg.CheckInterval,
		"renewal_window", renewCfg.RenewalWindow)

	ticker := time.NewTicker(renewCfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			slog.Info("tsa: renewal loop stopped")
			return
		case <-ticker.C:
			cfg := rc.Load()
			if cfg == nil || cfg.SignerCert == nil {
				continue
			}
			if !NeedsRenewal(cfg.SignerCert, renewCfg.RenewalWindow) {
				continue
			}
			slog.Info("tsa: signer cert approaching expiry, renewing",
				"not_after", cfg.SignerCert.NotAfter.Format(time.RFC3339))

			if err := renewSignerCert(rc, renewCfg); err != nil {
				slog.Error("tsa: renewal failed", "error", err)
				continue
			}
			slog.Info("tsa: signer cert renewed successfully")
		}
	}
}

// NeedsRenewal returns true if the certificate expires within the window.
func NeedsRenewal(cert *x509.Certificate, window time.Duration) bool {
	if cert == nil {
		return true
	}
	return time.Now().Add(window).After(cert.NotAfter)
}

// renewSignerCert issues a new signer certificate via the Varwof Core API,
// updates the on-disk files, and atomically swaps the RuntimeConfig.
func renewSignerCert(rc *RuntimeConfig, renewCfg *RenewalConfig) error {
	currentCfg := rc.Load()
	if currentCfg == nil || currentCfg.SignerCert == nil {
		return fmt.Errorf("no current signer cert")
	}

	// Generate new key pair
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Build CSR for the API
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   currentCfg.SignerCert.Subject.CommonName,
			Organization: currentCfg.SignerCert.Subject.Organization,
		},
		PublicKey: newKey.Public(),
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, newKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	// Call Varwof Core API
	certPEM, chainPEM, err := issueCertViaAPI(renewCfg, csrDER, currentCfg.SignerCert.Subject.CommonName)
	if err != nil {
		return fmt.Errorf("issue via API: %w", err)
	}

	// Parse new cert
	newCertBlock, _ := pem.Decode([]byte(certPEM))
	if newCertBlock == nil {
		return fmt.Errorf("no PEM in API response cert")
	}
	newCert, err := x509.ParseCertificate(newCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse new cert: %w", err)
	}

	// Parse chain
	var chain []*x509.Certificate
	if chainPEM != "" {
		chain = ParseChainPEM(chainPEM)
	}

	// Write new cert to disk
	if err := os.WriteFile(renewCfg.CertFile, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write new key to disk
	keyDER, err := x509.MarshalECPrivateKey(newKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(renewCfg.KeyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	// Atomic swap
	rc.Store(&TSAConfig{
		SignerCert: newCert,
		SignerKey:  newKey,
		Chain:      chain,
		TSTInfo:    currentCfg.TSTInfo,
	})

	return nil
}

// issueCertViaAPI calls POST /api/v1/certs to issue a new certificate.
func issueCertViaAPI(renewCfg *RenewalConfig, csrDER []byte, cn string) (certPEM, chainPEM string, err error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	payload := map[string]interface{}{
		"ca":       renewCfg.CAName,
		"cn":       cn,
		"csr_pem":  string(csrPEM),
		"validity": renewCfg.ValidityDays,
		"profile":  "timestamp",
	}
	body, _ := json.Marshal(payload)

	var client *http.Client
	if renewCfg.TLSClientCert != "" && renewCfg.TLSClientKey != "" {
		cert, tlsErr := tls.LoadX509KeyPair(renewCfg.TLSClientCert, renewCfg.TLSClientKey)
		if tlsErr != nil {
			return "", "", fmt.Errorf("load TLS client cert: %w", tlsErr)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if renewCfg.CACertFile != "" {
			caCert, caErr := loadCACertFile(renewCfg.CACertFile)
			if caErr == nil {
				pool := x509.NewCertPool()
				pool.AddCert(caCert)
				tlsCfg.RootCAs = pool
			}
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 30 * time.Second}
	} else {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	url := renewCfg.CoreURL + "/api/v1/certs"
	req, reqErr := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if reqErr != nil {
		return "", "", fmt.Errorf("create request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		CertPEM  string `json:"cert_pem"`
		ChainPEM string `json:"chain_pem,omitempty"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	return result.CertPEM, result.ChainPEM, nil
}

// ParseChainPEM parses a PEM-encoded certificate chain.
func ParseChainPEM(pemData string) []*x509.Certificate {
	var chain []*x509.Certificate
	data := []byte(pemData)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				chain = append(chain, cert)
			}
		}
		data = rest
	}
	return chain
}

// loadCACertFile loads a CA certificate from a PEM file.
func loadCACertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Compile-time check that crypto imports are used.
var _ = crypto.SHA256

// ForceRenewSignerCert triggers an immediate signer certificate renewal
// regardless of expiry. Used by the management API (POST /tsa/cert/renew).
func ForceRenewSignerCert(rc *RuntimeConfig, renewCfg *RenewalConfig) error {
	return renewSignerCert(rc, renewCfg)
}

// RotateSignerCert issues a brand-new signer certificate with a fresh key pair
// and atomically swaps it in. Used by the management API (POST /tsa/cert/rotate).
func RotateSignerCert(rc *RuntimeConfig, renewCfg *RenewalConfig) error {
	return renewSignerCert(rc, renewCfg)
}

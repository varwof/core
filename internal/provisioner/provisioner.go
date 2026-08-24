// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package provisioner implements the Provisioner + SignOption pattern
// inspired by step-ca. Each Provisioner authenticates a request and
// returns SignOptions that control certificate issuance parameters.
//
// Adding a new authentication method = adding a new Provisioner implementation.
package provisioner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/varwof/core/internal/ca"
)

// SignOption modifies or validates a SignConfig before signing.
// Inspired by step-ca's SignOption interface (CertificateModifier/Validator/Enforcer).
type SignOption interface {
	Apply(sc *ca.SignConfig) error
}

// SignOptionFunc is a function adapter for SignOption.
type SignOptionFunc func(sc *ca.SignConfig) error

func (f SignOptionFunc) Apply(sc *ca.SignConfig) error {
	return f(sc)
}

// AuthResult is returned by Provisioner.Authenticate().
type AuthResult struct {
	Username    string
	Role        string
	Permissions []string // grant patterns (e.g. "ca:*", "cert:issue")
	Options     []SignOption
	// CertIdentity records the client certificate identity snapshot bound to this authentication.
	// nil means no certificate (e.g. token/Basic login). Sourced from the same origin as mTLS
	// direct connection, ensuring Web sessions and certificate identity are not disconnected.
	CertIdentity *CertIdentity
}

// CertIdentity is a session-bound client certificate identity snapshot for Web user detection and audit display.
type CertIdentity struct {
	Serial       string    // Certificate serial number (%040X hex)
	Issuer       string    // Issuer DN
	CN           string    // Subject CN
	SpkiHash     string    // SHA-256(SubjectPublicKeyInfo) hex
	PrincipalUid string    // AIC PrincipalUid (empty for non-AIC certificates)
	AgentId      string    // AIC AgentId (empty for non-AIC certificates)
	NotAfter     time.Time // Certificate expiry time
}

// NewCertIdentityFromCert extracts an identity snapshot from a client certificate,
// populating principal/agent_id when the AIC extension is present.
func NewCertIdentityFromCert(cert *x509.Certificate) *CertIdentity {
	if cert == nil {
		return nil
	}
	id := &CertIdentity{
		Serial:   fmt.Sprintf("%040X", cert.SerialNumber),
		Issuer:   cert.Issuer.String(),
		CN:       cert.Subject.CommonName,
		SpkiHash: CertSpkiHash(cert),
		NotAfter: cert.NotAfter,
	}
	if aic, err := ca.ParseAIC(cert); err == nil && aic != nil {
		id.PrincipalUid = aic.PrincipalUid.String()
		id.AgentId = aic.AgentId
	}
	return id
}

// CertSpkiHash computes the certificate public key fingerprint (SHA-256 of SubjectPublicKeyInfo, hex).
func CertSpkiHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Provisioner authenticates an HTTP request and returns signing options.
type Provisioner interface {
	Name() string
	Type() string
	Authenticate(r *http.Request) (*AuthResult, error)
}

// Registry holds all registered provisioners.
type Registry struct {
	mu    sync.RWMutex
	items map[string]Provisioner
}

func NewRegistry() *Registry {
	return &Registry{items: make(map[string]Provisioner)}
}

func (r *Registry) Register(p Provisioner) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if name == "" {
		return ErrInvalidName
	}
	if _, exists := r.items[name]; exists {
		return ErrDuplicate
	}
	r.items[name] = p
	return nil
}

func (r *Registry) Find(name string) (Provisioner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.items[name]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.items))
	for n := range r.items {
		names = append(names, n)
	}
	return names
}

func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}

// Authenticate tries each provisioner in insertion order.
// Returns the first non-nil result, or nil if none match.
func (r *Registry) Authenticate(req *http.Request) (*AuthResult, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.items {
		result, err := p.Authenticate(req)
		if err != nil {
			continue
		}
		if result != nil {
			return result, p.Name(), nil
		}
	}
	return nil, "", nil
}

// ---- errors ----

type provisionerError string

func (e provisionerError) Error() string { return string(e) }

const (
	ErrInvalidName = provisionerError("provisioner: invalid name")
	ErrDuplicate   = provisionerError("provisioner: duplicate name")
	ErrNotFound    = provisionerError("provisioner: not found")
)

// ---- utility: parse mTLS cert from request ----

func PeerCertFromRequest(r *http.Request) *x509.Certificate {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	return nil
}

// ---- utility: PEM to cert ----

func PEMToCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrNotFound
	}
	return x509.ParseCertificate(block.Bytes)
}

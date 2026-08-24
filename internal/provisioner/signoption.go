package provisioner

import (
	"fmt"
	"time"

	"github.com/varwof/core/internal/ca"
)

// ---- Built-in SignOption implementations ----

// ProfileOption sets the certificate profile and applies profile-specific config.
// This replaces the direct switch on sc.Profile in applyProfile().
type ProfileOption struct {
	Profile ca.Profile
}

func (o *ProfileOption) Apply(sc *ca.SignConfig) error {
	sc.Profile = o.Profile
	return nil
}

// ValidityOption sets the certificate validity duration.
type ValidityOption struct {
	Validity int // in hours; 0 means use default
}

func (o *ValidityOption) Apply(sc *ca.SignConfig) error {
	if o.Validity > 0 {
		sc.Validity = time.Duration(o.Validity) * time.Hour
	}
	return nil
}

// SANOption adds Subject Alternative Names to the SignConfig.
type SANOption struct {
	DNSNames []string
	IPs      []string
	URIs     []string
	Emails   []string
}

func (o *SANOption) Apply(sc *ca.SignConfig) error {
	var sans []string
	for _, d := range o.DNSNames {
		sans = append(sans, "DNS:"+d)
	}
	for _, ip := range o.IPs {
		sans = append(sans, "IP:"+ip)
	}
	for _, u := range o.URIs {
		sans = append(sans, "URI:"+u)
	}
	for _, e := range o.Emails {
		sans = append(sans, "email:"+e)
	}
	if len(sans) > 0 {
		sc.SANs = append(sc.SANs, sans...)
	}
	return nil
}

// AICOption adds Agent Identity Certificate configuration.
type AICOption struct {
	Config ca.AICConfig
}

func (o *AICOption) Apply(sc *ca.SignConfig) error {
	sc.AIC = &o.Config
	return nil
}

// PrincipalAuthOption adds PrincipalAuthorization configuration.
type PrincipalAuthOption struct {
	Config ca.PrincipalAuthorizationConfig
}

func (o *PrincipalAuthOption) Apply(sc *ca.SignConfig) error {
	sc.PrincipalAuthorization = &o.Config
	return nil
}

// KeyTypeOption sets the key type for certificate issuance.
type KeyTypeOption struct {
	KeyType string
}

func (o *KeyTypeOption) Apply(sc *ca.SignConfig) error {
	sc.KeyType = o.KeyType
	return nil
}

// ---- Composite option ----

// CompositeOption applies multiple SignOptions in sequence.
type CompositeOption struct {
	Options []SignOption
}

func (o *CompositeOption) Apply(sc *ca.SignConfig) error {
	for _, opt := range o.Options {
		if err := opt.Apply(sc); err != nil {
			return fmt.Errorf("composite option: %w", err)
		}
	}
	return nil
}

// ---- Function-based option ----

// SignOptionFromFunc wraps a function as a SignOption.
func SignOptionFromFunc(fn func(sc *ca.SignConfig) error) SignOption {
	return SignOptionFunc(fn)
}

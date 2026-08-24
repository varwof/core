// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// ── v1.5 PrincipalAuthorization (aligned with draft-02 §8 + spec v1.5) ──
//
// PrincipalAuthorization replaces the legacy UserPermission (draft-02 global rename).

// MaxGrantEntries is the maximum number of entries in PrincipalAuthorization.grants (spec P1-A-24).
const MaxGrantEntries = 256

// DelegationModeEnum defines the delegation mode enumeration (draft-02 §8 DelegationModeEnum).
type DelegationModeEnum int

const (
	DelegationModeAuthorizedOnly        DelegationModeEnum = 0
	DelegationModeRepresentativeAllowed DelegationModeEnum = 1
)

// DelegationPolicy controls how a principal delegates permissions to an Agent (v1.7.1 spec §DelegationPolicy).
type DelegationPolicy struct {
	Version         int `json:"version,omitempty" asn1:"default:1"`
	MaxAgents       int `json:"max_agents,omitempty" asn1:"default:1"`
	AllowedMode     int `json:"allowed_mode,omitempty" asn1:"enum,default:0"`
	MaxSessionHours int `json:"max_session_hours,omitempty" asn1:"optional,omitempty,explicit,tag:0"`
}

// PrincipalAuthorization corresponds to the subject authorization statement in X.509v3 extensions (OID 1.3.6.1.4.1.66257.1.2).
// ASN.1 (v1.7.1): version, grants, authorizationConstraints [0],
// delegationPolicy [1], extensions [2].
type PrincipalAuthorization struct {
	Version                  int              `asn1:"default:1"`
	Grants                   []Capability     `asn1:"optional,omitempty"`
	AuthorizationConstraints []Capability     `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
	DelegationPolicy         DelegationPolicy `asn1:"optional,explicit,tag:1"`
	Extensions               []ExtField       `asn1:"optional,omitempty,contextspecific,explicit,tag:2"`
}

// PrincipalAuthorizationConfig is the configuration needed to issue a PrincipalAuthorization extension.
type PrincipalAuthorizationConfig struct {
	Grants           []Capability      `json:"grants,omitempty"`
	DelegationPolicy *DelegationPolicy `json:"delegation_policy,omitempty"`
}

// validatePA validates PrincipalAuthorization field constraints (grants≤256, spec P1-A-24).
func validatePA(grants []Capability) error {
	if len(grants) > MaxGrantEntries {
		return fmt.Errorf("principal_authorization: grants count %d exceeds max %d", len(grants), MaxGrantEntries)
	}
	for i, g := range grants {
		if len(g.SchemeId) < 1 || len(g.SchemeId) > 128 {
			return fmt.Errorf("principal_authorization: grant[%d].schemeId length %d: must be 1-128", i, len(g.SchemeId))
		}
		if len(g.CapabilityId) < 1 || len(g.CapabilityId) > 256 {
			return fmt.Errorf("principal_authorization: grant[%d].capabilityId length %d: must be 1-256", i, len(g.CapabilityId))
		}
	}
	return nil
}

// BuildPrincipalAuthorizationExtension builds a PrincipalAuthorization X.509v3 extension from the configuration.
func BuildPrincipalAuthorizationExtension(cfg PrincipalAuthorizationConfig) (pkix.Extension, error) {
	if err := validatePA(cfg.Grants); err != nil {
		return pkix.Extension{}, err
	}
	ext := PrincipalAuthorization{
		Version: 1,
		Grants:  cfg.Grants,
	}
	if cfg.DelegationPolicy != nil {
		ext.DelegationPolicy = *cfg.DelegationPolicy
	}
	if ext.Grants == nil {
		ext.Grants = []Capability{}
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("principal_authorization: marshal failed: %w", err)
	}
	return pkix.Extension{
		Id:       OIDPrincipalAuthorization,
		Critical: false,
		Value:    der,
	}, nil
}

// ParsePrincipalAuthorizationExtension parses the PrincipalAuthorization extension from the certificate extension list.
func ParsePrincipalAuthorizationExtension(exts []pkix.Extension) (*PrincipalAuthorization, error) {
	for _, ext := range exts {
		if ext.Id.Equal(OIDPrincipalAuthorization) {
			var pa PrincipalAuthorization
			if _, err := asn1.Unmarshal(ext.Value, &pa); err != nil {
				return nil, fmt.Errorf("principal_authorization: unmarshal failed: %w", err)
			}
			if err := validatePA(pa.Grants); err != nil {
				return nil, err
			}
			return &pa, nil
		}
	}
	return nil, nil
}

// GrantIds returns the full permission identifiers (scheme:capabilityId) for all Grants.
// Aligned with pki-types Capability.FullID() spec: matching/authorization decisions use the full identifier.
func (pa *PrincipalAuthorization) GrantIds() []string {
	if pa == nil {
		return nil
	}
	var ids []string
	for _, g := range pa.Grants {
		ids = append(ids, g.FullID())
	}
	return ids
}

// AllowsRepresentative checks whether the PrincipalAuthorization allows representative delegation.
func (pa *PrincipalAuthorization) AllowsRepresentative() bool {
	if pa == nil {
		return false
	}
	return pa.DelegationPolicy.AllowedMode == int(DelegationModeRepresentativeAllowed)
}

// PermIds is an alias for GrantIds, maintaining backward compatibility (legacy API callers).
func (pa *PrincipalAuthorization) PermIds() []string {
	return pa.GrantIds()
}

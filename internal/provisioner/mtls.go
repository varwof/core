// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package provisioner

import (
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal/ca"
)

// MTLSName is the built-in mTLS provisioner name.
const MTLSName = "mtls"

// MTLSProvisioner authenticates via mTLS client certificate.
// Uses the AIC extension first, then falls back to OU mapping.
type MTLSProvisioner struct{}

func NewMTLSProvisioner() *MTLSProvisioner { return &MTLSProvisioner{} }

func (p *MTLSProvisioner) Name() string { return MTLSName }
func (p *MTLSProvisioner) Type() string { return "mtls" }

// UserResolver looks up a username and returns the role and permission grants.
// Set by the Server to avoid circular imports.
var UserResolver func(username string) (role string, perms []string, err error)

// CertResolver looks up a client certificate forwarded by a trusted gateway
// (X-Client-Cert-DER passthrough) by (issuer DN, serial) and returns its
// status and principal_uid. Set by the Server to avoid circular imports.
var CertResolver func(issuerDN, serial string) (status, principalUid string, err error)

// AgentSessionMaxTTL caps how far into the future an X-Agent-TTL header may
// reach for delegated-agent certificates. Zero rejects delegated sessions
// entirely. Set at startup from Serve.AgentSessionMaxTTL.
var AgentSessionMaxTTL time.Duration = 24 * time.Hour

// TrustedGatewayOUs lists the OUs whose mTLS certs are trusted to assert
// delegated identities (X-Client-Cert-DER passthrough; legacy X-Agent-User
// username delegation also gated on this). Empty rejects gateway-asserted
// delegation entirely. Set at startup from Serve.TrustedGatewayOUs.
var TrustedGatewayOUs []string

func (p *MTLSProvisioner) Authenticate(r *http.Request) (*AuthResult, error) {
	cert := PeerCertFromRequest(r)
	if cert == nil {
		return nil, nil
	}

	aic, err := ca.ParseAIC(cert)
	if err == nil && aic != nil {
		pa, paErr := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
		if paErr != nil {
			return nil, nil
		}
		result, err := p.authFromAIC(aic, pa)
		if err != nil || result == nil {
			return result, err
		}
		result.CertIdentity = NewCertIdentityFromCert(cert)
		return result, nil
	}

	// Trusted-gateway delegation. Prefer B2 (X-Client-Cert-DER certificate
	// passthrough): the forwarded certificate is resolved for its principal
	// and permissions. B1 (X-Agent-User username) is a degraded fallback.
	if isTrustedGateway(cert) && r.Header.Get("X-Client-Cert-DER") != "" {
		return gatewayForwardedCertUser(r)
	}
	if isTrustedGateway(cert) && r.Header.Get("X-Agent-User") != "" {
		return gatewayDelegatedUser(r)
	}

	role := ouToRole(cert.Subject.OrganizationalUnit)
	if role == "" {
		return nil, nil
	}

	// Delegated-Agent certificates no longer trust client-supplied identity
	// (X-Agent-User): the operator must come from the certificate itself
	// (AIC PrincipalUid above, or the certificate CN). The delegated session
	// must also carry a server-verifiable expiry within the configured window.
	username := cert.Subject.CommonName
	if hasOU(cert.Subject.OrganizationalUnit, "Delegated-Agent") {
		if !delegatedSessionAllowed(r) {
			return nil, nil
		}
	}

	// Cert-first authorization: the certificate's PrincipalAuthorization
	// grants are the authoritative permission source. Without a PA extension
	// the certificate is rejected (fail-closed).
	pa, err := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
	if err != nil {
		return nil, nil
	}
	if pa == nil || len(pa.Grants) == 0 {
		return nil, nil
	}
	var paPerms []string
	for _, g := range pa.Grants {
		paPerms = append(paPerms, grantID(g))
	}

	return &AuthResult{
		Username:     username,
		Role:         role,
		Permissions:  paPerms,
		CertIdentity: NewCertIdentityFromCert(cert),
	}, nil
}

// delegatedSessionAllowed mirrors serve.Server.agentSessionAllowed for the
// provisioner path using the AgentSessionMaxTTL global.
func delegatedSessionAllowed(r *http.Request) bool {
	if AgentSessionMaxTTL <= 0 {
		return false
	}
	ttlStr := r.Header.Get("X-Agent-TTL")
	if ttlStr == "" {
		return false
	}
	ttl, err := time.Parse(time.RFC3339, ttlStr)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.After(ttl) {
		return false
	}
	if ttl.Sub(now) > AgentSessionMaxTTL {
		return false
	}
	return true
}

// isTrustedGateway reports whether the peer cert carries an OU in
// TrustedGatewayOUs, i.e. it is a gateway service certificate trusted to
// assert delegated identities.
func isTrustedGateway(cert *x509.Certificate) bool {
	for _, want := range TrustedGatewayOUs {
		if hasOU(cert.Subject.OrganizationalUnit, want) {
			return true
		}
	}
	return false
}

// gatewayForwardedCertUser (B2) resolves the identity of a client certificate
// forwarded by a trusted gateway via the X-Client-Cert-DER header (base64 DER
// of the verified peer cert). The certificate is independently resolved via
// CertResolver (issuer DN, serial): it must exist, be valid (not revoked), and
// map to a real enabled user via UserResolver. This keeps identity
// cryptographically bound to a certificate and auditable, unlike the legacy
// X-Agent-User username path (B1). The X-Agent-TTL must still be present, in
// the future, and within the configured window (fail-closed).
func gatewayForwardedCertUser(r *http.Request) (*AuthResult, error) {
	if !delegatedSessionAllowed(r) {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Client-Cert-DER"))
	if err != nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil
	}
	if CertResolver == nil {
		return nil, nil
	}
	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	status, principalUid, err := CertResolver(cert.Issuer.String(), serial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // certificate not issued by this PKI
		}
		return nil, fmt.Errorf("resolve forwarded cert: %w", err)
	}
	if status != "V" {
		return nil, nil // revoked, expired, or otherwise not valid
	}
	username := principalUid
	if username == "" {
		username = cert.Subject.CommonName
	}
	if username == "" {
		return nil, nil
	}
	if UserResolver == nil {
		return nil, nil
	}
	role, perms, err := UserResolver(username)
	if err != nil || role == "" {
		return nil, nil
	}
	return &AuthResult{
		Username:     username,
		Role:         role,
		Permissions:  perms,
		CertIdentity: NewCertIdentityFromCert(cert),
	}, nil
}

// gatewayDelegatedUser resolves the identity asserted by a trusted gateway via
// the X-Agent-User username header (B1). Usernames are not cryptographically
// bound to a certificate, so this path carries no CertIdentity and is a
// degraded fallback: prefer B2 (X-Client-Cert-DER certificate passthrough).
// The X-Agent-TTL must be present, in the future, and within the configured
// window (fail-closed); the principal's own role/permissions come from
// UserResolver (least privilege, not the gateway's).
func gatewayDelegatedUser(r *http.Request) (*AuthResult, error) {
	if !delegatedSessionAllowed(r) {
		return nil, nil
	}
	username := r.Header.Get("X-Agent-User")
	if username == "" {
		return nil, nil
	}
	if UserResolver == nil {
		return nil, nil
	}
	role, perms, err := UserResolver(username)
	if err != nil || role == "" {
		return nil, nil
	}
	return &AuthResult{
		Username:    username,
		Role:        role,
		Permissions: perms,
	}, nil
}

func (p *MTLSProvisioner) authFromAIC(aic *ca.AIC, pa *ca.PrincipalAuthorization) (*AuthResult, error) {
	uid := aic.PrincipalUid.String()
	if uid == ":" {
		return nil, nil
	}

	// Cert-first fail-closed: PA extension missing or empty → reject. Permissions come only
	// from the certificate, never falling back to UserResolver's user role permissions.
	if pa == nil || len(pa.Grants) == 0 {
		return nil, nil
	}

	if UserResolver == nil {
		// No resolver available; return basic identity without full permissions
		return &AuthResult{
			Username:    uid,
			Role:        "agent",
			Permissions: nil,
		}, nil
	}

	role, _, err := UserResolver(uid)
	if err != nil || role == "" {
		return nil, nil
	}

	// Secure intersection fail-closed: AIC declares no capabilities → grant empty permissions.
	// Must never fall back to inheriting all PA permissions.
	if len(aic.Capabilities) == 0 {
		return &AuthResult{
			Username:    uid,
			Role:        role + "(agent)",
			Permissions: nil,
		}, nil
	}

	// PA grants (authoritative) serve as matching templates, AIC capabilities (agent declarations)
	// as candidates. Result = AIC capabilities covered by PA grants (full ID intersection,
	// wildcard supported). Matching is uniformly based on FullID (schemeId:capabilityId),
	// consistent with the pki-types specification.
	var paIds []string
	for _, g := range pa.Grants {
		paIds = append(paIds, g.FullID())
	}
	var finalPerms []string
	for _, cap := range aic.Capabilities {
		if cap.CapabilityId == "" {
			continue
		}
		fullID := cap.FullID()
		if grantCovered(fullID, paIds) {
			finalPerms = append(finalPerms, fullID)
		}
	}
	return &AuthResult{
		Username:    uid,
		Role:        role + "(agent)",
		Permissions: finalPerms,
	}, nil
}

// grantCovered reports whether capabilityID is covered by any grant template in allowed (wildcard supported).
func grantCovered(capID string, allowed []string) bool {
	for _, a := range allowed {
		if auth.MatchCapability(capID, a) {
			return true
		}
	}
	return false
}

func ouToRole(ous []string) string {
	if p := auth.GetPolicy(); p != nil {
		for _, ou := range ous {
			if role := p.RoleByOU(ou); role != "" {
				return role
			}
		}
		return ""
	}
	for _, ou := range ous {
		switch ou {
		case "SuperAdmin":
			return "superadmin"
		case "admin", "Admin":
			return "admin"
		case "Operator", "operator":
			return "operator"
		case "Auditor", "auditor":
			return "auditor"
		case "Revoker", "revoker":
			return "revoker"
		case "ReadOnly", "readonly":
			return "readonly"
		case "Console", "console":
			return "console"
		case "AutoRenew", "auto-renew":
			return "auto-renew"
		case "Reporter", "reporter":
			return "reporter"
		}
	}
	return ""
}

// grantID returns the full permission identifier (scheme:capabilityId) of a PA grant,
// consistent with the gateway capabilityID (gateway-core/delegation_chain.go) concatenation logic:
// PA encodes SchemeId and CapabilityId separately (e.g. schemeId="ca", capabilityId="list"),
// full permission is "ca:list", used by HasPerm/MatchCapability to match grants in authorization policies.
func grantID(g ca.Capability) string {
	if g.SchemeId == "" {
		return g.CapabilityId
	}
	return g.SchemeId + ":" + g.CapabilityId
}

func hasOU(ous []string, target string) bool {
	for _, ou := range ous {
		if ou == target {
			return true
		}
	}
	return false
}

func rolePerms(role string) []string {
	if p := auth.GetPolicy(); p != nil {
		return p.RoleGrants(role)
	}
	raw := auth.RolePermissions[role]
	perms := make([]string, len(raw))
	for i, r := range raw {
		perms[i] = string(r)
	}
	return perms
}

var _ = (*x509.Certificate)(nil)

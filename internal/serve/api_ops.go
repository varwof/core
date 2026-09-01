// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
	pki "github.com/varwof/types"
)

// pemEncode encodes DER data into a PEM block.
func pemEncode(blockType string, data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data}))
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// x509MarshalPKCS8PrivateKey encodes a PKCS#8 private key.
func x509MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// ---- POST /api/v1/certs — Issue Certificate ----

type issueReq struct {
	CA                     string                           `json:"ca"`
	CN                     string                           `json:"cn"`
	SAN                    string                           `json:"san,omitempty"`
	Subject                string                           `json:"subject,omitempty"`
	Profile                string                           `json:"profile,omitempty"`
	KeyType                string                           `json:"key_type,omitempty"`
	Validity               int                              `json:"validity,omitempty"`
	AgentId                string                           `json:"agent_id,omitempty"`
	PrincipalUid           string                           `json:"principal_uid,omitempty"`
	HashAlgo               string                           `json:"hash_algo,omitempty"`
	DelegationMode         *int                             `json:"delegation_mode,omitempty"`
	PrincipalAuthorization *ca.PrincipalAuthorizationConfig `json:"principal_authorization,omitempty"`
	UserAuthSig            []byte                           `json:"user_auth_signature,omitempty"`
	UserAuthSigAlgo        string                           `json:"user_auth_signature_algo,omitempty"`
	UserAuthLifetime       int                              `json:"user_auth_lifetime,omitempty"`
	UserAuthNonce          []byte                           `json:"user_auth_nonce,omitempty"`
	UserAuthTimestamp      string                           `json:"user_auth_timestamp,omitempty"`
	UserAuthReasonCode     string                           `json:"user_auth_reason_code,omitempty"`
	UserAuthReasonDesc     string                           `json:"user_auth_reason_description,omitempty"`
	// UserCertPEM is the DA signer (user) certificate PEM. During agent-proxy issuance,
	// the CA uses it to verify the DelegationAuthorization signature (C3). Defaults to
	// the mTLS peer cert if its SPKI matches principal_uid.keyHash.
	UserCertPEM string `json:"user_cert_pem,omitempty"`
	// AIC capabilities for agent-proxy profile
	Capabilities []struct {
		SchemeId     string `json:"scheme_id"`
		CapabilityId string `json:"capability_id"`
		Parameters   []byte `json:"parameters,omitempty"`
	} `json:"capabilities,omitempty"`
	// AuthorizationConstraints are session-level constraints (allowed-cidr / time-window / max-concurrent).
	// Written into AIC extension field 7, enforced offline by the gateway.
	AuthorizationConstraints []struct {
		SchemeId     string `json:"scheme_id"`
		CapabilityId string `json:"capability_id"`
		Parameters   []byte `json:"parameters,omitempty"`
	} `json:"authorization_constraints,omitempty"`
	KeyPassword string `json:"key_password,omitempty"`
	// CAScope limits the issued cert's management scope to a sub-CA name
	// (m-admin/m-superadmin profiles). Only the superadmin may set a scope,
	// and a scoped admin may only mint scopes within its own scope.
	CAScope string `json:"ca_scope,omitempty"`
	// IsSPIFFE enables SPIFFE identity integration. When true, agentId is written
	// as "spiffe://{spiffe_trust_domain}/agent/{agentId}" and embedded in SAN URIs.
	// Requires spiffe_trust_domain to be set.
	IsSPIFFE *bool `json:"is_spiffe,omitempty"`
	// SPIFFEDomain is the SPIFFE trust domain (e.g. "varwof.com").
	// Required when is_spiffe=true.
	SPIFFEDomain string `json:"spiffe_trust_domain,omitempty"`
	// IdentityUsername resolves identity-user profile attributes from the
	// configured identity source (bridge-ldap/bridge-oauth). When profile
	// = identity-user and this is set, CN/OU/email are auto-filled from the
	// directory; cn may be omitted.
	IdentityUsername string `json:"identity_username,omitempty"`
	// IdentitySource overrides the identity source_tag used for the lookup
	// (defaults to config identity.source).
	IdentitySource string `json:"identity_source,omitempty"`
}

type issueResp struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	CA           string `json:"ca"`
	SPIFFEID     string `json:"spiffe_id,omitempty"`
}

// isManagementProfile reports whether the requested profile issues a
// management certificate (m-*). Such certificates carry CA scope and are
// minted for the management sub-CA, which operator and other non-superadmin
// roles are hard-excluded from.
func isManagementProfile(p ca.Profile) bool {
	switch p {
	case ca.ProfileMSuperAdmin, ca.ProfileMAdmin, ca.ProfileMOperator, ca.ProfileMAuditor,
		ca.ProfileMRevoker, ca.ProfileMReadonly, ca.ProfileMConsole, ca.ProfileMAutoRenew,
		ca.ProfileMReporter:
		return true
	}
	return false
}

func (s *Server) apiIssueCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// Single-level delegation: Agent -> Agent is prohibited.
	// CA MUST reject any certificate request where the requester is itself an Agent.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if requesterAIC, _ := ca.ParseAIC(r.TLS.PeerCertificates[0]); requesterAIC != nil {
			s.apiErr(w, r, http.StatusForbidden, "api.agent_delegation_denied",
				"certificate requester is itself an Agent; Agent->Agent delegation is prohibited")
			return
		}
	}

	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	cfg := s.getConfig()
	// Resolve the effective profile early: identity-user auto-fills CN from the
	// identity source, so the cn-required check is skipped for it.
	effProfile := ca.Profile(req.Profile)
	if effProfile == "" {
		effProfile = ca.Profile(cfg.Defaults.Profile)
	}
	if effProfile == "" {
		effProfile = ca.ProfileTLSServer
	}
	// ── Management sub-CA gate ─────────────────────────────────────────────────
	// Minting management (m-*) certificates is restricted to the superadmin
	// role; every other role (operator and friends) is hard-excluded from the
	// management sub-CA and confined to the other (non-management) regions.
	// The superadmin role is certificate-only: a live mTLS client certificate
	// (OU=SuperAdmin) must be in hand. Username/password and API tokens never
	// reach superadmin and are rejected here even if a stamp claims otherwise.
	// NOTE(deprecated): the operator's management-mint capability is planned
	// for removal; this gate is the fail-closed front-line for it.
	if isManagementProfile(effProfile) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			s.apiErr(w, r, http.StatusUnauthorized, "api.auth_required",
				"management sub-CA profile mint requires an mTLS certificate")
			return
		}
		u, _ := r.Context().Value(userCtxKey).(*AuthUser)
		if u == nil || u.Role != "superadmin" {
			s.apiErr(w, r, http.StatusForbidden, "api.management_mint_denied",
				"management sub-CA profile mint is reserved to superadmin (certificate-only)")
			return
		}
	}
	if req.CN == "" && effProfile != ca.ProfileIdentityUser {
		s.apiErr(w, r, http.StatusBadRequest, "api.cn_required", "")
		return
	}
	caName := req.CA
	if caName == "" {
		caName = cfg.Defaults.CA
	}
	if caName == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.ca_required", "")
		return
	}
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found_fmt", caName)
		return
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_ca_failed", err.Error())
		return
	}
	keyType := req.KeyType
	if keyType == "" {
		keyType = cfg.Defaults.KeyType
	}
	privKey, err := ca.GenerateKey(keyType)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.key_gen_failed", err.Error())
		return
	}
	validity := req.Validity
	if validity <= 0 {
		validity = 365
	}
	sc := &ca.SignConfig{
		DB:             s.getDB(),
		SkipDB:         s.addCertRecordEnabled(), // In-memory engine / buffer batch mode: issue only, no DB write
		CAKey:          issuerKey,
		CACert:         issuerCert,
		CAName:         caName,
		SubjectPubKey:  privKey.Public(),
		CommonName:     req.CN,
		SANs:           splitSANs(req.SAN),
		KeyType:        keyType,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
		Validity:       time.Duration(validity) * 24 * time.Hour,
		DefaultCountry: cfg.Defaults.DefaultCountry,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
		PolicyFile:     cfg.Policy,
		RequirePolicy:  s.requirePolicy(),
	}
	sc.Profile = effProfile
	if req.CAScope != "" {
		// Delegation guard: minting a scoped admin cert is a framework
		// operation. Only superadmin may set an arbitrary scope; a scoped
		// admin may only delegate a scope within its own (no escalation).
		if u, ok := r.Context().Value(userCtxKey).(*AuthUser); ok && u != nil && u.Role != "superadmin" {
			covered := false
			for _, s := range u.CAScopes {
				if s == "*" || s == req.CAScope {
					covered = true
					break
				}
				for _, sub := range strings.Split(s, ",") {
					if strings.TrimSpace(sub) == req.CAScope {
						covered = true
						break
					}
				}
			}
			if !covered {
				s.apiErr(w, r, http.StatusForbidden, "api.ca_scope_denied",
					"cannot mint cert with scope "+req.CAScope+" outside your own scope")
				return
			}
		}
		// Dual-write the scope: SAN URI (all profiles) + OID extension
		// (all m-* management profiles) so the issued cert carries both.
		sc.CAScope = []string{req.CAScope}
		sc.Scope = req.CAScope
	}
	if req.Subject != "" {
		n := parseDN(req.Subject)
		sc.Subject = &n
		if n.CommonName != "" {
			sc.CommonName = n.CommonName
		}
	}
	// identity-user profile: resolve the person's attributes from the configured
	// identity source (bridge-ldap / bridge-oauth) and auto-fill CN/OU/email.
	// Requires config identity.source_url to be set and the profile to be
	// identity-user (either explicit or the configured default).
	if sc.Profile == ca.ProfileIdentityUser {
		src := s.getIdentitySource()
		if src == nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.identity_source_not_configured",
				"identity-user profile requires config identity.source_url (bridge-ldap/bridge-oauth)")
			return
		}
		username := req.IdentityUsername
		if username == "" {
			username = req.CN
		}
		if username == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.identity_username_required",
				"identity-user profile requires identity_username (or cn)")
			return
		}
		id, err := src.Lookup(r.Context(), req.IdentitySource, username)
		if err != nil {
			s.apiErr(w, r, http.StatusBadGateway, "api.identity_lookup_failed", err.Error())
			return
		}
		if id.Disabled && !(cfg.Identity.DisabledOK) {
			s.apiErr(w, r, http.StatusForbidden, "api.identity_disabled",
				"identity account is disabled; issuance rejected")
			return
		}
		// Map identity attributes into the certificate subject.
		ous := cfg.Identity.CertificateOUS(id)
		cn := id.FullName
		if cn == "" {
			cn = id.Username
		}
		if cn == "" {
			cn = username
		}
		subj := pkix.Name{CommonName: cn}
		if sc.Subject != nil && len(sc.Subject.Organization) > 0 {
			subj.Organization = sc.Subject.Organization
		}
		if len(ous) > 0 {
			subj.OrganizationalUnit = ous
		}
		if id.Email != "" {
			// RFC 822 email in subject (emailAddress OID 1.2.840.113549.1.9.1)
			subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{1, 2, 840, 113549, 1, 9, 1},
				Value: id.Email,
			})
			// Also add email SAN if not already present.
			hasEmail := false
			for _, san := range sc.SANs {
				if strings.EqualFold(san, "email:"+id.Email) {
					hasEmail = true
					break
				}
			}
			if !hasEmail {
				sc.SANs = append(sc.SANs, "email:"+id.Email)
			}
		}
		sc.Subject = &subj
		sc.CommonName = subj.CommonName
	}
	if sc.Profile == ca.ProfileAgentProxy && req.AgentId != "" {
		var userAuth *ca.DelegationAuthorization
		if len(req.UserAuthSig) > 0 {
			var sigAlgoOID asn1.ObjectIdentifier
			// Map well-known name or OID string to ObjectIdentifier
			switch req.UserAuthSigAlgo {
			case "ECDSA-SHA256":
				sigAlgoOID = ca.OIDSigECDSAWithSHA256
			case "RSA-SHA256":
				sigAlgoOID = ca.OIDSigRSAWithSHA256
			case "RSA-PSS-SHA256":
				sigAlgoOID = ca.OIDSigRSAPSSWithSHA256
			default:
				if oid, err := parseOIDStr(req.UserAuthSigAlgo); err == nil {
					sigAlgoOID = oid
				}
			}
			if len(sigAlgoOID) == 0 {
				sigAlgoOID = ca.OIDSigECDSAWithSHA256 // default
			}
			// v1.7.1: DA's timestamp and reason must match what the requester used when signing,
			// otherwise the gateway's VerifyDelegationAuth TBS reconstruction will fail signature
			// verification. Falls back to defaults when not provided.
			daTS := time.Now()
			if req.UserAuthTimestamp != "" {
				if t, err := time.Parse(time.RFC3339, req.UserAuthTimestamp); err == nil {
					daTS = t
				}
			}
			reasonCode := "API_ISSUE"
			reasonDesc := "user-authorized AIC issuance"
			if req.UserAuthReasonCode != "" {
				reasonCode = req.UserAuthReasonCode
			}
			if req.UserAuthReasonDesc != "" {
				reasonDesc = req.UserAuthReasonDesc
			}
			userAuth = &ca.DelegationAuthorization{
				Reason:             ca.Reason{ReasonCode: reasonCode, Description: reasonDesc},
				SignatureValue:     req.UserAuthSig,
				SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: sigAlgoOID},
				Timestamp:          daTS,
				Nonce:              req.UserAuthNonce,
				RequestedLifetime:  req.UserAuthLifetime,
			}
		}

		// Convert API capabilities to CA capabilities
		var caps []ca.Capability
		for _, rc := range req.Capabilities {
			caps = append(caps, ca.Capability{
				SchemeId:     rc.SchemeId,
				CapabilityId: rc.CapabilityId,
				Parameters:   rc.Parameters,
			})
		}
		if caps == nil {
			caps = []ca.Capability{}
		}
		// Parse principal_uid if provided, otherwise construct from CN
		var pu ca.PrincipalUid
		if req.PrincipalUid != "" {
			var err error
			pu, err = ca.ParsePrincipalUid(req.PrincipalUid)
			if err != nil {
				s.apiErr(w, r, http.StatusBadRequest, "api.invalid_principal_uid", err.Error())
				return
			}
		} else {
			pu = ca.PrincipalUid{Version: 1, Realm: cfg.Defaults.Realm, Identifier: req.CN}
		}
		// KeyHash = requester certificate SPKI SHA-256 (v1.7.1 required; used for user certificate lookup).
		if len(pu.KeyHash) == 0 && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			pu.KeyHash = ca.SPKIHash(r.TLS.PeerCertificates[0].PublicKey)
		}
		// Apply hash_algo if specified
		if req.HashAlgo != "" {
			oid, err := ca.ParseHashAlgo(req.HashAlgo)
			if err != nil {
				s.apiErr(w, r, http.StatusBadRequest, "api.invalid_hash_algo", err.Error())
				return
			}
			pu.HashAlgo = ca.AlgorithmIdentifier{Algorithm: oid}
		}
		// v1.7.1: keyHash length must match the declared algorithm's output length
		// (current implementation only supports SHA-256=32).
		// Validate immediately before constructing AICConfig so invalid keyHash returns 400
		// instead of a deep 500.
		if err := ca.ValidatePrincipalUidKeyHash(pu); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_principal_uid", err.Error())
			return
		}
		// Delegation mode: explicitly specified in the request (0=authorized, 1=representative),
		// defaults to authorized. B6: AIC extension must carry this value (previously always 0 bug).
		dm := ca.DelegationAuthorized
		if req.DelegationMode != nil {
			dm = ca.DelegationMode(*req.DelegationMode)
		}
		// SPIFFE identity integration: transform agentId to SPIFFE URI format.
		agentId := req.AgentId
		if req.IsSPIFFE != nil && *req.IsSPIFFE {
			if req.SPIFFEDomain == "" {
				s.apiErr(w, r, http.StatusBadRequest, "api.spiffe_domain_required", "spiffe_trust_domain is required when is_spiffe=true")
				return
			}
			spiffeID := pki.BuildSPIFFEID(req.SPIFFEDomain, req.AgentId)
			if err := pki.ValidateSPIFFEID(spiffeID, req.SPIFFEDomain); err != nil {
				s.apiErr(w, r, http.StatusBadRequest, "api.invalid_spiffe_id", err.Error())
				return
			}
			agentId = spiffeID
		}
		sc.AIC = &ca.AICConfig{
			AgentId:                  agentId,
			PrincipalUid:             pu,
			Capabilities:             caps,
			DelegationMode:           dm,
			AuthorizationConstraints: apiConstraintsToCA(req.AuthorizationConstraints),
			DelegationAuthorization:  userAuth,
		}
		// Capability registration validation (single source of truth): capabilities declared in AIC must be registered.
		sc.ValidateCapabilities = s.validateCapabilities
		// v1.7.1 spec: delegationAuthorization is required; missing user authorization signature → reject AIC issuance
		if userAuth == nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.aic_requires_auth",
				"agent-proxy AIC issuance requires a user authorization signature (user_auth_sig)")
			return
		}
		// C3/M5: CA issuance-side DA signature verification (spec §Issuance Phase
		// Validation) — reconstruct DelegationAuthTBS and verify with DA signer
		// certificate public key; reject on failure. Verification now lives in the
		// ca library layer (VerifyDelegationAuthorization) and is re-run inside
		// Sign() via sc.UserCert (defense in depth; idempotent). Nonce is consumed
		// only after verification passes (replay check).
		userCert, err := resolveDAUserCert(r, req.UserCertPEM, pu)
		if err != nil {
			s.apiErr(w, r, http.StatusForbidden, "api.delegation_signature_invalid", err.Error())
			return
		}
		if err := ca.VerifyDelegationAuthorization(userCert, sc.AIC); err != nil {
			s.apiErr(w, r, http.StatusForbidden, "api.delegation_signature_invalid", err.Error())
			return
		}
		sc.UserCert = userCert
		// C2: DA reason must be explicitly declared by the authorizer (DA signer);
		// the CA must not fabricate audit reasons for the user.
		// reason_code is required (description may be omitted and filled with defaults);
		// missing → reject, to avoid silently filling API_ISSUE that masks authorization intent.
		if req.UserAuthReasonCode == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.reason_required",
				"delegation authorization requires user_auth_reason_code (C2)")
			return
		}
		// DA nonce anti-replay (06-delegation-auth.md §Nonce Lifecycle): the CA persists
		// the nonce at issuance; the same nonce cannot be used to mint again.
		// Engine-first, DB fallback.
		// Only performs replay check on the 32B nonce carried by the client signature;
		// BuildAICExtension itself rejects non-32B nonces (must be exactly 32 bytes).
		if len(userAuth.Nonce) == 32 {
			exp := daNonceExpiry(userAuth.Timestamp.Unix(), int64(userAuth.RequestedLifetime), s.daTimestampSkew(), s.getEngineNonceTTL())
			if err := s.storeDANonce(userAuth.Nonce, exp); err != nil {
				if errors.Is(err, db.ErrDuplicateNonce) {
					s.apiErr(w, r, http.StatusForbidden, "api.da_nonce_replayed",
						"delegation authorization nonce was already used to mint an AIC; replay rejected")
					return
				}
				if errors.Is(err, engine.ErrBackpressure) {
					s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests",
						"da nonce write pipeline full, retry later")
					return
				}
				s.apiErr(w, r, http.StatusInternalServerError, "api.da_nonce_store_failed", err.Error())
				return
			}
		}
		// DA timestamp freshness defense (P1-B-13): |now - timestamp| ≤ da_max_timestamp_skew.
		// If the client delays too long after signing the DA before submitting for issuance,
		// it is considered suspicious (replay/stolen signature) and rejected.
		if err := s.checkDATimestampFreshness(userAuth.Timestamp); err != nil {
			s.apiErr(w, r, http.StatusForbidden, "api.da_timestamp_stale", err.Error())
			return
		}
		// Short-lived AIC cert: 1 hour validity (authorized mode validity upper bound,
		// can be relaxed up to ≤24h via defaults.agent_proxy_max_validity, spec P1-B-09/25).
		sc.Validity = s.agentProxyMaxValidity()
		sc.MaxAgentProxyValidity = s.agentProxyMaxValidity()

		// delegation_mode → PrincipalAuthorization.DelegationPolicy (consistent with AIC
		// extension's delegationMode; B6: allowedMode must allow representative delegation).
		if req.DelegationMode != nil {
			if sc.PrincipalAuthorization == nil {
				sc.PrincipalAuthorization = &ca.PrincipalAuthorizationConfig{}
			}
			sc.PrincipalAuthorization.DelegationPolicy = &ca.DelegationPolicy{AllowedMode: *req.DelegationMode}
		}
	}
	if req.PrincipalAuthorization != nil {
		sc.PrincipalAuthorization = req.PrincipalAuthorization
	}

	// B6 gating: representative mode (dm==1) requires the principal authorization to
	// explicitly allow representative delegation (DelegationPolicy.allowedMode=1), and
	// the DA signature must have passed C3 verification.
	// authorized mode (dm==0) does not require PA (Auto-derive fallback when not set).
	// Note: must be evaluated after req.PrincipalAuthorization override, otherwise the
	// client-provided allowed_mode is ignored.
	if sc.AIC != nil && sc.AIC.DelegationMode == ca.DelegationRepresentative {
		paAllowed := false
		if sc.PrincipalAuthorization != nil && sc.PrincipalAuthorization.DelegationPolicy != nil &&
			sc.PrincipalAuthorization.DelegationPolicy.AllowedMode == int(ca.DelegationRepresentative) {
			paAllowed = true
		}
		if !paAllowed {
			s.apiErr(w, r, http.StatusForbidden, "api.representative_policy_denied",
				"representative delegation requires principal_authorization.delegation_policy.allowed_mode=1")
			return
		}
	}

	// representative mode requires user authorization signature
	if sc.PrincipalAuthorization != nil && sc.PrincipalAuthorization.DelegationPolicy != nil &&
		sc.PrincipalAuthorization.DelegationPolicy.AllowedMode == int(ca.DelegationRepresentative) {
		if sc.AIC == nil || len(sc.AIC.DelegationAuthorization.SignatureValue) == 0 {
			s.apiErr(w, r, http.StatusBadRequest, "api.representative_requires_auth",
				"representative mode requires user authorization signature")
			return
		}
	}

	// B2/B3: enforce DelegationPolicy.MaxAgents (concurrent delegation limit) and
	// MaxSessionHours (session duration limit). Only effective for agent-proxy (AIC)
	// issuance when PA explicitly carries a DelegationPolicy (Auto-derive fallback
	// path has no DelegationPolicy).
	if sc.AIC != nil && sc.PrincipalAuthorization != nil && sc.PrincipalAuthorization.DelegationPolicy != nil {
		dp := sc.PrincipalAuthorization.DelegationPolicy
		// B2 — MaxAgents: if the number of currently active agent-proxy AIC certificates
		// for the same principal ≥ limit, reject new delegation.
		// MaxAgents semantics: upper bound on the number of Agent instances simultaneously
		// delegated by the principal.
		if dp.MaxAgents > 0 {
			uid := sc.AIC.PrincipalUid.String()
			if uid != "" {
				n, err := s.countActiveAICsByPrincipalUid(uid, time.Now())
				if err != nil {
					slog.Warn("max_agents check failed", "error", err.Error(), "principal_uid", uid)
				} else if n >= dp.MaxAgents {
					s.apiErr(w, r, http.StatusForbidden, "api.max_agents_exceeded",
						fmt.Sprintf("principal already has %d active agent certs (max_agents=%d)", n, dp.MaxAgents))
					return
				}
			}
		}
		// B3 — MaxSessionHours: hard upper bound on representative delegation session duration;
		// exceeded → reject (takes the stricter of this and MaxAgentProxyValidity).
		if dp.MaxSessionHours > 0 {
			sessLimit := time.Duration(dp.MaxSessionHours) * time.Hour
			if sc.MaxAgentProxyValidity <= 0 || sessLimit < sc.MaxAgentProxyValidity {
				sc.Validity = sessLimit
				sc.MaxAgentProxyValidity = sessLimit
			}
		}
	}

	result, err := ca.Sign(sc)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.sign_failed", err.Error())
		return
	}
	// In-memory engine / buffer batch mode: upon successful signing, return the serial
	// immediately; the record is persisted by the engine (in-memory authority, async
	// batch persistence) or by RecordBuffer after batching (WAL-protected, max 500ms
	// latency). When the write pipeline is full, backpressure with 503; the client can
	// retry (this signing was not persisted, no side effects).
	if err := s.addCertRecord(result.Record); err != nil {
		if errors.Is(err, engine.ErrBackpressure) {
			s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests",
				"write pipeline full, retry later")
			return
		}
		s.apiErr(w, r, http.StatusInternalServerError, "api.persist_failed", err.Error())
		return
	}
	s.auditLog(r, "cert_issue",
		fmt.Sprintf("ca=%s profile=%s serial=%s cn=%q", caName, effProfile, result.SerialHex, result.Cert.Subject.CommonName))
	var keyPEM []byte
	if req.KeyPassword != "" {
		keyPEM, err = ca.EncryptPrivateKeyPEM(privKey, req.KeyPassword)
	} else {
		keyPEM, err = ca.KeyToPEM(privKey)
	}
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.key_pem_failed", err.Error())
		return
	}
	apiOK(w, issueResp{
		SerialNumber: result.SerialHex,
		CommonName:   result.Cert.Subject.CommonName,
		CertPEM:      string(ca.CertToPEM(result.CertDER)),
		KeyPEM:       string(keyPEM),
		CA:           caName,
		SPIFFEID:     pki.ExtractSPIFFEIDFromCert(result.Cert),
	})
}

// ---- POST /api/v1/cert/{ca}/{serial}/revoke ----

func (s *Server) apiRevokeCert(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records first so the target cert is visible to the
	// DB revoke UPDATE (avoids the ≤500ms issue→flush visibility window).
	s.FlushRecordBuffer()
	reason := 0 // unspecified
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Reason != "" {
		if r, err := ca.ParseRevokeReason(req.Reason); err == nil {
			reason = r
		}
	}
	// cascade revoke: also revoke agent certs with same PrincipalUid
	cascaded, err := s.revokeWithCascade(caName, serial, reason)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_failed", err.Error())
		return
	}
	// best-effort disconnect on gateways (GAP-19)
	go s.notifyGatewaysDisconnect("agent", caName, serial)
	recordCertRevoked(caName)
	s.auditLog(r, "cert_revoke",
		fmt.Sprintf("ca=%s serial=%s reason=%d cascade=%d", caName, serial, reason, cascaded))
	resp := map[string]any{"status": "revoked", "ca": caName, "serial": serial}
	if cascaded > 0 {
		resp["cascade_count"] = cascaded
	}
	apiOK(w, resp)
}

// ---- POST /api/v1/user/revoke-all ----

func (s *Server) apiUserRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records so recently issued AIC certs of this user
	// are visible to the DB revoke UPDATE.
	s.FlushRecordBuffer()

	// Extract principalUid from mTLS client cert AIC extension.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.apiErr(w, r, http.StatusUnauthorized, "api.mtls_required", "mTLS client certificate required")
		return
	}
	aic, err := ca.ParseAIC(r.TLS.PeerCertificates[0])
	if err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.aic_parse_failed", err.Error())
		return
	}
	if aic == nil || aic.PrincipalUid.String() == ":" {
		s.apiErr(w, r, http.StatusBadRequest, "api.no_principal_uid", "certificate has no PrincipalUid in AIC extension")
		return
	}

	reason := 2 // cACompromise as default for user-initiated mass revoke
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Reason != "" {
		if r, err := ca.ParseRevokeReason(req.Reason); err == nil {
			reason = r
		}
	}

	count, err := s.revokeByPrincipalUid(aic.PrincipalUid.String(), reason)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_all_failed", err.Error())
		return
	}
	// best-effort disconnect on gateways (GAP-19)
	go s.notifyGatewaysDisconnectUser(aic.PrincipalUid.String())
	apiOK(w, map[string]any{
		"status":        "ok",
		"principal_uid": aic.PrincipalUid.String(),
		"revoked_count": count,
	})
}

// ---- POST /api/v1/certs/revoke-by-principal ----
func (s *Server) apiRevokeByPrincipal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records so recently issued certs of this principal
	// are visible to the DB revoke UPDATE.
	s.FlushRecordBuffer()
	var req struct {
		PrincipalUid string `json:"principal_uid"`
		Reason       string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.PrincipalUid == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.principal_uid_required", "")
		return
	}
	reason := 0
	if req.Reason != "" {
		if r, err := ca.ParseRevokeReason(req.Reason); err == nil {
			reason = r
		}
	}
	count, err := s.revokeByPrincipalUid(req.PrincipalUid, reason)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_failed", err.Error())
		return
	}
	apiOK(w, map[string]any{
		"status":        "ok",
		"principal_uid": req.PrincipalUid,
		"revoked_count": count,
	})
}

// ---- POST /api/v1/sub-ca/{name}/revoke-all ----
func (s *Server) apiRevokeSubCAAll(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records so recently issued certs of this sub-CA
	// are visible to the DB revoke UPDATE.
	s.FlushRecordBuffer()
	// Admin cert scope must cover the target sub-CA (in addition to any
	// enterprise-mode checkCAScope applied by the routes engine).
	if err := s.verifyAdminCert(r, name); err != nil {
		s.apiErr(w, r, http.StatusUnauthorized, "sub_ca.unauthorized", err.Error())
		return
	}
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	reason := 0
	if req.Reason != "" {
		if r, err := ca.ParseRevokeReason(req.Reason); err == nil {
			reason = r
		}
	}
	count, err := s.revokeBySubCA(name, reason)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_failed", err.Error())
		return
	}
	apiOK(w, map[string]any{
		"status":        "ok",
		"sub_ca":        name,
		"revoked_count": count,
	})
}

// ---- POST /api/v1/certs/revoke-batch ----
// Revocation-storm endpoint: revoke many certificates in one call. With the
// memory engine enabled the batch is applied in memory under a single lock
// (immediately visible to reads — "memory is truth") and persisted
// asynchronously; the DB path uses a single transaction.
func (s *Server) apiRevokeCertsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records so recently issued certs are visible to the
	// DB fallback UPDATEs.
	s.FlushRecordBuffer()

	var req struct {
		Entries []struct {
			CA     string `json:"ca"`
			Serial string `json:"serial"`
			Reason string `json:"reason,omitempty"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if len(req.Entries) == 0 {
		s.apiErr(w, r, http.StatusBadRequest, "api.batch_empty", "")
		return
	}

	entries := make([]db.RevokeBatchEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		if e.CA == "" || e.Serial == "" {
			s.apiErr(w, r, http.StatusBadRequest, "api.batch_entry_required", "")
			return
		}
		reason := 0
		if e.Reason != "" {
			if rr, err := ca.ParseRevokeReason(e.Reason); err == nil {
				reason = rr
			}
		}
		entries = append(entries, db.RevokeBatchEntry{CA: e.CA, Serial: e.Serial, Reason: reason})
	}

	count, err := s.revokeCertsBatch(entries)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.revoke_failed", err.Error())
		return
	}
	// Best-effort disconnect on gateways for all affected serials.
	go func() {
		for _, e := range entries {
			s.notifyGatewaysDisconnect("agent", e.CA, e.Serial)
		}
	}()
	if count > 0 {
		recordCertRevoked("")
	}
	apiOK(w, map[string]any{
		"status":        "ok",
		"revoked_count": count,
	})
}

// ---- POST /api/v1/cert/{ca}/{serial}/renew ----

func (s *Server) apiRenewCert(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	// Flush buffered issue records first so the source cert is visible to the
	// DB lookup (avoids the ≤500ms issue→flush visibility window).
	s.FlushRecordBuffer()
	cfg := s.getConfig()
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found_fmt", caName)
		return
	}
	if s.rl != nil {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		if !s.rl.AllowCA(ip, caName) {
			s.apiErr(w, r, http.StatusTooManyRequests, "api.too_many_requests", "")
			return
		}
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_ca_failed", err.Error())
		return
	}
	records, err := s.getDB().ListCerts(caName)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.list_certs_failed", err.Error())
		return
	}
	var oldCN string
	for _, rec := range records {
		if rec.SerialNumber == serial {
			oldCN = rec.CommonName
			break
		}
	}
	if oldCN == "" {
		s.apiErr(w, r, http.StatusNotFound, "api.cert_not_found", "")
		return
	}
	privKey, err := ca.GenerateKey(cfg.Defaults.KeyType)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.key_gen_failed", err.Error())
		return
	}
	sc := &ca.SignConfig{
		DB:             s.getDB(),
		SkipDB:         s.addCertRecordEnabled(), // In-memory engine / buffer batch mode: issue only, no DB write
		CAKey:          issuerKey,
		CACert:         issuerCert,
		CAName:         caName,
		SubjectPubKey:  privKey.Public(),
		CommonName:     oldCN,
		Profile:        ca.ProfileTLSServer,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
		Validity:       365 * 24 * time.Hour,
		DefaultCountry: cfg.Defaults.DefaultCountry,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
		PolicyFile:     cfg.Policy,
		RequirePolicy:  s.requirePolicy(),
	}
	result, err := ca.Sign(sc)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.sign_failed", err.Error())
		return
	}
	if err := s.addCertRecord(result.Record); err != nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests", err.Error())
		return
	}
	keyPEM, err := ca.KeyToPEM(privKey)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.key_pem_failed", err.Error())
		return
	}
	apiOK(w, issueResp{
		SerialNumber: result.SerialHex,
		CommonName:   result.Cert.Subject.CommonName,
		CertPEM:      string(ca.CertToPEM(result.CertDER)),
		KeyPEM:       string(keyPEM),
		CA:           caName,
	})
}

// ---- POST /api/v1/crl/{ca}/generate ----

// crlNumberStore returns a DB-backed ca.CRLNumberStore for persisting CRL
// numbers across restarts (H12 fix). Returns nil when the DB is unavailable
// (e.g. pure-memory engine mode with no DB handle).
func (s *Server) crlNumberStore() ca.CRLNumberStore {
	d := s.getDB()
	if d == nil {
		return nil
	}
	return d
}

func (s *Server) apiGenerateCRL(w http.ResponseWriter, r *http.Request, caName string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	cfg := s.getConfig()
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found_fmt", caName)
		return
	}
	caCert, caKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_ca_failed", err.Error())
		return
	}
	cfgCRL := &ca.CRLConfig{
		DB:                   s.getDB(),
		RevokedEntriesSource: s.revokedEntriesSource(),
		CACert:               caCert,
		CAKey:                caKey,
		CAName:               caName,
		ValidityDays:         90,
		NumberStore:          s.crlNumberStore(),
	}
	crlDER, err := ca.GenerateCRL(cfgCRL)
	if r.URL.Query().Get("delta") == "1" || r.URL.Query().Get("delta") == "true" {
		sinceStr := r.URL.Query().Get("since")
		var sinceTime time.Time
		if sinceStr != "" {
			sinceTime, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				s.apiErr(w, r, http.StatusBadRequest, "api.invalid_since", err.Error())
				return
			}
		} else {
			sinceTime = cfgCRL.LastThisUpdate
		}
		if sinceTime.IsZero() {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_since", "delta requires since or a recorded last thisUpdate")
			return
		}
		crlDER, err = ca.GenerateDeltaCRL(cfgCRL, &ca.DeltaCRLConfig{
			Since:         sinceTime,
			BaseCRLNumber: cfgCRL.LastCRLNumber,
		})
	}
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.crl_gen_failed", err.Error())
		return
	}

	// Persist the CRL to the configured output dir (same as the CLI
	// `pki crl generate`), so /healthz CRL freshness reflects it and
	// CRL distribution points serve the freshly-generated file.
	if outDir := cfg.CRL.OutputDir; outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err == nil {
			crlPath := filepath.Join(outDir, ca.CRLFilename(caName, -1, 0))
			if r.URL.Query().Get("delta") == "1" || r.URL.Query().Get("delta") == "true" {
				crlPath = filepath.Join(outDir, ca.SanitizeCAName(caName)+".delta.crl")
			}
			if werr := os.WriteFile(crlPath, crlDER, 0o644); werr != nil {
				slog.Warn("api/crl: persist CRL failed", "ca", caName, "path", crlPath, "error", werr)
			}
		}
	}

	apiOK(w, map[string]interface{}{
		"ca":     caName,
		"delta":  r.URL.Query().Get("delta") == "1" || r.URL.Query().Get("delta") == "true",
		"length": len(crlDER),
	})
}

// ---- Helpers ----

func splitSANs(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// apiConstraintsToCA converts API authorization_constraints into a ca.Capability list.
// Constraints are written into AIC extension field 7, enforced offline by the gateway via CheckAuthorizationConstraints.
func apiConstraintsToCA(cs []struct {
	SchemeId     string `json:"scheme_id"`
	CapabilityId string `json:"capability_id"`
	Parameters   []byte `json:"parameters,omitempty"`
}) []ca.Capability {
	if len(cs) == 0 {
		return nil
	}
	out := make([]ca.Capability, 0, len(cs))
	for _, c := range cs {
		out = append(out, ca.Capability{
			SchemeId:     c.SchemeId,
			CapabilityId: c.CapabilityId,
			Parameters:   c.Parameters,
		})
	}
	return out
}

func parseDN(s string) pkix.Name {
	var n pkix.Name
	parts := strings.Split(s, "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		key := p[:eq]
		val := p[eq+1:]
		switch strings.ToUpper(key) {
		case "CN":
			n.CommonName = val
		case "C":
			n.Country = []string{val}
		case "ST":
			n.Province = []string{val}
		case "L":
			n.Locality = []string{val}
		case "O":
			n.Organization = []string{val}
		case "OU":
			n.OrganizationalUnit = []string{val}
		}
	}
	return n
}

// ---- POST /api/v1/cert/{ca}/{serial}/export — Export PFX ----

// apiExportCert handles POST /api/v1/cert/{ca}/{serial}/export
func (s *Server) apiExportCert(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	records, err := s.getDB().ListCerts(caName)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.list_certs_failed", err.Error())
		return
	}
	for _, rec := range records {
		if rec.SerialNumber == serial {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(ca.CertToPEM(rec.CertDER))
			return
		}
	}
	s.apiErr(w, r, http.StatusNotFound, "api.cert_not_found", "")
}

// ─── DNS Management API (via main port) ─────────────────────────

func (s *Server) apiDNSHealth(w http.ResponseWriter, r *http.Request) {
	apiOK(w, map[string]string{"status": "ok"})
}

// apiDNSList handles GET /api/v1/dns/records
func (s *Server) apiDNSList(w http.ResponseWriter, r *http.Request) {
	// DNS records not available in main server context
	apiOK(w, []map[string]string{})
}

// apiDNSACME handles PUT /api/v1/dns/acme-challenge/{domain}
func (s *Server) apiDNSACME(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/v1/dns/acme-challenge/")
	if domain == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.domain_required", "")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var body struct {
			KeyAuth string `json:"key_auth"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", "")
			return
		}
		apiOK(w, map[string]string{"status": "set", "domain": domain})
	default:
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.put_required", "")
	}
}

// apiDNSCERT handles GET /api/v1/dns/cert/{domain}
func (s *Server) apiDNSCERT(w http.ResponseWriter, r *http.Request) {
	s.apiErr(w, r, http.StatusNotImplemented, "api.cert_management_via_dns", "")
}

// ─── DNS over HTTPS (DoH) ───────────────────────────────────────
// GET  /dns-query?name=_acme-challenge.x.com&type=TXT
// POST /dns-query (Content-Type: application/dns-message)

var dnsTypeMap = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
	"TXT": 16, "AAAA": 28, "SRV": 33, "CERT": 37, "TLSA": 52,
}

func (s *Server) apiDNSQuery(w http.ResponseWriter, r *http.Request) {
	// GET mode: JSON query (?name=X&type=TXT)
	if r.Method == http.MethodGet {
		name := dns.Fqdn(r.URL.Query().Get("name"))
		qtypeStr := r.URL.Query().Get("type")
		if name == "" || name == "." {
			s.apiErr(w, r, http.StatusBadRequest, "api.name_required", "")
			return
		}
		qtype := dns.TypeTXT
		if qtypeStr != "" {
			if t, ok := dnsTypeMap[qtypeStr]; ok {
				qtype = t
			}
		}
		// Try local DNS server first, then upstream
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		// Use upstream resolver
		c := &dns.Client{Timeout: 5 * time.Second}
		resolvers := []string{"119.29.29.29:53", "180.76.76.76:53", "208.67.220.220:53", "1.1.1.1:53"}
		for _, r := range resolvers {
			in, _, err := c.Exchange(m, r)
			if err != nil {
				continue
			}
			results := []map[string]string{}
			for _, ans := range in.Answer {
				switch v := ans.(type) {
				case *dns.TXT:
					for _, txt := range v.Txt {
						results = append(results, map[string]string{"type": "TXT", "value": txt})
					}
				case *dns.A:
					results = append(results, map[string]string{"type": "A", "value": v.A.String()})
				case *dns.AAAA:
					results = append(results, map[string]string{"type": "AAAA", "value": v.AAAA.String()})
				}
			}
			apiOK(w, map[string]interface{}{"name": name, "answers": results})
			return
		}
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		return
	}
	s.apiErr(w, r, http.StatusMethodNotAllowed, "api.get_required", "")
}

// ---- POST /api/v1/agent/register ----

func (s *Server) apiAgentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// Must use mTLS client certificate
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.apiErr(w, r, http.StatusUnauthorized, "api.mtls_required", "mTLS client certificate required")
		return
	}

	cert := r.TLS.PeerCertificates[0]

	// Prefer extracting agentId from AIC extension
	aic, aicErr := ca.ParseAIC(cert)
	var agentId, principalUid string
	if aicErr == nil && aic != nil {
		agentId = aic.AgentId
		principalUid = aic.PrincipalUid.String()
	} else {
		// Fallback: get from request body
		var req struct {
			AgentId      string   `json:"agent_id"`
			PrincipalUid string   `json:"principal_uid"`
			Capabilities []string `json:"capabilities,omitempty"`
		}
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&req)
		}
		agentId = req.AgentId
		principalUid = req.PrincipalUid
	}

	if agentId == "" || principalUid == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.missing_fields", "agent_id and principal_uid required")
		return
	}

	// Validate principalUid matches the current user (prevent impersonation)
	user, err := s.authenticate(r)
	if err != nil || user == nil {
		s.apiErr(w, r, http.StatusUnauthorized, "api.unauthorized", "")
		return
	}

	apiOK(w, map[string]any{
		"status":        "ok",
		"agent_id":      agentId,
		"principal_uid": principalUid,
	})
}

// ── POST /api/v1/aic/issue — Issue Agent Identity Certificate ─────────────
//
// Security constraints:
//  1. The user certificate's Issuing CA must match the CA issuing the AIC (cross-CA prohibited)
//  2. The user must sign the DelegationAuthorization with their private key (explicit delegation consent)
//  3. Varwof Core verifies the signature before issuing the AIC
//
// Request body:
//
//	{
//	  "agent_id": "agent-001",
//	  "principal_uid": "user@example.com",
//	  "capabilities": [{"scheme_id":"varwof/demo-mysql-v1","capability_id":"SELECT:*"}],
//	  "duration": "5m",
//	  "key_type": "ecdsa-p256",
//	  "ou": ["gateway:ops"],
//	  "delegation": {
//	    "user_cert_hash": "base64...",
//	    "signature": "base64...",
//	    "algo": "ECDSA-SHA256",
//	    "nonce": "base64...",
//	    "timestamp": 1234567890
//	  }
//	}
func (s *Server) apiIssueAIC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}

	// 1. Must use mTLS
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.apiErr(w, r, http.StatusUnauthorized, "api.mtls_required", "mTLS client certificate required")
		return
	}

	userCert := r.TLS.PeerCertificates[0]

	// 2. Agent-to-Agent delegation is prohibited (single-level delegation only)
	if requesterAIC, _ := ca.ParseAIC(userCert); requesterAIC != nil {
		s.apiErr(w, r, http.StatusForbidden, "api.agent_delegation_denied",
			"certificate requester is itself an Agent; Agent->Agent delegation is prohibited")
		return
	}

	// 3. Parse request body
	var req struct {
		AgentID      string             `json:"agent_id"`
		PrincipalUID string             `json:"principal_uid"`
		Capabilities []ca.Capability    `json:"capabilities"`
		Duration     string             `json:"duration"`
		KeyType      string             `json:"key_type"`
		OU           []string           `json:"ou"`
		Delegation   *delegationSigJSON `json:"delegation"`
		CSRPEM       string             `json:"csr_pem"` // Optional: client sends CSR (recommended mode)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_json", err.Error())
		return
	}
	if req.AgentID == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.agent_id_required", "")
		return
	}
	if req.PrincipalUID == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.principal_uid_required", "")
		return
	}
	if len(req.Capabilities) == 0 {
		s.apiErr(w, r, http.StatusBadRequest, "api.aic_capabilities_required",
			"AIC must declare at least one capability; empty-capability AICs grant no permissions")
		return
	}

	// 4. ★ Delegation signature is required (explicit user consent)
	if req.Delegation == nil {
		s.apiErr(w, r, http.StatusForbidden, "api.delegation_required",
			"delegation authorization signature is required; user must explicitly approve agent delegation")
		return
	}

	// 5. Determine issuing CA (use default CA)
	cfg := s.getConfig()
	caName := cfg.Defaults.CA
	if caName == "" {
		s.apiErr(w, r, http.StatusInternalServerError, "api.no_default_ca", "")
		return
	}
	caCfg, ok := cfg.CAs[caName]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found_fmt", caName)
		return
	}

	// 6. Load CA signer
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(caName, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_ca_failed", err.Error())
		return
	}

	// 7. ★ Core security check: user certificate's Issuing CA must match the issuing CA
	//    user certificate AKI == issuing CA certificate SKI
	if len(userCert.AuthorityKeyId) > 0 && len(issuerCert.SubjectKeyId) > 0 {
		if !bytesEqual(userCert.AuthorityKeyId, issuerCert.SubjectKeyId) {
			s.apiErr(w, r, http.StatusForbidden, "api.issuer_ca_mismatch",
				"user certificate issuer CA does not match the issuing CA; cross-CA AIC issuance is prohibited")
			return
		}
	} else {
		// AKI/SKI unavailable, fall back to Subject matching
		if userCert.Issuer.CommonName != issuerCert.Subject.CommonName {
			s.apiErr(w, r, http.StatusForbidden, "api.issuer_ca_mismatch",
				"user certificate issuer does not match the issuing CA")
			return
		}
	}

	// 8. ★ Verify delegation signature
	//    Reconstruct delegation message → SHA256 → verify with user certificate public key
	//    User certificate is located via SPKI hash (PrincipalUid.KeyHash), no longer compared separately with UserCertHash

	// Reconstruct delegation message (consistent with client-side signing)
	delegationMsg := delegationMessageJSON{
		AgentID:      req.AgentID,
		PrincipalUID: req.PrincipalUID,
		Capabilities: req.Capabilities,
		Timestamp:    req.Delegation.Timestamp,
		Nonce:        req.Delegation.Nonce,
		LifetimeSec:  req.Delegation.LifetimeSec,
	}
	msgBytes, err := json.Marshal(delegationMsg)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.delegation_marshal_failed", err.Error())
		return
	}

	hash := sha256.Sum256(msgBytes)

	// Verify signature based on algorithm type
	var verifyErr error
	switch userCert.PublicKeyAlgorithm {
	case x509.ECDSA:
		verifyErr = verifyECDSASignature(userCert, hash[:], req.Delegation.Signature)
	case x509.RSA:
		verifyErr = verifyRSASignature(userCert, hash[:], req.Delegation.Signature)
	default:
		s.apiErr(w, r, http.StatusBadRequest, "api.unsupported_key_algorithm",
			"user certificate uses unsupported key algorithm")
		return
	}

	if verifyErr != nil {
		s.apiErr(w, r, http.StatusForbidden, "api.delegation_signature_invalid",
			verifyErr.Error())
		return
	}

	// 9. Check if delegation authorization has expired
	if req.Delegation.LifetimeSec > 0 && time.Since(time.Unix(req.Delegation.Timestamp, 0)) > time.Duration(req.Delegation.LifetimeSec)*time.Second {
		s.apiErr(w, r, http.StatusForbidden, "api.delegation_expired",
			fmt.Sprintf("delegation expired (lifetime=%ds)", req.Delegation.LifetimeSec))
		return
	}

	// 9.0 DA timestamp freshness defense (P1-B-13): |now - timestamp| ≤ da_max_timestamp_skew.
	// Together with nonce uniqueness, forms a "short time window second line of defense" —
	// delaying too long after signing the DA before submitting for issuance is suspicious.
	if req.Delegation.Timestamp > 0 {
		if err := s.checkDATimestampFreshness(time.Unix(req.Delegation.Timestamp, 0)); err != nil {
			s.apiErr(w, r, http.StatusForbidden, "api.da_timestamp_stale", err.Error())
			return
		}
	}

	// 9.1 DA nonce anti-replay (06-delegation-auth.md §Nonce Lifecycle): the CA persists
	//     the nonce at issuance; the same nonce cannot be used to mint again.
	//     Only performs replay check on the nonce carried by the client signature;
	//     when not provided, the server generates a random 32B nonce (see step 12),
	//     with no replay surface.
	if len(req.Delegation.Nonce) == 32 {
		exp := daNonceExpiry(req.Delegation.Timestamp, int64(req.Delegation.LifetimeSec), s.daTimestampSkew(), s.getEngineNonceTTL())
		if err := s.storeDANonce(req.Delegation.Nonce, exp); err != nil {
			if errors.Is(err, db.ErrDuplicateNonce) {
				s.apiErr(w, r, http.StatusForbidden, "api.da_nonce_replayed",
					"delegation authorization nonce was already used to mint an AIC; replay rejected")
				return
			}
			if errors.Is(err, engine.ErrBackpressure) {
				s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests",
					"da nonce write pipeline full, retry later")
				return
			}
			s.apiErr(w, r, http.StatusInternalServerError, "api.da_nonce_store_failed", err.Error())
			return
		}
	}

	slog.Info("api/aic/issue: delegation signature verified",
		"agent_id", req.AgentID,
		"principal_uid", req.PrincipalUID,
		"user_cn", userCert.Subject.CommonName)

	// 9. Parse validity duration
	duration := 5 * time.Minute
	if req.Duration != "" {
		if d, err := time.ParseDuration(req.Duration); err == nil && d > 0 && d <= 24*time.Hour {
			duration = d
		}
	}

	// 10. Obtain public key — two modes
	var pubKey crypto.PublicKey
	var serverGeneratedKey crypto.Signer

	if req.CSRPEM != "" {
		// ★ CSR mode (recommended): client generates key locally, sends CSR
		csrBlock, _ := pem.Decode([]byte(req.CSRPEM))
		if csrBlock == nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr", "failed to decode CSR PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr", err.Error())
			return
		}
		if err := csr.CheckSignature(); err != nil {
			s.apiErr(w, r, http.StatusBadRequest, "api.invalid_csr_signature", err.Error())
			return
		}
		pubKey = csr.PublicKey
		slog.Info("api/aic/issue: CSR mode (client-generated key)", "agent_id", req.AgentID)
	} else {
		// Server-side key generation (convenience mode, suitable for web and other applications)
		keyType := req.KeyType
		if keyType == "" {
			keyType = "ecdsa-p256"
		}
		privKey, err := ca.GenerateKey(keyType)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.key_gen_failed", err.Error())
			return
		}
		pubKey = privKey.Public()
		serverGeneratedKey = privKey
		slog.Info("api/aic/issue: server-keygen mode", "agent_id", req.AgentID)
	}

	// 11. Construct OU
	ou := req.OU
	if len(ou) == 0 {
		ou = []string{"gateway:ops"}
	}
	// M24 fix: client-controlled OU must not carry wildcard roles ("*",
	// "gateway:*") that HasRole interprets as matching any role.
	if err := auth.ValidateOUS(ou); err != nil {
		s.apiErr(w, r, http.StatusBadRequest, "api.invalid_ou", err.Error())
		return
	}

	// 12. Construct DelegationAuthorization (embedded in AIC extension).
	//     If the client did not provide a nonce (< 32B), a random nonce is issued for
	//     anti-replay (signature was already verified in previous steps).
	nonce := req.Delegation.Nonce
	if len(nonce) != 32 {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.nonce_generation_failed", err.Error())
			return
		}
	}
	userAuth := &ca.DelegationAuthorization{
		Reason:             ca.Reason{ReasonCode: "API_ISSUE", Description: "user-authorized AIC issuance"},
		SignatureValue:     req.Delegation.Signature,
		SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: selectSigAlgo(req.Delegation.Algo)},
		Timestamp:          time.Unix(req.Delegation.Timestamp, 0),
		Nonce:              nonce,
		RequestedLifetime:  req.Delegation.LifetimeSec,
	}

	// 13. Construct SignConfig
	sc := &ca.SignConfig{
		DB:                    s.getDB(),
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                caName,
		SubjectPubKey:         pubKey,
		CommonName:            req.AgentID,
		Subject:               &pkix.Name{CommonName: req.AgentID, OrganizationalUnit: ou},
		CRLBaseURL:            cfg.CRL.CRLBaseURL,
		Validity:              duration,
		DefaultCountry:        cfg.Defaults.DefaultCountry,
		DefaultOrg:            cfg.Defaults.DefaultOrg,
		Profile:               ca.ProfileAgentProxy,
		MaxAgentProxyValidity: s.agentProxyMaxValidity(),
		AIC: &ca.AICConfig{
			AgentId:                 req.AgentID,
			PrincipalUid:            ca.PrincipalUid{Realm: "pki", Identifier: req.PrincipalUID, KeyHash: ca.SPKIHash(pubKey)},
			Capabilities:            req.Capabilities,
			DelegationAuthorization: userAuth,
		},
		ValidateCapabilities: s.validateCapabilities,
	}

	// 14. Sign
	result, err := ca.Sign(sc)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.sign_failed", err.Error())
		return
	}

	// 15. Encode response
	certPEM := pemEncode("CERTIFICATE", result.CertDER)

	resp := map[string]string{
		"cert_pem":      certPEM,
		"serial_number": result.SerialHex,
		"ca":            caName,
	}

	// Only return key_pem when the server generated the key
	if serverGeneratedKey != nil {
		keyDER, err := x509MarshalPKCS8PrivateKey(serverGeneratedKey)
		if err != nil {
			s.apiErr(w, r, http.StatusInternalServerError, "api.key_encode_failed", err.Error())
			return
		}
		resp["key_pem"] = pemEncode("PRIVATE KEY", keyDER)
	}

	writeJSON(w, resp)
}

// ── Delegation signature JSON types ──────────────────────────────────────

type delegationSigJSON struct {
	Signature   []byte `json:"signature"`
	Algo        string `json:"algo"`
	Nonce       []byte `json:"nonce"`
	Timestamp   int64  `json:"timestamp"`
	LifetimeSec int    `json:"lifetime_sec"`
}

type delegationMessageJSON struct {
	AgentID      string          `json:"agent_id"`
	PrincipalUID string          `json:"principal_uid"`
	Capabilities []ca.Capability `json:"capabilities"`
	Timestamp    int64           `json:"timestamp"`
	Nonce        []byte          `json:"nonce"`
	LifetimeSec  int             `json:"lifetime_sec"`
}

// selectSigAlgo selects the OID based on the algorithm name.
func selectSigAlgo(name string) asn1.ObjectIdentifier {
	switch name {
	case "RSA-SHA256":
		return ca.OIDSigRSAWithSHA256
	case "RSA-PSS-SHA256":
		return ca.OIDSigRSAPSSWithSHA256
	default:
		return ca.OIDSigECDSAWithSHA256
	}
}

// verifyECDSASignature verifies an ECDSA signature.
func verifyECDSASignature(cert *x509.Certificate, digest, sig []byte) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not ECDSA public key")
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyRSASignature verifies an RSA PKCS#1 v1.5 signature.
func verifyRSASignature(cert *x509.Certificate, digest, sig []byte) error {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not RSA public key")
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}

// resolveDAUserCert resolves the DA signer (user) certificate:
//  1. Request body user_cert_pem (populated by client, DA signer certificate)
//  2. mTLS peer cert (can be used as user certificate only when SPKI matches principal_uid.keyHash)
//
// Both must satisfy SPKI == keyHash (if keyHash is non-empty) to prevent certificate mismatch/forgery.
func resolveDAUserCert(r *http.Request, userCertPEM string, pu ca.PrincipalUid) (*x509.Certificate, error) {
	var candidates []*x509.Certificate
	if userCertPEM != "" {
		block, _ := pem.Decode([]byte(userCertPEM))
		if block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				candidates = append(candidates, cert)
			}
		}
	}
	if r.TLS != nil {
		for _, peer := range r.TLS.PeerCertificates {
			candidates = append(candidates, peer)
		}
	}
	for _, cert := range candidates {
		if len(pu.KeyHash) > 0 {
			spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if !bytes.Equal(spkiHash[:], pu.KeyHash) {
				continue
			}
		}
		return cert, nil
	}
	if userCertPEM != "" {
		return nil, fmt.Errorf("verify_delegation_auth: user_cert_pem does not match principal_uid.keyHash")
	}
	return nil, fmt.Errorf("verify_delegation_auth: no user certificate available (provide user_cert_pem or use mTLS)")
}

// parseOIDStr parses a dotted-decimal OID string (e.g. "1.2.840.10045.4.3.2") into an asn1.ObjectIdentifier.
func parseOIDStr(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		oid[i] = v
	}
	return oid, nil
}

// ---- GET /api/v1/cert/by-key — Find certificate by public key hash ----

func (s *Server) apiFindCertByKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		s.apiErr(w, r, http.StatusBadRequest, "api.hash_required",
			"hash parameter (SHA-256 hex of SPKI DER) is required")
		return
	}
	caName := r.URL.Query().Get("ca")
	status := r.URL.Query().Get("status")
	certs, err := s.getCertBySPKIHash(hash, caName, status)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.query_failed", err.Error())
		return
	}
	list := make([]jsonCert, 0, len(certs))
	for _, c := range certs {
		list = append(list, certToJSON(c, false))
	}
	if list == nil {
		list = []jsonCert{}
	}
	writeJSON(w, list)
}

// ---- POST /api/v1/cert/{ca}/{serial}/re-sign — Re-sign certificate (same key, possibly new CA) ----

type reSignReq struct {
	TargetCA string `json:"target_ca,omitempty"`
	Profile  string `json:"profile,omitempty"`
	Validity int    `json:"validity,omitempty"`
}

// apiReSignCert handles POST /api/v1/cert/{ca}/{serial}/re-sign
func (s *Server) apiReSignCert(w http.ResponseWriter, r *http.Request, caName, serial string) {
	if r.Method != http.MethodPost {
		s.apiErr(w, r, http.StatusMethodNotAllowed, "api.method_not_allowed", "")
		return
	}
	var req reSignReq
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}

	// Flush buffered issue records first so the source cert is visible.
	s.FlushRecordBuffer()

	// Load the existing certificate record
	oldRec, err := s.getCertRecord(caName, serial)
	if err != nil {
		s.apiErr(w, r, http.StatusNotFound, "api.cert_not_found", "")
		return
	}
	oldCert, err := x509.ParseCertificate(oldRec.CertDER)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.parse_cert_failed", err.Error())
		return
	}

	// Determine target CA
	targetCA := req.TargetCA
	if targetCA == "" {
		targetCA = caName
	}

	cfg := s.getConfig()
	caCfg, ok := cfg.CAs[targetCA]
	if !ok {
		s.apiErr(w, r, http.StatusNotFound, "api.ca_not_found_fmt", targetCA)
		return
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, s.resolvePassword(targetCA, caCfg.Password))
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.load_ca_failed", err.Error())
		return
	}

	validity := req.Validity
	if validity <= 0 {
		validity = 365
	}

	sc := &ca.SignConfig{
		DB:                    s.getDB(),
		SkipDB:                s.addCertRecordEnabled(), // In-memory engine / buffer batch mode: issue only, no DB write
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                targetCA,
		SubjectPubKey:         oldCert.PublicKey,
		CommonName:            oldRec.CommonName,
		SANs:                  splitSANs(oldRec.SAN),
		Profile:               ca.Profile(req.Profile),
		KeyType:               oldRec.KeyAlgo,
		MaxAgentProxyValidity: s.agentProxyMaxValidity(), // agent-proxy re-issue also subject to validity upper bound
		CRLBaseURL:            cfg.CRL.CRLBaseURL,
		Validity:              time.Duration(validity) * 24 * time.Hour,
		DefaultCountry:        cfg.Defaults.DefaultCountry,
		DefaultOrg:            cfg.Defaults.DefaultOrg,
		PolicyFile:            cfg.Policy,
		RequirePolicy:         s.requirePolicy(),
	}
	if sc.Profile == "" {
		sc.Profile = ca.Profile(oldRec.Profile)
	}
	if sc.Profile == "" {
		sc.Profile = ca.ProfileTLSServer
	}

	result, err := ca.Sign(sc)
	if err != nil {
		s.apiErr(w, r, http.StatusInternalServerError, "api.sign_failed", err.Error())
		return
	}
	if err := s.addCertRecord(result.Record); err != nil {
		s.apiErr(w, r, http.StatusServiceUnavailable, "api.too_many_requests", err.Error())
		return
	}

	apiOK(w, issueResp{
		SerialNumber: result.SerialHex,
		CommonName:   result.Cert.Subject.CommonName,
		CertPEM:      string(ca.CertToPEM(result.CertDER)),
		CA:           targetCA,
	})
}

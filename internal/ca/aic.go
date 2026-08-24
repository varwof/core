// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	pki "github.com/varwof/types"
)

// AlgorithmIdentifier is the ASN.1 algorithm identifier (I-D §6 AlgorithmIdentifier).
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Signature algorithm OID constants.
var (
	OIDSigECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSigECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSigECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSigRSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSigRSAWithSHA384    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSigRSAWithSHA512    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSigRSAPSSWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSigEd25519          = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// DelegationMode defines the Agent's delegation mode.
type DelegationMode int

const (
	DelegationAuthorized     DelegationMode = 0 // Authorized delegation (Agent acts on behalf of user)
	DelegationRepresentative DelegationMode = 1 // Full representation (Agent fully represents user)
)

// HashAlgoOIDs maps hash algorithm name strings to OIDs.
var HashAlgoOIDs = map[string]asn1.ObjectIdentifier{
	"sha256":   {2, 16, 840, 1, 101, 3, 4, 2, 1},
	"sha384":   {2, 16, 840, 1, 101, 3, 4, 2, 2},
	"sha512":   {2, 16, 840, 1, 101, 3, 4, 2, 3},
	"sha3-256": {2, 16, 840, 1, 101, 3, 4, 2, 8},
	"sha3-384": {2, 16, 840, 1, 101, 3, 4, 2, 9},
	"sha3-512": {2, 16, 840, 1, 101, 3, 4, 2, 10},
	"sm3":      {1, 2, 156, 10197, 1, 401},
}

// ParseHashAlgo parses a hash algorithm string (e.g. "sha256") to an OID.
// Returns nil if empty (caller should use default SHA-256).
func ParseHashAlgo(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, nil
	}
	oid, ok := HashAlgoOIDs[strings.ToLower(s)]
	if !ok {
		return nil, fmt.Errorf("hash_algo: unsupported algorithm %q, supported: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512, sm3", s)
	}
	return oid, nil
}

// DefaultHashAlgo returns the default SHA-256 OID.
func DefaultHashAlgo() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
}

// PrincipalUid is the structured ASN.1 type for principal identity (spec §3.2).
// ASN.1 SEQUENCE: { version INTEGER { v1(1) }, realm UTF8String, identifier UTF8String,
//
//	keyHash OCTET STRING (SIZE(1..64)), hashAlgo [0] EXPLICIT AlgorithmIdentifier OPTIONAL }
//
// keyHash = hashAlgo(SPKI); hashAlgo defaults to SHA-256 when omitted.
// Communication format: {realm}:{identifier}:{keyFingerprint} (keyFingerprint is base64url encoded)
type PrincipalUid struct {
	Version    int                 `asn1:"default:1"`
	Realm      string              `asn1:"utf8"`
	Identifier string              `asn1:"utf8"`
	KeyHash    []byte              `asn1:"octet"`
	HashAlgo   AlgorithmIdentifier `asn1:"optional,omitempty,explicit,tag:0"`
}

// HashAlgoOID returns the actually effective hash algorithm OID (empty → default SHA-256).
func (pu PrincipalUid) HashAlgoOID() asn1.ObjectIdentifier {
	if len(pu.HashAlgo.Algorithm) == 0 {
		return DefaultHashAlgo()
	}
	return pu.HashAlgo.Algorithm
}

// String returns the communication format {realm}:{identifier}:{keyFingerprint} (spec §3.2).
func (pu PrincipalUid) String() string {
	fp := base64.RawURLEncoding.EncodeToString(pu.KeyHash)
	return pu.Realm + ":" + pu.Identifier + ":" + fp
}

// ParsePrincipalUid parses a communication-format PrincipalUid string.
func ParsePrincipalUid(s string) (PrincipalUid, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: invalid format, expected {realm}:{identifier}:{keyFingerprint}")
	}
	if len(parts[0]) < 1 || len(parts[0]) > 128 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: realm length %d: must be 1-128", len(parts[0]))
	}
	if len(parts[1]) < 1 || len(parts[1]) > 256 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: identifier length %d: must be 1-256", len(parts[1]))
	}
	keyHash, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return PrincipalUid{}, fmt.Errorf("principal_uid: invalid keyFingerprint base64url: %w", err)
	}
	if len(keyHash) < 1 || len(keyHash) > 64 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: keyHash length %d: must be 1-64", len(keyHash))
	}
	if strings.Contains(parts[0], ":") || strings.Contains(parts[1], ":") {
		return PrincipalUid{}, fmt.Errorf("principal_uid: realm and identifier must not contain ':'")
	}
	return PrincipalUid{
		Version:    1,
		Realm:      parts[0],
		Identifier: parts[1],
		KeyHash:    keyHash,
		HashAlgo:   AlgorithmIdentifier{Algorithm: DefaultHashAlgo()},
	}, nil
}

// MakePrincipalUidFromCert constructs a PrincipalUid from a certificate (KeyHash = SPKI SHA-256, used for CA issuance).
func MakePrincipalUidFromCert(realm, identifier string, cert *x509.Certificate) PrincipalUid {
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	h := sha256.Sum256(pubBytes)
	return PrincipalUid{
		Version:    1,
		Realm:      realm,
		Identifier: identifier,
		KeyHash:    h[:],
		HashAlgo:   AlgorithmIdentifier{Algorithm: DefaultHashAlgo()},
	}
}

// SPKIHash returns the SPKI DER SHA-256 digest of the public key (v1.7.1 keyHash computation method).
func SPKIHash(pub crypto.PublicKey) []byte {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	h := sha256.Sum256(pubBytes)
	return h[:]
}

// Capability is the protocol-level capability container — Varwof only defines the container
// structure, not specific semantics. schemeId identifies the capability scheme (e.g. "varwof-gateway-v1"),
// capabilityId is the specific capability under that scheme, parameters are encoded as declared by schemeId.
//
// Encoding specification (consistent with pki-types Capability.FullID()):
// capabilityId is a pure action identifier (without scheme prefix), full permission identifier = schemeId + ":" + capabilityId,
// uniformly generated by FullID(); all matching/intersection/authorization decisions must be based on the full identifier.
type Capability struct {
	SchemeId     string `json:"scheme_id,omitempty" asn1:"utf8"`
	CapabilityId string `json:"capability_id,omitempty" asn1:"utf8"`
	Parameters   []byte `json:"parameters,omitempty" asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
}

// FullID returns the full capability identifier (schemeId:capacityId), semantically identical to pki-types Capability.FullID().
// When schemeId is empty, it degrades to capabilityId (compatible with generic capabilities without a scheme).
func (c Capability) FullID() string {
	if c.SchemeId == "" {
		return c.CapabilityId
	}
	return c.SchemeId + ":" + c.CapabilityId
}

// DelegationAuthorization is the cryptographic evidence of user authorization (v1.7.1 spec §DelegationAuthorization).
// Field order (consistent with pki-types): reason → requestedLifetime → timestamp → nonce →
// signatureAlgorithm → signatureValue. reason is required (authorization must have a reason).
// User certificate is located via PrincipalUid.KeyHash (SPKI SHA-256), no longer storing UserCertHash separately.
type DelegationAuthorization struct {
	Reason             Reason              `asn1:""`
	RequestedLifetime  int                 `asn1:"default:0"`
	Timestamp          time.Time           `asn1:"generalized"`
	Nonce              []byte              `asn1:"octet"` // 32-byte random number, anti-replay (REQUIRED)
	SignatureAlgorithm AlgorithmIdentifier `asn1:""`
	SignatureValue     []byte              `asn1:"octet"`
}

// Reason is the reason description for delegation authorization (v1.7.1 spec §Reason), for audit/display only, not participating in permission decisions.
// Both fields are required: reasonCode 1..64, description 1..512.
type Reason struct {
	ReasonCode  string `asn1:"utf8"`
	Description string `asn1:"utf8"`
}

// ExtField is a single extension field in the AIC internal extension slot. Vendors can use their own IANA PEN OIDs, users can use the Varwof-reserved .1.1.5.x space.
type ExtField struct {
	ExtnID    asn1.ObjectIdentifier `asn1:"objectidentifier"`
	Critical  bool                  `asn1:"default:false"`
	ExtnValue []byte                `asn1:"octet"`
}

// AIC is the X.509v3 extension ASN.1 structure (v1.7.1 spec §AIC).
// ASN.1 field order: version, agentId, principalUid, capabilities, delegationMode,
// authorizationConstraints [0], delegationAuthorization, extensions [1].
// delegationAuthorization is required by spec; Go encoding/asn1 cannot marshal "required but empty" DA
// (empty signature OID causes error), so the tag retains optional,omitempty; required semantics are enforced in ParseAIC/BuildAIC.
type AIC struct {
	Version                  int                     `asn1:"default:1"`
	AgentId                  string                  `asn1:"utf8"`
	PrincipalUid             PrincipalUid            `asn1:""`
	Capabilities             []Capability            `asn1:"sequence"`
	DelegationMode           DelegationMode          `asn1:"default:0"`
	AuthorizationConstraints []Capability            `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
	DelegationAuthorization  DelegationAuthorization `asn1:"optional,omitempty"`
	Extensions               []ExtField              `asn1:"optional,omitempty,contextspecific,explicit,tag:1"`
}

// AICConfig is the configuration needed to issue the AIC extension.
// BuildAIC uses required fields to construct the ASN.1 extension.
type AICConfig struct {
	AgentId                  string
	PrincipalUid             PrincipalUid
	DelegationMode           DelegationMode
	Capabilities             []Capability
	AuthorizationConstraints []Capability
	DelegationAuthorization  *DelegationAuthorization
}

// errCapOverflow is the protection error for capability_overflow (draft-02 §6.4: MUST NOT > 256).
var errCapOverflow = fmt.Errorf("aic: capabilities exceed max limit (256 entries)")

// BuildAIC constructs the AIC X.509v3 extension from configuration (v1.7.1 spec: DA required, critical=false).
// Validation coverage: V6 keyHash length, V8 lifetime 1..86400, V10/V15 constraint schemeId whitelist,
// V16 non-empty authorization, R1/R2/R4/R5 Reason required and length, nonce 32 bytes.
func BuildAIC(cfg AICConfig) (pkix.Extension, error) {
	if cfg.AgentId == "" {
		return pkix.Extension{}, fmt.Errorf("aic: agentId is required")
	}
	// V6: principalUid.realm/identifier length (ASN.1 SIZE(1..128) / SIZE(1..256)).
	if len(cfg.PrincipalUid.Realm) < 1 || len(cfg.PrincipalUid.Realm) > 128 {
		return pkix.Extension{}, fmt.Errorf("aic: principalUid.realm length %d: must be 1-128", len(cfg.PrincipalUid.Realm))
	}
	if len(cfg.PrincipalUid.Identifier) < 1 || len(cfg.PrincipalUid.Identifier) > 256 {
		return pkix.Extension{}, fmt.Errorf("aic: principalUid.identifier length %d: must be 1-256", len(cfg.PrincipalUid.Identifier))
	}
	if cfg.DelegationAuthorization == nil {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuthorization is required")
	}
	da := cfg.DelegationAuthorization
	// R1/R2: reason required.
	if da.Reason.ReasonCode == "" {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.reason.reasonCode must not be empty")
	}
	if da.Reason.Description == "" {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.reason.description must not be empty")
	}
	// R4/R5: reason length.
	if len(da.Reason.ReasonCode) > 64 {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.reason.reasonCode length %d: must be <= 64", len(da.Reason.ReasonCode))
	}
	if len(da.Reason.Description) > 512 {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.reason.description length %d: must be <= 512", len(da.Reason.Description))
	}
	if len(da.Nonce) != 32 {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.nonce length %d: must be exactly 32 bytes", len(da.Nonce))
	}
	// V8: lifetime 1..86400, 0 → 3600.
	lifetime := da.RequestedLifetime
	if lifetime == 0 {
		lifetime = 3600
		da.RequestedLifetime = lifetime
	}
	if lifetime < 1 || lifetime > 86400 {
		return pkix.Extension{}, fmt.Errorf("aic: delegationAuth.requestedLifetime %d: must be 1-86400", da.RequestedLifetime)
	}
	// V6: keyHash length.
	if err := ValidatePrincipalUidKeyHash(cfg.PrincipalUid); err != nil {
		return pkix.Extension{}, err
	}
	// V10/V15: constraint schemeId whitelist + capabilities must not use constraint scheme.
	for _, c := range cfg.AuthorizationConstraints {
		if c.SchemeId != "constraint" && c.SchemeId != "constraint-v1" {
			return pkix.Extension{}, fmt.Errorf("aic: authorizationConstraints schemeId %q: must be \"constraint\" or \"constraint-v1\"", c.SchemeId)
		}
		// V17: max-concurrent constraint parameters must be {"max": N} and N ∈ 1..1024.
		if c.CapabilityId == pki.ConstraintConcurrentKey && len(c.Parameters) > 0 {
			if err := pki.ValidateMaxConcurrentParam(c.Parameters); err != nil {
				return pkix.Extension{}, fmt.Errorf("aic: authorizationConstraints: %v", err)
			}
		}
	}
	for _, c := range cfg.Capabilities {
		if c.SchemeId == "constraint" || c.SchemeId == "constraint-v1" {
			return pkix.Extension{}, fmt.Errorf("aic: capability schemeId %q: constraint scheme forbidden in capabilities", c.SchemeId)
		}
	}
	// V16: capabilities and authorizationConstraints must not both be empty.
	if len(cfg.Capabilities) == 0 && len(cfg.AuthorizationConstraints) == 0 {
		return pkix.Extension{}, fmt.Errorf("aic: capabilities and authorizationConstraints must not both be empty")
	}
	if len(cfg.Capabilities) > 256 {
		return pkix.Extension{}, errCapOverflow
	}
	if len(cfg.AuthorizationConstraints) > 8 {
		return pkix.Extension{}, fmt.Errorf("aic: authorizationConstraints count %d exceeds max 8", len(cfg.AuthorizationConstraints))
	}

	ext := AIC{
		Version:                  1,
		AgentId:                  cfg.AgentId,
		PrincipalUid:             cfg.PrincipalUid,
		DelegationMode:           cfg.DelegationMode,
		Capabilities:             cfg.Capabilities,
		AuthorizationConstraints: cfg.AuthorizationConstraints,
		DelegationAuthorization:  *cfg.DelegationAuthorization,
	}

	if ext.Capabilities == nil {
		ext.Capabilities = []Capability{}
	}

	der, err := asn1.Marshal(ext)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("aic: marshal failed: %w", err)
	}
	return pkix.Extension{
		Id:       OIDAIC,
		Critical: false,
		Value:    der,
	}, nil
}

// ParseAIC parses the AIC extension from a certificate.
// If the certificate does not contain an AIC extension, returns nil (not an error).
// Per v1.7.1 spec, delegationAuthorization is required; missing returns an error.
func ParseAIC(cert *x509.Certificate) (*AIC, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAIC) {
			var aic AIC
			if _, err := asn1.Unmarshal(ext.Value, &aic); err != nil {
				return nil, fmt.Errorf("aic: unmarshal failed: %w", err)
			}
			if !aic.DelegationAuthorization.isPresent() {
				return nil, fmt.Errorf("aic: delegationAuthorization is required but missing")
			}
			return &aic, nil
		}
	}
	return nil, nil
}

// isPresent determines whether DelegationAuthorization actually exists (non-zero value).
func (d DelegationAuthorization) isPresent() bool {
	return d.Reason.ReasonCode != "" || d.Reason.Description != "" ||
		len(d.SignatureValue) > 0 || len(d.Nonce) > 0 ||
		d.RequestedLifetime > 0 || !d.Timestamp.IsZero()
}

// ValidatePrincipalUidKeyHash validates that keyHash length matches the declared hashAlgo (v1.7.1 §5,
// spec P1-A-12). SHA-2/SHA-3 + SM3 (built-in pure Go implementation in pki-types, C1) are validated
// against the mapping table for output length; algorithms requiring external dependencies like
// BLAKE2/BLAKE3 return a clear "unsupported" error.
func ValidatePrincipalUidKeyHash(pu PrincipalUid) error {
	if len(pu.KeyHash) == 0 {
		return fmt.Errorf("aic: principalUid.keyHash: required")
	}
	algo := pu.HashAlgoOID()
	if len(algo) == 0 {
		algo = pki.OIDSHA256
	}
	name := pki.HashOIDName(algo)
	if name == "" {
		return fmt.Errorf("aic: principalUid.hashAlgo %v: unsupported keyHash algorithm", algo)
	}
	want, ok := pki.HashOutputLen[name]
	if !ok {
		return fmt.Errorf("aic: principalUid.hashAlgo %v: no output length mapping (requires external dependency)", algo)
	}
	if len(pu.KeyHash) != want {
		return fmt.Errorf("aic: principalUid.keyHash length %d: must be %d (%s)", len(pu.KeyHash), want, name)
	}
	return nil
}

// CheckPermission checks whether an agent certificate has a specified permission (matched by CapabilityId).
func (a *AIC) CheckPermission(required string) (bool, error) {
	if a == nil {
		return false, fmt.Errorf("aic: nil extension")
	}
	if len(a.Capabilities) == 0 {
		return false, fmt.Errorf("aic: no capabilities in cert, check principalUid=%s via RBAC", a.PrincipalUid.String())
	}
	for _, cap := range a.Capabilities {
		if cap.CapabilityId == required {
			return true, nil
		}
	}
	return false, nil
}

// Principal returns the human principal that the Agent represents.
func (a *AIC) Principal() string {
	if a == nil {
		return ""
	}
	return a.PrincipalUid.String()
}

// HasProtocol checks whether an agent has a protocol capability with the specified SchemeId.
func (a *AIC) HasProtocol(schemeId string) bool {
	if a == nil {
		return false
	}
	for _, cap := range a.Capabilities {
		if cap.SchemeId == schemeId {
			return true
		}
	}
	return false
}

// IntersectPermissions returns the intersection of CapabilityId list with user permissions.
func (a *AIC) IntersectPermissions(userPerms []string) []string {
	if a == nil || len(a.Capabilities) == 0 {
		return userPerms
	}
	capSet := make(map[string]bool, len(a.Capabilities))
	for _, c := range a.Capabilities {
		capSet[c.CapabilityId] = true
	}
	var result []string
	for _, p := range userPerms {
		if capSet[p] {
			result = append(result, p)
		}
	}
	return result
}

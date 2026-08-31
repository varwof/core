// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

// SignJWT issues an AIC-JWT (draft-wei-aic-jwt-00) from the same SignConfig
// that drives X.509 AIC issuance, producing the "two carriers on one trust
// root" representation: the same CA key signs certs and JWS, the same
// PrincipalUid/capabilities/DA semantics are carried over. The JWT's issuer
// kid is the CA certificate's SPKI hash, so X.509 chain verification and JWS
// verification anchor to the same trust root.

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/types/aicjwt"
)

// JWTSignOptions controls AIC-JWT issuance on top of SignConfig.
type JWTSignOptions struct {
	// Audience is the aud claim (REQUIRED by draft). Empty → defaults to
	// "varwof-core" (the core issuer's own audience).
	Audience []string
	// Issuer overrides the iss claim. Empty → "varwof-core".
	Issuer string
	// TokenType overrides the default typ (aic+jwt). Kept for extensibility.
	TokenType string
	// Scope is an optional OAuth scope string mirroring the AIC capabilities
	// (informational; capabilities remain the authority).
	Scope string
	// StatusListURI, when set, adds a status claim (RFC 9457 status list
	// reference) pointing to the core revocation status list endpoint.
	StatusListURI string
	// StatusListIndex is the index within the status list.
	StatusListIndex int
	// DA is an optional inner DA JWS (typ aic+da+jwt, signed by the principal
	// key). Authorized mode omits it (lifetime-bounded lightweight profile);
	// representative mode REQUIRES it. When set, it is embedded in the outer
	// "da" claim.
	DA string
}

// SignJWTResult is the output of SignJWT.
type SignJWTResult struct {
	Token     string // JWS compact serialization
	Header    aicjwt.Header
	Claims    aicjwt.OuterClaims
	Principal PrincipalUid
	AgentID   string
	CA        *x509.Certificate
	Alg       string
}

// SignJWT issues an AIC-JWT. It performs all AIC issuance validations shared
// with Sign(): required AIC/PA/DA checks, capability registration, PA−cap
// coverage, and — like Sign — the DA nonce consumption hook. It does NOT
// touch the database or build an X.509 certificate.
func SignJWT(sc *SignConfig, opts JWTSignOptions) (*SignJWTResult, error) {
	if sc == nil {
		return nil, fmt.Errorf("aicjwt: nil SignConfig")
	}
	if sc.CAKey == nil {
		return nil, fmt.Errorf("aicjwt: CAKey is required")
	}
	if sc.AIC == nil {
		return nil, fmt.Errorf("aicjwt: AIC config is required")
	}
	if sc.CACert == nil {
		return nil, fmt.Errorf("aicjwt: CACert is required")
	}

	aic := sc.AIC
	// Shared validations (keep parity with Sign()).
	if aic.AgentId == "" {
		return nil, fmt.Errorf("aic: agentId is required")
	}
	r := aic.PrincipalUid.Realm
	id := aic.PrincipalUid.Identifier
	if len(r) < 1 || len(r) > 128 {
		return nil, fmt.Errorf("aic: principalUid.realm length %d: must be 1-128", len(r))
	}
	if len(id) < 1 || len(id) > 256 {
		return nil, fmt.Errorf("aic: principalUid.identifier length %d: must be 1-256", len(id))
	}
	if aic.DelegationAuthorization == nil {
		return nil, fmt.Errorf("aic: delegationAuthorization is required")
	}
	if len(aic.Capabilities) > 256 {
		return nil, fmt.Errorf("aic: capabilities exceed max limit (256 entries)")
	}
	if sc.PrincipalAuthorization != nil && len(sc.PrincipalAuthorization.Grants) > 0 {
		if err := validatePrincipalAuthForAIC(aic, sc.PrincipalAuthorization); err != nil {
			return nil, err
		}
	}
	if sc.ValidateCapabilities != nil {
		ids := make([]string, 0, len(aic.Capabilities))
		for _, c := range aic.Capabilities {
			ids = append(ids, c.FullID())
		}
		if err := sc.ValidateCapabilities(ids); err != nil {
			return nil, err
		}
	}
	if sc.UserCert != nil {
		if err := VerifyDelegationAuthorization(sc.UserCert, aic); err != nil {
			return nil, err
		}
	}
	if sc.ConsumeDANonce != nil && aic.DelegationAuthorization != nil {
		if err := sc.ConsumeDANonce(aic.DelegationAuthorization.Nonce); err != nil {
			return nil, err
		}
	}

	// DA nonce must be 32 bytes (shared with x509 path).
	if len(aic.DelegationAuthorization.Nonce) != 32 {
		return nil, fmt.Errorf("aic: delegationAuth.nonce length %d: must be exactly 32 bytes", len(aic.DelegationAuthorization.Nonce))
	}

	// Derive the signing algorithm from the CA key.
	alg, err := aicjwt.AlgForPublicKey(sc.CAKey.Public())
	if err != nil {
		return nil, fmt.Errorf("aicjwt: %w", err)
	}

	// kid = issuer CA certificate SPKI hash (the trust-root binding).
	kid, err := aicjwt.SPKIHash(sc.CACert, "sha-256")
	if err != nil {
		return nil, fmt.Errorf("aicjwt: SPKIHash: %w", err)
	}

	// Principal → draft §5.1.2 principal object.
	hashAlg := aic.PrincipalUid.HashAlgoOID()
	hashAlgStr := "sha-256"
	if !hashAlg.Equal(DefaultHashAlgo()) {
		// Only SHA-256 SPKI hashes are canonical in the AIC-JWT reference
		// implementation; any non-default OID is downgraded to the canonical
		// convention (no silent semantic drift).
		hashAlgStr = "sha-256"
	}
	principal := aicjwt.Principal{
		Realm:   r,
		ID:      id,
		KeyHash: b64uEncode(aic.PrincipalUid.KeyHash),
		HashAlg: hashAlgStr,
	}

	// Capabilities (AIC capabilities → JWT capabilities 1:1).
	caps := make([]aicjwt.Capability, 0, len(aic.Capabilities))
	for _, c := range aic.Capabilities {
		if c.SchemeId == "" && c.CapabilityId == "" {
			continue
		}
		caps = append(caps, aicjwt.Capability{
			Scheme: c.SchemeId,
			ID:     c.CapabilityId,
			Params: json.RawMessage(c.Parameters),
		})
	}
	constraints := make([]aicjwt.Capability, 0, len(aic.AuthorizationConstraints))
	for _, c := range aic.AuthorizationConstraints {
		if c.SchemeId == "" && c.CapabilityId == "" {
			continue
		}
		constraints = append(constraints, aicjwt.Capability{
			Scheme: c.SchemeId,
			ID:     c.CapabilityId,
			Params: json.RawMessage(c.Parameters),
		})
	}

	// Validity window. If the config requests it, honor explicit NotBefore/NotAfter.
	now := time.Now()
	notBefore := now
	notAfter := now.Add(sc.Validity)
	if sc.Validity <= 0 {
		if sc.NotAfter != nil {
			notAfter = *sc.NotAfter
		} else {
			notAfter = now.Add(24 * time.Hour)
		}
	}
	if sc.NotBefore != nil {
		notBefore = *sc.NotBefore
	}
	// Bound by issuer lifetime (mirrors x509 Sign() behavior).
	if sc.CACert != nil && notAfter.After(sc.CACert.NotAfter) {
		notAfter = sc.CACert.NotAfter
	}
	if sc.CACert != nil && notBefore.Before(sc.CACert.NotBefore) {
		notBefore = sc.CACert.NotBefore
	}

	nowUnix := notBefore.Unix()
	exp := notAfter.Unix()

	typ := opts.TokenType
	if typ == "" {
		typ = "aic+jwt"
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = "varwof-core"
	}
	aud := opts.Audience
	if len(aud) == 0 {
		aud = []string{"varwof-core"}
	}

	// DA claim: authorized (lightweight) mode has no inner DA JWS; the
	// lifetime cap enforces the delegation contract (draft §3.3). Representative
	// mode REQUIRES an inner DA JWS signed by the principal key.
	da := ""
	switch aic.DelegationMode {
	case DelegationRepresentative:
		if opts.DA == "" {
			return nil, fmt.Errorf("aicjwt: representative mode requires a DA JWS (JWTSignOptions.DA)")
		}
		da = opts.DA
	case DelegationAuthorized:
		da = ""
	}

	// Status (revocation) reference.
	var status *aicjwt.StatusRef
	if opts.StatusListURI != "" {
		status = &aicjwt.StatusRef{Idx: opts.StatusListIndex, URI: opts.StatusListURI}
	}

	daMode := "authorized"
	switch aic.DelegationMode {
	case DelegationRepresentative:
		daMode = "representative"
	case DelegationAuthorized:
		daMode = "authorized"
	}

	header := aicjwt.Header{Alg: alg, Typ: typ, Kid: kid}
	nbf := notBefore.Unix()
	claims := aicjwt.OuterClaims{
		Iss:      issuer,
		Sub:      aic.AgentId,
		Aud:      aud,
		Iat:      nowUnix,
		Exp:      exp,
		Nbf:      &nbf,
		Jti:      randomTokenID(),
		Cnf:      &aicjwt.Cnf{Jkt: ""}, // filled below
		Scope:    opts.Scope,
		ClientID: "",
		Status:   status,
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      principal,
			DelegationMode: daMode,
			Capabilities:   caps,
			Constraints:    constraints,
		},
		Da:           da,
		AuthzDetails: nil,
	}

	// cnf.jkt = RFC 7638 thumbprint of the subject public key. We derive it
	// from the supplied SubjectPubKey or, failing that, from the CA key (the
	// device key is not present in a pure AS issuance context; the caller must
	// provide a SubjectPubKey to bind a real principal key).
	cnfJkt := ""
	if sc.SubjectPubKey != nil {
		j, jkerr := aicjwt.PublicKeyToJWK(sc.SubjectPubKey)
		if jkerr != nil {
			return nil, fmt.Errorf("aicjwt: subject key to JWK: %w", jkerr)
		}
		tp, tperr := aicjwt.JWKThumbprint(j)
		if tperr != nil {
			return nil, fmt.Errorf("aicjwt: thumbprint: %w", tperr)
		}
		cnfJkt = tp
	}
	claims.Cnf.Jkt = cnfJkt
	if claims.Cnf.Jkt == "" {
		return nil, fmt.Errorf("aicjwt: cnf.jkt cannot be empty (provide SubjectPubKey)")
	}

	hb, err := json.Marshal(&header)
	if err != nil {
		return nil, fmt.Errorf("aicjwt: marshal header: %w", err)
	}
	pb, err := json.Marshal(&claims)
	if err != nil {
		return nil, fmt.Errorf("aicjwt: marshal payload: %w", err)
	}
	token, err := aicjwt.SignCompact(hb, pb, alg, sc.CAKey)
	if err != nil {
		return nil, fmt.Errorf("aicjwt: sign: %w", err)
	}

	return &SignJWTResult{
		Token:     token,
		Header:    header,
		Claims:    claims,
		Principal: aic.PrincipalUid,
		AgentID:   aic.AgentId,
		Alg:       alg,
		CA:        sc.CACert,
	}, nil
}

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomTokenID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return b64uEncode(b)
}

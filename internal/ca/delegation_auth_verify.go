// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	pki "github.com/varwof/types"
)

// ─────────────────────────────────────────────────────────────────────
// M5: Delegation Authorization signature verification at the CA library
// layer.
//
// Previously DA signature verification + nonce anti-replay were wired only
// in the serve layer (apiIssueCert / apiAICIssue). Library consumers that
// call ca.Sign/BuildAIC directly could mint AIC certificates carrying an
// unverified, replayable DelegationAuthorization. This file moves the
// verification into the ca package so every issuance path — server or
// library — validates the DA evidence when the DA signer certificate is
// supplied.
// ─────────────────────────────────────────────────────────────────────

// VerifyDelegationAuthorization verifies the DelegationAuthorization carried
// in an AICConfig against the DA signer's certificate:
//
//  1. Reconstructs DelegationAuthTBS with the exact same field order the
//     client signer and gateway-lib VerifyDelegationAuth use.
//  2. Cross-validates the user certificate's SPKI hash against
//     PrincipalUid.KeyHash (prevents forged user certs).
//  3. Verifies the signature with the user certificate's public key
//     (ECDSA/RSA/RSA-PSS/Ed25519), keyed off the declared algorithm OID.
//
// Returns an error when the evidence is missing, malformed, or invalid.
// A nil userCert or nil AIC is treated as invalid (fail-closed).
func VerifyDelegationAuthorization(userCert *x509.Certificate, aic *AICConfig) error {
	if userCert == nil {
		return fmt.Errorf("verify_delegation_auth: nil user cert")
	}
	if aic == nil || aic.DelegationAuthorization == nil {
		return fmt.Errorf("verify_delegation_auth: nil delegation authorization")
	}
	da := aic.DelegationAuthorization
	if len(da.SignatureValue) == 0 {
		return fmt.Errorf("verify_delegation_auth: empty signature")
	}

	// Construct DelegationAuthTBS consistent with the signer.
	tbs := pki.DelegationAuthTBS{
		Version: 1,
		AgentId: aic.AgentId,
		PrincipalUid: pki.PrincipalUid{
			Version:    aic.PrincipalUid.Version,
			Realm:      aic.PrincipalUid.Realm,
			Identifier: aic.PrincipalUid.Identifier,
			KeyHash:    aic.PrincipalUid.KeyHash,
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: aic.PrincipalUid.HashAlgo.Algorithm},
		},
		Reason:                   pki.Reason{ReasonCode: da.Reason.ReasonCode, Description: da.Reason.Description},
		Capabilities:             toPKICapabilities(aic.Capabilities),
		DelegationMode:           pki.DelegationMode(aic.DelegationMode),
		AuthorizationConstraints: toPKICapabilities(aic.AuthorizationConstraints),
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("verify_delegation_auth: marshal tbs: %w", err)
	}
	digest := sha256.Sum256(tbsDER)

	// Cross-validation: the provided user certificate SPKI hash must match
	// PrincipalUid.keyHash (prevents forged user certificates — consistent with
	// gateway-lib VerifyDelegationAuth).
	if len(aic.PrincipalUid.KeyHash) > 0 {
		spkiHash := sha256.Sum256(userCert.RawSubjectPublicKeyInfo)
		if !bytes.Equal(spkiHash[:], aic.PrincipalUid.KeyHash) {
			return fmt.Errorf("verify_delegation_auth: user cert SPKI hash mismatch with principal_uid.keyHash")
		}
	}

	algoOID := da.SignatureAlgorithm.Algorithm
	switch pub := userCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !algoOID.Equal(OIDSigECDSAWithSHA256) {
			return fmt.Errorf("verify_delegation_auth: unsupported ECDSA algorithm OID %s", algoOID)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], da.SignatureValue) {
			return fmt.Errorf("verify_delegation_auth: ecdsa signature verification failed")
		}
	case *rsa.PublicKey:
		switch {
		case algoOID.Equal(OIDSigRSAWithSHA256):
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], da.SignatureValue); err != nil {
				return fmt.Errorf("verify_delegation_auth: rsa-sha256 verification: %w", err)
			}
		case algoOID.Equal(OIDSigRSAPSSWithSHA256):
			if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], da.SignatureValue, nil); err != nil {
				return fmt.Errorf("verify_delegation_auth: rsa-pss-sha256 verification: %w", err)
			}
		default:
			return fmt.Errorf("verify_delegation_auth: unsupported RSA algorithm OID %s", algoOID)
		}
	case ed25519.PublicKey:
		if !algoOID.Equal(OIDSigEd25519) {
			return fmt.Errorf("verify_delegation_auth: unsupported Ed25519 algorithm OID %s", algoOID)
		}
		if !ed25519.Verify(pub, digest[:], da.SignatureValue) {
			return fmt.Errorf("verify_delegation_auth: ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("verify_delegation_auth: unsupported key type %T", userCert.PublicKey)
	}
	return nil
}

// toPKICapabilities converts a ca.Capability slice to a pki.Capability slice
// (ASN.1 structures are identical).
func toPKICapabilities(cs []Capability) []pki.Capability {
	if len(cs) == 0 {
		return nil
	}
	out := make([]pki.Capability, 0, len(cs))
	for _, c := range cs {
		out = append(out, pki.Capability{
			SchemeId:     c.SchemeId,
			CapabilityId: c.CapabilityId,
			Parameters:   c.Parameters,
		})
	}
	return out
}

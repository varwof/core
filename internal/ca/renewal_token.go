// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// NonceStorer abstracts nonce persistence for one-time-use enforcement.
// Implemented by db.DB via StoreNonce/ConsumeNonce.
type NonceStorer interface {
	StoreNonce(nonce []byte) error
	ConsumeNonce(nonce []byte) error
}

// RenewalToken is the ASN.1 structure for automatic renewal tokens (I-D §6).
// 7 fields: version, principalUid, oldCertSerial, newKeyHash, timestamp, nonce, validityPeriod.
type RenewalToken struct {
	Version        int          `asn1:"default:1"`
	PrincipalUid   PrincipalUid `asn1:"optional,contextspecific,tag:0"`
	OldCertSerial  []byte       `asn1:"octet"`
	NewKeyHash     []byte       `asn1:"octet"`
	Timestamp      time.Time    `asn1:"generalized"`
	Nonce          []byte       `asn1:"octet"` // SIZE(16)
	ValidityPeriod int          `asn1:"default:300"`
}

// RenewalTokenExt is the ASN.1 serialization structure for RenewalToken (used for DER encoding).
// Identical to RenewalToken (no CertificateIssuerName or other contextual fields).
type RenewalTokenExt struct {
	Version        int          `asn1:"default:1"`
	PrincipalUid   PrincipalUid `asn1:"optional,contextspecific,tag:0"`
	OldCertSerial  []byte       `asn1:"octet"`
	NewKeyHash     []byte       `asn1:"octet"`
	Timestamp      time.Time    `asn1:"generalized"`
	Nonce          []byte       `asn1:"octet"` // SIZE(16)
	ValidityPeriod int          `asn1:"default:300"`
}

// BuildRenewalToken constructs a RenewalToken X.509v3 extension.
// oldCertSerial is the DER-encoded serial number of the certificate requesting renewal,
// principalUid is the principal identity identifier,
// newKeyHash is the SHA-256 hash of the new public key (32 bytes).
// If store is non-nil, the nonce is persisted (for one-time-use enforcement).
func BuildRenewalToken(oldCertSerial []byte, principalUid PrincipalUid, newKeyHash []byte, store NonceStorer) (pkix.Extension, error) {
	if len(oldCertSerial) == 0 {
		return pkix.Extension{}, fmt.Errorf("renewal_token: oldCertSerial required")
	}
	if len(newKeyHash) != 32 {
		return pkix.Extension{}, fmt.Errorf("renewal_token: newKeyHash must be 32 bytes")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return pkix.Extension{}, fmt.Errorf("renewal_token: nonce generation failed: %w", err)
	}

	// Persist nonce for one-time-use enforcement (store=nil skips persistence).
	if store != nil {
		if err := store.StoreNonce(nonce); err != nil {
			return pkix.Extension{}, fmt.Errorf("renewal_token: store nonce: %w", err)
		}
	}

	ext := RenewalTokenExt{
		Version:        1,
		PrincipalUid:   principalUid,
		OldCertSerial:  oldCertSerial,
		NewKeyHash:     newKeyHash,
		Timestamp:      time.Now(),
		Nonce:          nonce,
		ValidityPeriod: 300, // 5-minute upper bound
	}

	der, err := asn1.Marshal(ext)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("renewal_token: marshal failed: %w", err)
	}

	return pkix.Extension{
		Id:       OIDRenewalToken,
		Critical: false,
		Value:    der,
	}, nil
}

// ParseRenewalToken parses a RenewalToken from a certificate extension.
func ParseRenewalToken(cert *pkix.Extension) (*RenewalTokenExt, error) {
	if cert == nil {
		return nil, nil
	}
	if !cert.Id.Equal(OIDRenewalToken) {
		return nil, nil
	}
	var token RenewalTokenExt
	if _, err := asn1.Unmarshal(cert.Value, &token); err != nil {
		return nil, fmt.Errorf("renewal_token: unmarshal failed: %w", err)
	}
	return &token, nil
}

// IsExpired checks whether the RenewalToken has expired (5-minute validity period).
func (r *RenewalTokenExt) IsExpired() bool {
	if r == nil {
		return true
	}
	return time.Now().After(r.Timestamp.Add(time.Duration(r.ValidityPeriod) * time.Second))
}

// VerifyNonce verifies that the nonce length is 16 bytes (spec §6: SIZE(16)).
func (r *RenewalTokenExt) VerifyNonce() bool {
	if r == nil {
		return false
	}
	return len(r.Nonce) == 16
}

// ValidateConstraints validates RenewalToken constraints (spec §6).
func (r *RenewalTokenExt) ValidateConstraints() error {
	if r == nil {
		return fmt.Errorf("renewal_token: nil token")
	}
	if r.ValidityPeriod > 300 {
		return fmt.Errorf("renewal_token: validityPeriod %d exceeds max 300 seconds", r.ValidityPeriod)
	}
	if len(r.OldCertSerial) == 0 {
		return fmt.Errorf("renewal_token: oldCertSerial required")
	}
	if len(r.NewKeyHash) != 32 {
		return fmt.Errorf("renewal_token: newKeyHash length %d: must be 32", len(r.NewKeyHash))
	}
	if !r.VerifyNonce() {
		return fmt.Errorf("renewal_token: nonce length %d: must be 16", len(r.Nonce))
	}
	return nil
}

// ValidateAndConsumeNonce validates one-time nonce usage and consumes it.
// Combined check: length + not expired + not already used; atomically consumes on pass.
func ValidateAndConsumeNonce(token *RenewalTokenExt, store NonceStorer) error {
	if token == nil {
		return fmt.Errorf("renewal_token: nil token")
	}
	if !token.VerifyNonce() {
		return fmt.Errorf("renewal_token: nonce length %d: must be 16", len(token.Nonce))
	}
	if token.IsExpired() {
		return fmt.Errorf("renewal_token: token expired")
	}
	if store == nil {
		return fmt.Errorf("renewal_token: nonce store not configured — refusing to validate (fail-closed)")
	}
	return store.ConsumeNonce(token.Nonce)
}

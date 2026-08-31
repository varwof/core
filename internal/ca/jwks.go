// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

// Certificate ↔ JWK interop for AIC-JWT. The ground-truth implementation
// lives in github.com/varwof/types/aicjwt (shared by core, gateway and the
// aic-jwt reference ecosystem); this file re-exports the pieces core's CA
// pipeline needs so callers import from package ca only.

import (
	"crypto"
	"crypto/x509"

	"github.com/varwof/types/aicjwt"
)

// JWK is the RFC 7517 JSON Web Key (kty/crv/x/y/n/e + kid/use/x5c/x5t).
type JWK = aicjwt.JWK

// JWKS is a JWK Key Set (RFC 7517 §5).
type JWKS = aicjwt.JWKS

// SPKISHA256 returns base64url(SHA-256(SubjectPublicKeyInfo)) — the key_hash
// convention used for both X.509 PrincipalUid and AIC-JWT kid.
func SPKISHA256(cert *x509.Certificate) string {
	h, err := aicjwt.SPKIHash(cert, "sha-256")
	if err != nil {
		return ""
	}
	return h
}

// CertToJWK converts an X.509 certificate into a JWK bound to that
// certificate (kid = SPKI hash, x5c = the certificate, x5t = thumbprint).
func CertToJWK(cert *x509.Certificate) (JWK, error) {
	return aicjwt.CertToJWK(cert)
}

// BuildJWKS builds a JWKS from certificates, deduplicated by kid.
func BuildJWKS(certs []*x509.Certificate) (JWKS, error) {
	return aicjwt.BuildJWKS(certs)
}

// BuildJWKSJSON returns the marshaled JWKS for a certificate set.
func BuildJWKSJSON(certs []*x509.Certificate) ([]byte, error) {
	return aicjwt.BuildJWKSJSON(certs)
}

// JWSToAlg derives the JOSE algorithm implied by a public key.
func JWSToAlg(pub any) (string, error) {
	return aicjwt.AlgForPublicKey(pub)
}

// jwtAlgFromSigner returns the signing algorithm for a crypto.Signer.
func jwtAlgFromSigner(s crypto.Signer) (string, error) {
	return aicjwt.AlgForPublicKey(s.Public())
}

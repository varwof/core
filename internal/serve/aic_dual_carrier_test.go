// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/varwof/aic-jwt"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/types/aicjwt"
)

type carrierAlg struct {
	name    string // expected JOSE alg
	caCert  *x509.Certificate
	caKey   crypto.Signer
	subject crypto.Signer
}

// newCarrierAlg builds a CA + subject key pair for one algorithm leg of the
// dual-carrier matrix.
func newCarrierAlg(t *testing.T, alg string) carrierAlg {
	t.Helper()
	var caKey, subjectKey crypto.Signer
	switch alg {
	case "ES256":
		k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caKey, subjectKey = k1, k2
	case "RS256":
		k1, _ := rsa.GenerateKey(rand.Reader, 2048)
		k2, _ := rsa.GenerateKey(rand.Reader, 2048)
		caKey, subjectKey = k1, k2
	case "EdDSA":
		_, sk1, _ := ed25519.GenerateKey(rand.Reader)
		_, sk2, _ := ed25519.GenerateKey(rand.Reader)
		caKey, subjectKey = sk1, sk2
	default:
		t.Fatalf("unknown alg %q", alg)
	}

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "carrier-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	return carrierAlg{name: alg, caCert: caCert, caKey: caKey, subject: subjectKey}
}

// x509AICFor signs an x509 AIC leaf (no DB) carrying the given AIC config.
func x509AICFor(t *testing.T, alg carrierAlg) *x509.Certificate {
	t.Helper()
	aicCfg := carrierAICConfig(t, alg)
	ext, err := ca.BuildAIC(aicCfg)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "agent-matrix"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, alg.caCert, alg.subject.Public(), alg.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// carrierAICConfig builds the AIC config shared by both carriers for one leg.
func carrierAICConfig(t *testing.T, alg carrierAlg) ca.AICConfig {
	t.Helper()
	keyHash := ca.SPKIHash(alg.subject.Public())
	return ca.AICConfig{
		AgentId:        "agent-matrix",
		PrincipalUid:   ca.PrincipalUid{Version: 1, Realm: "r", Identifier: "matrix-user", KeyHash: keyHash},
		DelegationMode: ca.DelegationAuthorized,
		Capabilities:   []ca.Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
		DelegationAuthorization: &ca.DelegationAuthorization{
			Reason:             ca.Reason{ReasonCode: "ROTATION", Description: "matrix test"},
			Nonce:              make([]byte, 32),
			Timestamp:          time.Now().Add(-time.Minute),
			RequestedLifetime:  3600,
			SignatureAlgorithm: ca.AlgorithmIdentifier{Algorithm: ca.OIDSigECDSAWithSHA256},
		},
	}
}

// jwtFor signs the AIC-JWT leg with the same AIC config.
func jwtFor(t *testing.T, alg carrierAlg) string {
	t.Helper()
	aicCfg := carrierAICConfig(t, alg)
	res, err := ca.SignJWT(&ca.SignConfig{
		CAKey: alg.caKey, CACert: alg.caCert, SubjectPubKey: alg.subject.Public(), Validity: time.Hour,
		AIC: &aicCfg,
	}, ca.JWTSignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

// outerClaimsFor decodes an AIC-JWT payload.
func outerClaimsFor(t *testing.T, tok string) aicjson.OuterClaims {
	t.Helper()
	_, pb, _, err := aicjson.ParseCompact(tok)
	if err != nil {
		t.Fatal(err)
	}
	var outer aicjson.OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		t.Fatal(err)
	}
	return outer
}

func TestDualCarrierMatrix(t *testing.T) {
	for _, alg := range []string{"ES256", "RS256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			c := newCarrierAlg(t, alg)
			cert := x509AICFor(t, c)
			tok := jwtFor(t, c)
			outer := outerClaimsFor(t, tok)

			// (a) Same trust root: the JWT kid must be the CA cert's SPKI
			// hash and the token must verify with the CA key that signed the
			// x509 carrier.
			hb, _, _, err := aicjson.ParseCompact(tok)
			if err != nil {
				t.Fatal(err)
			}
			var hdr aicjson.Header
			if err := json.Unmarshal(hb, &hdr); err != nil {
				t.Fatal(err)
			}
			if hdr.Alg != alg {
				t.Fatalf("alg = %q, want %q", hdr.Alg, alg)
			}
			if hdr.Kid != ca.SPKISHA256(c.caCert) {
				t.Fatalf("kid %q != CA SPKI hash %q", hdr.Kid, ca.SPKISHA256(c.caCert))
			}
			if _, err := aicjson.Validate(tok, aicjson.VerifyOptions{
				Now:              time.Now(),
				ExpectedIssuer:   "varwof-core",
				ExpectedAudience: []string{"varwof-core"},
				IssuerKeys:       map[string]crypto.PublicKey{ca.SPKISHA256(c.caCert): c.caCert.PublicKey},
			}); err != nil {
				t.Fatalf("JWT does not validate with x509 CA key: %v", err)
			}

			// (b) Same subject: x509 AIC key_hash must equal the JWT
			// principal key_hash.
			certAIC, err := ca.ParseAIC(cert)
			if err != nil {
				t.Fatal(err)
			}
			certKeyHash := base64.RawURLEncoding.EncodeToString(certAIC.PrincipalUid.KeyHash)
			if outer.Aic == nil {
				t.Fatal("JWT missing aic claim")
			}
			if outer.Aic.Principal.KeyHash != certKeyHash {
				t.Fatalf("JWT key_hash %q != cert key_hash %q", outer.Aic.Principal.KeyHash, certKeyHash)
			}
			if outer.Aic.Principal.Realm != certAIC.PrincipalUid.Realm ||
				outer.Aic.Principal.ID != certAIC.PrincipalUid.Identifier {
				t.Fatalf("JWT principal %+v != cert principal %+v", outer.Aic.Principal, certAIC.PrincipalUid)
			}

			// (c) cnf binding: the token's cnf.jkt must equal the thumbprint
			// of the x509 subject public key (same key across both carriers).
			if outer.Cnf == nil || outer.Cnf.Jkt == "" {
				t.Fatal("JWT missing cnf.jkt")
			}
			subjectJWK, err := aicjwt.CertToJWK(cert)
			if err != nil {
				t.Fatal(err)
			}
			thumb, err := aicjwt.JWKThumbprint(subjectJWK)
			if err != nil {
				t.Fatal(err)
			}
			if outer.Cnf.Jkt != thumb {
				t.Fatalf("cnf.jkt %q != cert thumbprint %q", outer.Cnf.Jkt, thumb)
			}

			// (d) Capabilities carried identically on both carriers.
			if len(outer.Aic.Capabilities) != 1 || outer.Aic.Capabilities[0].ID != "SELECT:*" {
				t.Fatalf("JWT capabilities = %+v", outer.Aic.Capabilities)
			}

			// (e) Tamper detection: a bit-flipped JWT signature fails; a
			// certificate signed by a different subject key is detected by
			// the key_hash mismatch.
			tampered := tok[:len(tok)-3] + "AAA"
			if _, err := aicjson.Validate(tampered, aicjson.VerifyOptions{
				Now:        time.Now(),
				IssuerKeys: map[string]crypto.PublicKey{ca.SPKISHA256(c.caCert): c.caCert.PublicKey},
			}); err == nil {
				t.Fatal("tampered JWT must fail validation")
			}
		})
	}
}

func TestDualCarrierMatrix_TamperedCertificate(t *testing.T) {
	c := newCarrierAlg(t, "ES256")

	// Re-issue the certificate under a DIFFERENT subject key: the JWT still
	// binds the original key, so the pair is inconsistent.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	orig := c.subject
	c.subject = otherKey
	wrongCert := x509AICFor(t, c)
	c.subject = orig

	tok := jwtFor(t, c)
	outer := outerClaimsFor(t, tok)

	certAIC, err := ca.ParseAIC(wrongCert)
	if err != nil {
		t.Fatal(err)
	}
	if outer.Aic.Principal.KeyHash == base64.RawURLEncoding.EncodeToString(certAIC.PrincipalUid.KeyHash) {
		t.Fatal("tampered certificate must NOT match the JWT principal key_hash")
	}
}
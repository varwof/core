// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// buildDelegationTBS replicates the exact DelegationAuthTBS marshalling used
// by VerifyDelegationAuthorization so tests can produce valid signatures.
func buildDelegationTBS(aic *AICConfig) ([]byte, error) {
	da := aic.DelegationAuthorization
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
	return asn1.Marshal(tbs)
}

func baseDACert(pubKey crypto.PublicKey) *x509.Certificate {
	return &x509.Certificate{PublicKey: pubKey}
}

func newDAConfig(pubKey crypto.PublicKey, algoOID asn1.ObjectIdentifier) *AICConfig {
	cfg := &AICConfig{
		AgentId:        "agent-7",
		PrincipalUid:   PrincipalUid{Version: 1, Realm: "acme", Identifier: "alice"},
		DelegationMode: DelegationAuthorized,
		Capabilities: []Capability{
			{SchemeId: "tt", CapabilityId: "smart-device", Parameters: []byte{0x01}},
		},
		AuthorizationConstraints: []Capability{{SchemeId: "tt", CapabilityId: "smart-device"}},
		DelegationAuthorization: &DelegationAuthorization{
			Reason:             Reason{ReasonCode: "maintenance", Description: "scheduled maintenance"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().Round(time.Second),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: algoOID},
		},
	}
	// S3 security fix: a DelegationAuthorization must bind to the principal's
	// key (non-empty KeyHash). Compute it from the same public key so the
	// valid-signature cases exercise the principal-binding cross-check.
	if pubKey != nil {
		if kh, err := pki.KeyHashFromCertSPKI(pki.OIDSHA256, &x509.Certificate{PublicKey: pubKey}); err == nil {
			cfg.PrincipalUid.KeyHash = kh
		}
	}
	return cfg
}

func signDA(t *testing.T, key crypto.Signer, aic *AICConfig, autoOID asn1.ObjectIdentifier) {
	t.Helper()
	tbs, err := buildDelegationTBS(aic)
	if err != nil {
		t.Fatalf("marshal tbs: %v", err)
	}
	digest := sha256.Sum256(tbs)
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest[:])
	case *rsa.PrivateKey:
		switch {
		case autoOID.Equal(OIDSigRSAWithSHA256):
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		case autoOID.Equal(OIDSigRSAPSSWithSHA256):
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], nil)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, digest[:])
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	aic.DelegationAuthorization.SignatureValue = sig
}

func TestVerifyDelegationAuthorization(t *testing.T) {
	if err := VerifyDelegationAuthorization(nil, &AICConfig{}); err == nil {
		t.Fatal("nil user cert must error")
	}
	if err := VerifyDelegationAuthorization(&x509.Certificate{}, nil); err == nil {
		t.Fatal("nil AIC must error")
	}
	aic := newDAConfig(nil, OIDSigECDSAWithSHA256)
	if err := VerifyDelegationAuthorization(&x509.Certificate{PublicKey: nil}, aic); err == nil {
		t.Fatal("empty signature must error")
	}
}

func TestVerifyDelegationAuthorizationECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := newDAConfig(&key.PublicKey, OIDSigECDSAWithSHA256)
	signDA(t, key, aic, OIDSigECDSAWithSHA256)
	cert := baseDACert(&key.PublicKey)
	if err := VerifyDelegationAuthorization(cert, aic); err != nil {
		t.Fatalf("valid ECDSA DA rejected: %v", err)
	}

	wrong := newDAConfig(&key.PublicKey, OIDSigEd25519)
	wrong.DelegationAuthorization.SignatureValue = aic.DelegationAuthorization.SignatureValue
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), wrong); err == nil {
		t.Fatal("wrong ECDSA OID must error")
	}

	tampered := newDAConfig(&key.PublicKey, OIDSigECDSAWithSHA256)
	tampered.DelegationAuthorization.SignatureAlgorithm.Algorithm = OIDSigECDSAWithSHA256
	tampered.DelegationAuthorization.SignatureValue = aic.DelegationAuthorization.SignatureValue
	tampered.DelegationAuthorization.SignatureValue[len(tampered.DelegationAuthorization.SignatureValue)-1] ^= 0x01
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), tampered); err == nil {
		t.Fatal("tampered ECDSA DA must error")
	}

	mismatch := newDAConfig(&key.PublicKey, OIDSigECDSAWithSHA256)
	mismatch.PrincipalUid.KeyHash = []byte{0xde, 0xad}
	mismatch.DelegationAuthorization.SignatureValue = aic.DelegationAuthorization.SignatureValue
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), mismatch); err == nil {
		t.Fatal("keyHash mismatch must error")
	}
}

func TestVerifyDelegationAuthorizationRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pkcs1 := newDAConfig(&key.PublicKey, OIDSigRSAWithSHA256)
	signDA(t, key, pkcs1, OIDSigRSAWithSHA256)
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), pkcs1); err != nil {
		t.Fatalf("valid RSA-PKCS1 DA rejected: %v", err)
	}

	pss := newDAConfig(&key.PublicKey, OIDSigRSAPSSWithSHA256)
	signDA(t, key, pss, OIDSigRSAPSSWithSHA256)
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), pss); err != nil {
		t.Fatalf("valid RSA-PSS DA rejected: %v", err)
	}

	unsupported := newDAConfig(&key.PublicKey, asn1.ObjectIdentifier{1, 2, 3, 4})
	unsupported.DelegationAuthorization.SignatureValue = pss.DelegationAuthorization.SignatureValue
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), unsupported); err == nil {
		t.Fatal("unsupported RSA OID must error")
	}
}

func TestVerifyDelegationAuthorizationEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := newDAConfig(pub, OIDSigEd25519)
	signDA(t, priv, aic, OIDSigEd25519)
	if err := VerifyDelegationAuthorization(baseDACert(pub), aic); err != nil {
		t.Fatalf("valid Ed25519 DA rejected: %v", err)
	}

	wrong := newDAConfig(pub, OIDSigECDSAWithSHA256)
	wrong.DelegationAuthorization.SignatureValue = aic.DelegationAuthorization.SignatureValue
	if err := VerifyDelegationAuthorization(baseDACert(pub), wrong); err == nil {
		t.Fatal("wrong Ed25519 OID must error")
	}
}

func TestVerifyDelegationAuthorizationUnsupportedKey(t *testing.T) {
	aic := newDAConfig(big.NewInt(42), OIDSigECDSAWithSHA256)
	aic.DelegationAuthorization.SignatureValue = []byte{0x01}
	if err := VerifyDelegationAuthorization(&x509.Certificate{PublicKey: nil}, aic); err == nil {
		t.Fatal("unsupported key type must error")
	}
}

// S3: an empty PrincipalUid.KeyHash must fail closed (principal-binding bypass).
// Previously the SPKI cross-check was skipped when KeyHash was empty, letting a
// caller self-delegate AIC capabilities with an arbitrary self-signed cert.
func TestVerifyDelegationAuthorization_EmptyKeyHashFailsClosed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := newDAConfig(&key.PublicKey, OIDSigECDSAWithSHA256)
	signDA(t, key, aic, OIDSigECDSAWithSHA256)
	// Strip the KeyHash (the vulnerable path) but keep a valid signature.
	aic.PrincipalUid.KeyHash = nil
	if err := VerifyDelegationAuthorization(baseDACert(&key.PublicKey), aic); err == nil {
		t.Fatal("empty keyHash must fail closed")
	}
}

// TestVerifyDelegationAuthorization_UserSignerProtocol verifies cross-repo
// compatibility with the DA produced by user-signer's SignApproval:
//
//   - the DA signer (user) certificate is a self-signed public-key container
//     whose SPKI hash equals principalUid.keyHash (the signer binds the key,
//     not the certificate chain);
//   - the DelegationAuthorization carries reason/lifetime/timestamp/nonce and
//     an ECDSA-SHA256 ASN.1 signature over sha256(DER(DelegationAuthTBS)).
//
// This mirrors exactly how varwof/user-signer constructs and signs, so the
// agent can forward {da, user_cert_pem} from user-signer straight to core.
func TestVerifyDelegationAuthorization_UserSignerProtocol(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	principalUid := PrincipalUid{Version: 1, Realm: "pki", Identifier: "alice@example.com"}
	// user-signer: keyHash = sha256(cert.RawSubjectPublicKeyInfo).
	cert := userSignerStyleCert(&key.PublicKey, "default")
	{
		kh, _ := pki.KeyHashFromCertSPKI(pki.OIDSHA256, cert)
		principalUid.KeyHash = kh
	}
	aic := &AICConfig{
		AgentId:        "spiffe://trustdomain/agent/alice-bot",
		PrincipalUid:   principalUid,
		DelegationMode: DelegationAuthorized,
		Capabilities: []Capability{
			{SchemeId: "ca", CapabilityId: "issue", Parameters: []byte(`{"tpl":"ci"}`)},
		},
		DelegationAuthorization: &DelegationAuthorization{
			Reason:             Reason{ReasonCode: "ops", Description: "release pipeline"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().Round(time.Second),
			Nonce:              nonce,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	// user-signer signs sha256(DER(DelegationAuthTBS)) with its local ECDSA key.
	signDA(t, key, aic, OIDSigECDSAWithSHA256)

	if err := VerifyDelegationAuthorization(cert, aic); err != nil {
		t.Fatalf("user-signer-protocol DA rejected by core: %v", err)
	}
}

// userSignerStyleCert builds a self-signed public-key container whose SPKI
// hash binds to the supplied public key — exactly what user-signer emits (it
// signs the container with a throwaway key because it never exposes the raw
// user private key).
func userSignerStyleCert(pub crypto.PublicKey, cn string) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"varwof-user-signer"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signKey)
	if err != nil {
		return nil
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

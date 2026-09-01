// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
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

	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

func keyHashOfPub(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	h, err := pki.KeyHashFromSPKI(DefaultHashAlgo(), der)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func selfSignedRSA(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test RSA CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSignJWT_Golden_EC verifies that AIC-JWT issuance from a SignConfig
// produces a token that verifies under the CA's own public key (kid = CA SPKI
// hash), and that the JWT capability/principal material is equivalent to a
// parallel X.509 AIC issuance from the same SignConfig.
func TestSignJWT_Golden_EC(t *testing.T) {
	caCert, caKey := newTestCA(t)

	// Subject/agent key bound in cnf.
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principalKeyHash := keyHashOfPub(t, principalKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	aic := &AICConfig{
		AgentId:      "agent-007",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "zhangsan@varwof.com", KeyHash: principalKeyHash},
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"},
			{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"},
		},
		DelegationAuthorization: testAICDelegation(),
		DelegationMode:          DelegationAuthorized,
	}

	sc := &SignConfig{
		CAKey:         caKey,
		CACert:        caCert,
		CAName:        "test-ca",
		Profile:       ProfileAgentProxy,
		CommonName:    "agent-007",
		SubjectPubKey: agentKey.Public(),
		Validity:      1 * time.Hour,
		AIC:           aic,
	}

	result, err := SignJWT(sc, JWTSignOptions{})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if result.Token == "" {
		t.Fatal("empty token")
	}

	// (a) issuer key = CA public key; kid must match the CA SPKI hash.
	wantKid, err := aicjwt.SPKIHash(caCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if result.Header.Kid != wantKid {
		t.Fatalf("kid = %q, want %q", result.Header.Kid, wantKid)
	}
	if result.Header.Alg != "ES256" {
		t.Fatalf("alg = %q, want ES256", result.Header.Alg)
	}

	// (b) full 11-step validation against CA issuer key.
	dec, err := aicjwt.Validate(result.Token, aicjwt.VerifyOptions{
		IssuerKeys:       map[string]crypto.PublicKey{wantKid: caKey.Public()},
		ExpectedIssuer:   "varwof-core",
		ExpectedAudience: []string{"varwof-core"},
		Now:              time.Now(),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !dec.Permit {
		t.Fatal("decision not permit")
	}
	if len(dec.Capabilities) != 2 {
		t.Fatalf("capabilities len = %d, want 2", len(dec.Capabilities))
	}

	// (c) carrier equivalence: JWT capabilities == x509 AIC capabilities.
	jwtCaps := dec.Capabilities
	for i, c := range jwtCaps {
		if c.Scheme != aic.Capabilities[i].SchemeId || c.ID != aic.Capabilities[i].CapabilityId {
			t.Fatalf("cap[%d] mismatch: jwt %s:%s vs x509 %s:%s",
				i, c.Scheme, c.ID, aic.Capabilities[i].SchemeId, aic.Capabilities[i].CapabilityId)
		}
	}
	// principal equivalence
	if result.Claims.Aic.Principal.Realm != "varwof" ||
		result.Claims.Aic.Principal.ID != "zhangsan@varwof.com" {
		t.Fatalf("principal mismatch: %+v", result.Claims.Aic.Principal)
	}
	// cnf.jkt bound to the agent key
	agentJWK, err := aicjwt.PublicKeyToJWK(&agentKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := aicjwt.JWKThumbprint(agentJWK)
	if err != nil {
		t.Fatal(err)
	}
	if result.Claims.Cnf == nil || result.Claims.Cnf.Jkt != jkt {
		t.Fatalf("cnf.jkt = %+v, want %q", result.Claims.Cnf, jkt)
	}

	// (d) authorized mode has no inner DA JWS (lifetime-bounded lightweight).
	if result.Claims.Da != "" {
		t.Fatal("authorized mode must not carry a da claim")
	}
}

// TestSignJWT_RequiresConfig verifies the failure modes are enforced.
func TestSignJWT_RequiresConfig(t *testing.T) {
	caCert, caKey := newTestCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ph := keyHashOfPub(t, principalKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	// AIC missing → error.
	_, err = SignJWT(&SignConfig{CAKey: caKey, CACert: caCert, SubjectPubKey: agentKey.Public()}, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error when AIC is nil")
	}

	// agentId empty → error.
	_, err = SignJWT(&SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: agentKey.Public(),
		AIC: &AICConfig{
			AgentId: "", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: ph},
			DelegationAuthorization: testAICDelegation(),
		},
	}, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error when agentId empty")
	}

	// Missing SubjectPubKey → cnf.jkt empty error.
	okAIC := &AICConfig{
		AgentId: "agent-008", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: ph},
		Capabilities:            []Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
		DelegationAuthorization: testAICDelegation(),
	}
	_, err = SignJWT(&SignConfig{CAKey: caKey, CACert: caCert, AIC: okAIC}, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error when SubjectPubKey is nil (cnf.jkt)")
	}

	// >256 caps → error.
	tooMany := make([]Capability, 257)
	for i := range tooMany {
		tooMany[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	_, err = SignJWT(&SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: agentKey.Public(),
		AIC: &AICConfig{
			AgentId: "agent-009", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: ph},
			Capabilities: tooMany, DelegationAuthorization: testAICDelegation(),
		},
	}, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error when capabilities > 256")
	}
}

func TestSignJWTBadNonce(t *testing.T) {
	caCert, caKey := newTestCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ph := keyHashOfPub(t, agentKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignJWT(&SignConfig{
		CAKey: caKey, CACert: caCert, SubjectPubKey: agentKey.Public(),
		AIC: &AICConfig{
			AgentId: "agent-010", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: ph},
			Capabilities: []Capability{{SchemeId: "s", CapabilityId: "c"}},
			DelegationAuthorization: &DelegationAuthorization{
				Reason: Reason{ReasonCode: "R", Description: "d"},
				Nonce:  make([]byte, 16), // not 32 bytes
			},
		},
	}, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error when DA nonce is not 32 bytes")
	}
}

// TestSignJWT_RSA uses an RSA CA to exercise the RS256 path end-to-end.
func TestSignJWT_RepresentativeRequiresDA(t *testing.T) {
	caCert, caKey := newTestCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The principal (represented user) signs the DA; the agent key is the
	// token's cnf binding.
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userHash := keyHashOfPub(t, userKey.Public())
	userCert := principalCert(t, userKey)

	aic := &AICConfig{
		AgentId: "agent-rep", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: userHash},
		Capabilities:            []Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
		DelegationMode:          DelegationRepresentative,
		DelegationAuthorization: testAICDelegation(),
	}
	sc := &SignConfig{CAKey: caKey, CACert: caCert, SubjectPubKey: agentKey.Public(), AIC: aic, Validity: time.Hour}

	// No DA → reject.
	_, err = SignJWT(sc, JWTSignOptions{})
	if err == nil {
		t.Fatal("expected error: representative mode without DA JWS")
	}

	// With a genuine DA JWS signed by the user key → pass.
	da := buildTestDA(t, userKey, userHash)
	res, err := SignJWT(sc, JWTSignOptions{DA: da})
	if err != nil {
		t.Fatalf("SignJWT(representative+DA): %v", err)
	}
	if res.Claims.Aic.DelegationMode != "representative" {
		t.Fatalf("delegation_mode = %q, want representative", res.Claims.Aic.DelegationMode)
	}
	// The outer token must now validate with the DA present.
	if _, err := aicjwt.Validate(res.Token, aicjwt.VerifyOptions{
		IssuerKeys: map[string]crypto.PublicKey{res.Header.Kid: caKey.Public()},
		PrincipalMaterial: &aicjwt.PrincipalKeyMaterial{
			X5C: []*x509.Certificate{userCert},
		},
		PA: &aicjwt.PAClaims{
			Ver: 1,
			Principal: aicjwt.Principal{
				Realm: "r", ID: "i", KeyHash: b64uEncode(userHash), HashAlg: "sha-256",
			},
			Grants: []aicjwt.Capability{{Scheme: "std/database-v1", ID: "SELECT:*"}},
			DelegationPolicy: &aicjwt.DelegationPolicy{
				MaxAgents:   1,
				AllowedMode: aicjwt.AllowedModeRepresentative,
			},
		},
		Now: time.Now(),
	}); err != nil {
		t.Fatalf("validate representative token: %v", err)
	}
}

func buildTestDA(t *testing.T, principalKey *ecdsa.PrivateKey, keyHash []byte) string {
	t.Helper()
	da := aicjwt.DAClaims{
		Ver:     1,
		AgentID: "agent-rep",
		Principal: aicjwt.Principal{
			Realm: "r", ID: "i", KeyHash: b64uEncode(keyHash), HashAlg: "sha-256",
		},
		Reason:            aicjwt.Reason{Code: "ROTATION", Desc: "test DA"},
		Capabilities:      []aicjwt.Capability{{Scheme: "std/database-v1", ID: "SELECT:*"}},
		DelegationMode:    "representative",
		RequestedLifetime: 3600,
		TS:                time.Now().Unix(),
		Nonce:             b64uEncode(make([]byte, 32)),
	}
	hdrBS, err := json.Marshal(&aicjwt.Header{Alg: "ES256", Typ: "aic+da+jwt", Kid: "principal-kid"})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(&da)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := aicjwt.SignCompact(hdrBS, pb, "ES256", principalKey)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func principalCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "principal-representative"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignJWT_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caCert := selfSignedRSA(t, key)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ph := keyHashOfPub(t, agentKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	res, err := SignJWT(&SignConfig{
		CAKey: key, CACert: caCert, SubjectPubKey: agentKey.Public(),
		Validity: 30 * time.Minute,
		AIC: &AICConfig{
			AgentId: "agent-rsa", PrincipalUid: PrincipalUid{Realm: "r", Identifier: "i", KeyHash: ph},
			Capabilities:            []Capability{{SchemeId: "std/database-v1", CapabilityId: "SELECT:*"}},
			DelegationAuthorization: testAICDelegation(),
		},
	}, JWTSignOptions{})
	if err != nil {
		t.Fatalf("SignJWT(RSA): %v", err)
	}
	if res.Alg != "RS256" {
		t.Fatalf("alg = %q, want RS256", res.Alg)
	}
	if _, err := aicjwt.Validate(res.Token, aicjwt.VerifyOptions{
		IssuerKeys: map[string]crypto.PublicKey{res.Header.Kid: key.Public()},
		Now:        time.Now(),
	}); err != nil {
		t.Fatalf("validate RSA token: %v", err)
	}
}

// L19: JWT jti must be cryptographically random and unique per issuance. It
// must never fall back to the guessable time-based value the old
// randomTokenID used when randomness unavailable.
func TestSignJWT_JtiRandomL19(t *testing.T) {
	caCert, caKey := newTestCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := &AICConfig{
		AgentId:                 "agent-l19",
		PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "u@varwof.com", KeyHash: keyHashOfPub(t, principalKey.Public())},
		Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}},
		DelegationAuthorization: testAICDelegation(),
		DelegationMode:          DelegationAuthorized,
	}
	sc := &SignConfig{
		CAKey: caKey, CACert: caCert, CAName: "test-ca",
		Profile: ProfileAgentProxy, CommonName: "agent-l19",
		SubjectPubKey: agentKey.Public(), Validity: time.Hour, AIC: aic,
	}
	mk := func() string {
		res, err := SignJWT(sc, JWTSignOptions{})
		if err != nil {
			t.Fatalf("SignJWT: %v", err)
		}
		return res.Claims.Jti
	}

	j1 := mk()
	j2 := mk()
	if j1 == "" || j2 == "" {
		t.Fatal("jti must be present")
	}
	if j1 == j2 {
		t.Fatal("jti must be unique per issuance")
	}
	// A time-based fallback would be a decimal timestamp string, not base64url;
	// a random 12-byte jti decodes to exactly 12 bytes.
	raw, err := base64.RawURLEncoding.DecodeString(j1)
	if err != nil {
		t.Fatalf("jti %q is not base64url (L19 fallback?): %v", j1, err)
	}
	if len(raw) != 12 {
		t.Fatalf("jti %q decodes to %d bytes, want 12 (random, not time-based)", j1, len(raw))
	}
}

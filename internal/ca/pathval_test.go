// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// C3: path building + policy verification engine tests
// ─────────────────────────────────────────────────────────────────────

// certGen holds a certificate and its signing key.
type certGen struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// genRoot builds a self-signed trust anchor.
func genRoot(t *testing.T, cn string) *certGen {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certGen{cert: cert, key: key}
}

// genIntermediate builds a CA certificate signed by parent, optionally with
// policy extensions.
func genIntermediate(t *testing.T, parent *certGen, cn string, opts map[string]any) *certGen {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if pm, ok := opts["policy_mappings"].([]x509.PolicyMapping); ok && len(pm) > 0 {
		type Mapping struct {
			IssuerDomainPolicy  asn1.ObjectIdentifier
			SubjectDomainPolicy asn1.ObjectIdentifier
		}
		mappings := make([]Mapping, 0, len(pm))
		for _, m := range pm {
			mappings = append(mappings, Mapping{
				IssuerDomainPolicy:  asn1OIDFromX509(m.IssuerDomainPolicy),
				SubjectDomainPolicy: asn1OIDFromX509(m.SubjectDomainPolicy),
			})
		}
		b, err := asn1.Marshal(mappings)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 33},
			Value: b,
		})
	}
	if v, ok := opts["require_explicit"]; ok {
		// Go's x509.CreateCertificate does not emit policyConstraints — encode it
		// manually (mirrors addPolicyExtensions in sign.go).
		type policyConstraints struct {
			RequireExplicitPolicy int `asn1:"optional,explicit,tag:0"`
		}
		b, err := asn1.Marshal(policyConstraints{RequireExplicitPolicy: v.(int)})
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 36},
			Critical: true,
			Value:    b,
		})
	}
	if v, ok := opts["inhibit_any"]; ok {
		// Go's x509.CreateCertificate does not emit inhibitAnyPolicy — encode it
		// manually (mirrors addPolicyExtensions in sign.go).
		b, err := asn1.Marshal(v.(int))
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 54},
			Critical: true,
			Value:    b,
		})
	}
	if v, ok := opts["policies"].([]string); ok {
		oids := make([]x509.OID, 0, len(v))
		for _, p := range v {
			oids = append(oids, mustOIDFromStr(p))
		}
		tmpl.Policies = oids
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certGen{cert: cert, key: key}
}

// genLeaf builds an end-entity certificate signed by parent, optionally with
// certificate policies.
func genLeaf(t *testing.T, parent *certGen, cn string, policies []string) *certGen {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if len(policies) > 0 {
		oids := make([]x509.OID, 0, len(policies))
		for _, p := range policies {
			oids = append(oids, mustOIDFromStr(p))
		}
		tmpl.Policies = oids
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certGen{cert: cert, key: key}
}

func mustOIDFromStr(s string) x509.OID {
	oid, err := x509.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return oid
}

func asn1OIDFromX509(o x509.OID) asn1.ObjectIdentifier {
	out, err := parseOID(o.String())
	if err != nil {
		panic(err)
	}
	return out
}

func TestBuildChainToRoot(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", nil)

	src := &StaticSource{Roots: []*x509.Certificate{root.cert}, CAs: []*x509.Certificate{sub.cert}}
	chain, trusted, err := BuildChain(leaf.cert, src, 8)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted root")
	}
	if len(chain) != 3 {
		t.Fatalf("want 3 hops (leaf, sub, root), got %d", len(chain))
	}
	if chain[0].Subject.CommonName != "leaf.example.com" || chain[2].Subject.CommonName != "Root CA" {
		t.Fatalf("chain order wrong: %v -> %v", chain[0].Subject.CommonName, chain[2].Subject.CommonName)
	}
}

func TestBuildChainUntrustedTerminal(t *testing.T) {
	root := genRoot(t, "Root CA")
	otherRoot := genRoot(t, "Other Root")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", nil)

	// root is present as a CA (buildable) but NOT a trust anchor; otherRoot is
	// the only anchor. Path reaches root but is not trusted.
	src := &StaticSource{Roots: []*x509.Certificate{otherRoot.cert}, CAs: []*x509.Certificate{sub.cert, root.cert}}
	chain, trusted, err := BuildChain(leaf.cert, src, 8)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if trusted {
		t.Fatal("should not be trusted: terminal root not in anchors")
	}
	if len(chain) != 3 {
		t.Fatalf("chain should still reach root CA, got %d hops", len(chain))
	}
}

func TestBuildChainMaxDepth(t *testing.T) {
	root := genRoot(t, "Root CA")
	var chain []*x509.Certificate
	prev := root
	for i := 0; i < 20; i++ {
		prev = genIntermediate(t, prev, "L"+string(rune('A'+i)), nil)
		chain = append(chain, prev.cert)
	}
	leaf := genLeaf(t, prev, "leaf.example.com", nil)
	src := &StaticSource{Roots: []*x509.Certificate{root.cert}, CAs: chain}
	got, _, err := BuildChain(leaf.cert, src, 4)
	if err == nil {
		t.Fatal("expected max depth error")
	}
	_ = got
}

func TestBuildChainCycleProtection(t *testing.T) {
	// A single self-signed root: BuildChain from a leaf under root reaches the
	// root and returns; the seen-set cycle protection path is exercised when the
	// same CA is a candidate twice (impossible with distinct DER). We verify the
	// happy path terminates with a bounded chain.
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", nil)
	src := &StaticSource{Roots: []*x509.Certificate{root.cert}, CAs: []*x509.Certificate{sub.cert, sub.cert}}
	chain, trusted, err := BuildChain(leaf.cert, src, 8)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted")
	}
	if len(chain) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(chain))
	}
}

func TestVerifyPathRejectsExpired(t *testing.T) {
	root := genRoot(t, "Root CA")
	leaf := genLeaf(t, root, "leaf.example.com", nil)
	leaf.cert.NotAfter = time.Now().Add(-time.Hour)
	chain := []*x509.Certificate{leaf.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Valid {
		t.Fatal("expected invalid: expired cert")
	}
}

func TestVerifyPathRejectsNonCACheckSignature(t *testing.T) {
	root := genRoot(t, "Root CA")
	// leaf2 signed by leaf (non-CA)
	leaf1 := genLeaf(t, root, "leaf1", nil)
	leaf2 := genLeaf(t, leaf1, "leaf2", nil)
	chain := []*x509.Certificate{leaf2.cert, leaf1.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Valid {
		t.Fatal("expected invalid: non-CA in chain")
	}
	if res.RejectReason == "" {
		t.Fatal("expected reject reason")
	}
}

// TestEvaluatePolicyMappings verifies RFC 5280 §6.1 policy mapping: the
// intermediate CA maps 1.2.3.4.1 → 1.2.3.4.2; the leaf carries 1.2.3.4.1 and
// the user requests 1.2.3.4.2 → the mapping makes it accepted.
func TestEvaluatePolicyMappings(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Bridge CA", map[string]any{
		"policy_mappings": []x509.PolicyMapping{
			{IssuerDomainPolicy: mustOIDFromStr("1.2.3.4.1"), SubjectDomainPolicy: mustOIDFromStr("1.2.3.4.2")},
		},
	})
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.1"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.2"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid, reject=%q", res.RejectReason)
	}
	if res.Policy == nil {
		t.Fatal("expected policy decision")
	}
	if len(res.Policy.AcceptedUserPolicies) != 1 || res.Policy.AcceptedUserPolicies[0] != "1.2.3.4.2" {
		t.Fatalf("expected accepted policy 1.2.3.4.2 via mapping, got %v", res.Policy.AcceptedUserPolicies)
	}
}

// TestEvaluatePolicyNoMappingRejected verifies that without mapping the
// requested policy is rejected.
func TestEvaluatePolicyNoMappingRejected(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.1"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.2"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	// Structurally valid, but policy acceptance fails because the chain never
	// carries 1.2.3.4.2 (no mapping).
	if res.Valid == false {
		t.Fatal("expected structurally valid")
	}
	if res.Policy == nil || len(res.Policy.AcceptedUserPolicies) != 0 {
		t.Fatalf("expected zero accepted policies, got %v", res.Policy.AcceptedUserPolicies)
	}
}

// TestEvaluatePolicyExplicitPolicy verifies requireExplicitPolicy enforcement:
// when the leaf carries a policy and the chain requires explicit policy, the
// policy is honored.
func TestEvaluatePolicyExplicitPolicy(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", map[string]any{
		"require_explicit": 0,
	})
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.5"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.5"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid with explicit policy, reject=%q", res.RejectReason)
	}
	if len(res.Policy.AcceptedUserPolicies) != 1 {
		t.Fatalf("expected 1 accepted policy, got %v", res.Policy.AcceptedUserPolicies)
	}
}

// TestEvaluatePolicyAcceptAny verifies empty user policy set accepts the leaf
// policy.
func TestEvaluatePolicyAcceptAny(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.5"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy: true, // empty user set = accept any
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid with any-policy acceptance, reject=%q", res.RejectReason)
	}
	if len(res.Policy.AcceptedUserPolicies) != 1 || res.Policy.AcceptedUserPolicies[0] != "1.2.3.4.5" {
		t.Fatalf("expected accepted policy 1.2.3.4.5, got %v", res.Policy.AcceptedUserPolicies)
	}
}

// TestEvaluatePolicyInhibitAnyPolicyIntermediate verifies that an
// inhibitAnyPolicy constraint asserted by an intermediate CA (not the leaf) is
// honored via the per-certificate minimum (RFC 5280 §6.1.5(j)).
func TestEvaluatePolicyInhibitAnyPolicyIntermediate(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", map[string]any{
		"inhibit_any": 0,
	})
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.5"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.5"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Policy == nil {
		t.Fatal("expected policy decision")
	}
	if !res.Policy.InhibitAnyPolicyHit {
		t.Fatal("expected InhibitAnyPolicyHit when intermediate asserts inhibitAnyPolicy=0")
	}
}

// TestEvaluatePolicyInhibitAnyPolicyLeaf verifies that an inhibitAnyPolicy
// constraint seeded from the leaf is enforced as the walk moves upward.
func TestEvaluatePolicyInhibitAnyPolicyLeaf(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// Go's x509.CreateCertificate does not emit inhibitAnyPolicy — encode it manually.
	inhibitBytes, err := asn1.Marshal(0)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 54},
		Critical: true,
		Value:    inhibitBytes,
	})
	oids := make([]x509.OID, 0, 1)
	oids = append(oids, mustOIDFromStr("1.2.3.4.5"))
	tmpl.Policies = oids
	der, err := x509.CreateCertificate(rand.Reader, tmpl, sub.cert, &key.PublicKey, sub.key)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{leafCert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.5"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Policy == nil {
		t.Fatal("expected policy decision")
	}
	if !res.Policy.InhibitAnyPolicyHit {
		t.Fatal("expected InhibitAnyPolicyHit when leaf asserts inhibitAnyPolicy=0")
	}
}

// TestEvaluatePolicyNoInhibitAnyPolicy verifies the flag stays false when no
// certificate along the path asserts inhibitAnyPolicy.
func TestEvaluatePolicyNoInhibitAnyPolicy(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"1.2.3.4.5"})
	chain := []*x509.Certificate{leaf.cert, sub.cert, root.cert}

	res, err := VerifyPath(chain, nil, VerifyPathOptions{
		VerifyPolicy:         true,
		UserInitialPolicySet: []string{"1.2.3.4.5"},
	})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Policy == nil {
		t.Fatal("expected policy decision")
	}
	if res.Policy.InhibitAnyPolicyHit {
		t.Fatal("expected InhibitAnyPolicyHit=false without inhibitAnyPolicy extension")
	}
}

// TestVerifyPathWithStaticSource builds via the engine and checks policy.
func TestVerifyPathWithStaticSource(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", []string{"2.5.29.32.0"})

	src := &StaticSource{Roots: []*x509.Certificate{root.cert}, CAs: []*x509.Certificate{sub.cert}}
	res, err := VerifyPath([]*x509.Certificate{leaf.cert}, src, VerifyPathOptions{VerifyPolicy: true})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid, reject=%q", res.RejectReason)
	}
	if !res.RootIsTrusted {
		t.Fatal("expected root trusted")
	}
	if len(res.Chain) != 3 {
		t.Fatalf("expected chain of 3, got %d", len(res.Chain))
	}
}

// ─────────────────────────────────────────────────────────────────────
// H6: RFC 5280 path length / name constraints / keyCertSign enforcement
// ─────────────────────────────────────────────────────────────────────

// TestVerifyPathPathLenConstraint verifies MaxPathLen is enforced: a
// pathlen:0 sub-CA must not be able to have another CA beneath it.
func TestVerifyPathPathLenConstraint(t *testing.T) {
	root := genRoot(t, "Root CA")
	// sub has MaxPathLen=0 → no subordinate CAs allowed.
	sub := genIntermediate(t, root, "Sub CA", nil)
	sub.cert.MaxPathLen = 0
	sub.cert.MaxPathLenZero = true
	sub.cert.BasicConstraintsValid = true
	// A second-level CA beneath sub.
	sub2 := genIntermediate(t, sub, "Sub2 CA", nil)
	leaf := genLeaf(t, sub2, "leaf.example.com", nil)

	chain := []*x509.Certificate{leaf.cert, sub2.cert, sub.cert, root.cert}
	res, err := VerifyPath(chain, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected pathlen violation, got valid: %s", res.RejectReason)
	}
	if !strings.Contains(res.RejectReason, "path length") {
		t.Fatalf("expected path length rejection, got: %s", res.RejectReason)
	}

	// Sanity: with a deep enough pathlen the same chain is valid.
	sub.cert.MaxPathLen = 1
	sub.cert.MaxPathLenZero = false
	res2, err := VerifyPath(chain, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Valid {
		t.Fatalf("expected valid with sufficient pathlen: %s", res2.RejectReason)
	}
}

// TestVerifyPathNameConstraintDNS verifies name constraint enforcement: a
// sub-CA constrained to DNS:.example.com must not issue for another domain.
func TestVerifyPathNameConstraintDNS(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	sub.cert.PermittedDNSDomains = []string{".example.com"}
	sub.cert.PermittedDNSDomainsCritical = true

	ok := genLeaf(t, sub, "good.example.com", nil)
	ok.cert.DNSNames = []string{"good.example.com"}

	// Rebuild the leaf cert with a SAN outside the constraint. genLeaf creates
	// no SAN, so set it directly (the parsed cert is what VerifyPath reads).
	bad := genLeaf(t, sub, "evil.org", nil)
	bad.cert.DNSNames = []string{"evil.org"}

	resGood, err := VerifyPath([]*x509.Certificate{ok.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if !resGood.Valid {
		t.Fatalf("expected good.example.com valid: %s", resGood.RejectReason)
	}

	resBad, err := VerifyPath([]*x509.Certificate{bad.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify bad: %v", err)
	}
	if resBad.Valid {
		t.Fatalf("expected evil.org rejected by name constraint: %s", resBad.RejectReason)
	}
	if !strings.Contains(resBad.RejectReason, "name constraint") {
		t.Fatalf("expected name constraint reason, got: %s", resBad.RejectReason)
	}
}

// TestVerifyPathNameConstraintPropagates verifies RFC 5280 §4.2.1.10: a
// trusted root's name constraint must be applied not only to its immediate
// intermediate but to every certificate below it — including the leaf. A leaf
// outside the root's permitted DNS subtree must be rejected even when the
// intermediate directly above it imposes no constraint.
func TestVerifyPathNameConstraintPropagates(t *testing.T) {
	root := genRoot(t, "Root CA")
	root.cert.PermittedDNSDomains = []string{".example.com"}
	root.cert.PermittedDNSDomainsCritical = true
	sub := genIntermediate(t, root, "sub.example.com", nil)

	ok := genLeaf(t, sub, "good.example.com", nil)
	ok.cert.DNSNames = []string{"good.example.com"}

	bad := genLeaf(t, sub, "evil.org", nil)
	bad.cert.DNSNames = []string{"evil.org"}

	resGood, err := VerifyPath([]*x509.Certificate{ok.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if !resGood.Valid {
		t.Fatalf("expected good.example.com valid under propagated constraint: %s", resGood.RejectReason)
	}

	resBad, err := VerifyPath([]*x509.Certificate{bad.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify bad: %v", err)
	}
	if resBad.Valid {
		t.Fatalf("expected evil.org rejected by root propagated name constraint: %s", resBad.RejectReason)
	}
	if !strings.Contains(resBad.RejectReason, "name constraint") {
		t.Fatalf("expected name constraint reason, got: %s", resBad.RejectReason)
	}
}

// TestVerifyPathKeyUsageCertSign verifies a CA without keyCertSign cannot sign
// a subordinate. Go's CheckSignatureFrom rejects such a signature outright, so
// the exact rejection reason may be Go's or our explicit keyCertSign check —
// what matters is the path is invalid.
func TestVerifyPathKeyUsageCertSign(t *testing.T) {
	root := genRoot(t, "Root CA")
	// Root itself lacks keyCertSign → its signature on the sub must be rejected.
	root.cert.KeyUsage = x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	sub := genIntermediate(t, root, "Sub CA", nil)
	leaf := genLeaf(t, sub, "leaf.example.com", nil)

	res, err := VerifyPath([]*x509.Certificate{leaf.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatalf("verify path: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected keyCertSign violation, got valid: %s", res.RejectReason)
	}
	if res.RejectReason == "" {
		t.Fatal("expected a rejection reason")
	}
}

// TestVerifyPathIPNameConstraint verifies IP CIDR name constraint enforcement.
func TestVerifyPathIPNameConstraint(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)
	_, net10, _ := net.ParseCIDR("10.0.0.0/8")
	sub.cert.PermittedIPRanges = []*net.IPNet{net10}

	good := genLeaf(t, sub, "ip-leaf", nil)
	good.cert.IPAddresses = []net.IP{net.ParseIP("10.1.2.3")}
	bad := genLeaf(t, sub, "ip-leaf", nil)
	bad.cert.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}

	resGood, err := VerifyPath([]*x509.Certificate{good.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !resGood.Valid {
		t.Fatalf("expected 10.1.2.3 valid: %s", resGood.RejectReason)
	}
	resBad, err := VerifyPath([]*x509.Certificate{bad.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resBad.Valid {
		t.Fatalf("expected 192.168.1.1 rejected: %s", resBad.RejectReason)
	}
}

// genLeafUnknownCritical builds an end-entity certificate carrying an
// unrecognized CRITICAL extension. RFC 5280 §4.1.1.2 requires such a
// certificate to be rejected; Go surfaces it via UnhandledCriticalExtensions.
func genLeafUnknownCritical(t *testing.T, parent *certGen, cn string) *certGen {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
			Critical: true,
			Value:    []byte("unknown-critical"),
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.UnhandledCriticalExtensions) == 0 {
		t.Fatal("expected UnhandledCriticalExtensions to be populated for unknown critical extension")
	}
	return &certGen{cert: cert, key: key}
}

// TestVerifyPathRejectsUnhandledCritical verifies F7.2: VerifyPath must reject
// any certificate carrying an unrecognized CRITICAL extension (RFC 5280
// §4.1.1.2), and still accept an otherwise-identical chain without one.
func TestVerifyPathRejectsUnhandledCritical(t *testing.T) {
	root := genRoot(t, "Root CA")
	sub := genIntermediate(t, root, "Sub CA", nil)

	good := genLeaf(t, sub, "leaf.example.com", nil)
	resGood, err := VerifyPath([]*x509.Certificate{good.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !resGood.Valid {
		t.Fatalf("normal chain should be valid: %s", resGood.RejectReason)
	}

	bad := genLeafUnknownCritical(t, sub, "leaf.example.com")
	resBad, err := VerifyPath([]*x509.Certificate{bad.cert, sub.cert, root.cert}, nil, VerifyPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resBad.Valid {
		t.Fatal("expected path with unrecognized critical extension to be rejected")
	}
	if !strings.Contains(resBad.RejectReason, "unrecognized critical extension") {
		t.Fatalf("expected reject reason mentioning unrecognized critical extension, got: %q", resBad.RejectReason)
	}
}

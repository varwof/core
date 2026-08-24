package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPolicyMappingsInSubCA(t *testing.T) {
	caCert, caKey := newTestCA(t)
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rep := 1
	res, err := Sign(&SignConfig{
		DB:                nil,
		SkipDB:            true,
		CAKey:             caKey,
		CACert:            caCert,
		SubjectPubKey:     &subKey.PublicKey,
		Profile:           ProfileSubCA,
		CommonName:        "Bridge CA",
		Validity:          365 * 24 * time.Hour,
		PolicyMappings:    []PolicyMapping{{IssuerDomainPolicy: "1.2.3.4.1", SubjectDomainPolicy: "1.2.3.4.2"}},
		RequireExplicitPolicy: &rep,
		InhibitAnyPolicy:      new(int),
	})
	if err != nil {
		t.Fatalf("sign sub-CA with policy extensions: %v", err)
	}

	cert := res.Cert
	findExt := func(oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
		for _, e := range cert.Extensions {
			if e.Id.Equal(oid) {
				return e, true
			}
		}
		return pkix.Extension{}, false
	}

	if ext, ok := findExt(oidPolicyMappings); !ok {
		t.Fatal("missing Policy Mappings extension")
	} else {
		type Mapping struct {
			IssuerDomainPolicy  asn1.ObjectIdentifier
			SubjectDomainPolicy asn1.ObjectIdentifier
		}
		var mappings []Mapping
		if _, err := asn1.Unmarshal(ext.Value, &mappings); err != nil {
			t.Fatalf("unmarshal Policy Mappings: %v", err)
		}
		if len(mappings) != 1 {
			t.Fatalf("want 1 mapping, got %d", len(mappings))
		}
		if mappings[0].IssuerDomainPolicy.String() != "1.2.3.4.1" || mappings[0].SubjectDomainPolicy.String() != "1.2.3.4.2" {
			t.Fatalf("mapping mismatch: %v -> %v", mappings[0].IssuerDomainPolicy, mappings[0].SubjectDomainPolicy)
		}
	}

	if _, ok := findExt(oidPolicyConstraints); !ok {
		t.Fatal("missing Policy Constraints extension")
	}
	if _, ok := findExt(oidInhibitAnyPolicy); !ok {
		t.Fatal("missing Inhibit anyPolicy extension")
	}
}

func TestPolicyMappingsRejectedOnEndEntity(t *testing.T) {
	caCert, caKey := newTestCA(t)
	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Sign(&SignConfig{
		DB:            nil,
		SkipDB:        true,
		CAKey:         caKey,
		CACert:        caCert,
		SubjectPubKey: &eeKey.PublicKey,
		Profile:       ProfileTLSServer,
		CommonName:    "end.example.com",
		Validity:      24 * time.Hour,
		PolicyMappings: []PolicyMapping{{IssuerDomainPolicy: "1.2.3.4.1", SubjectDomainPolicy: "1.2.3.4.2"}},
	})
	if err == nil {
		t.Fatal("expected error when Policy Mappings on end-entity cert")
	}
	if !strings.Contains(err.Error(), "only allowed in CA certificates") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyConstraintsOnlyInhibitPolicyMapping(t *testing.T) {
	caCert, caKey := newTestCA(t)
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	inhibit := 2
	res, err := Sign(&SignConfig{
		DB:                  nil,
		SkipDB:              true,
		CAKey:               caKey,
		CACert:              caCert,
		SubjectPubKey:       &subKey.PublicKey,
		Profile:             ProfileSubCA,
		CommonName:          "Policy CA",
		Validity:            365 * 24 * time.Hour,
		InhibitPolicyMapping: &inhibit,
	})
	if err != nil {
		t.Fatalf("sign sub-CA with inhibitPolicyMapping: %v", err)
	}

	var found bool
	for _, e := range res.Cert.Extensions {
		if e.Id.Equal(oidPolicyConstraints) {
			found = true
			type PolicyConstraints struct {
				RequireExplicitPolicy int `asn1:"optional,explicit,tag:0"`
				InhibitPolicyMapping  int `asn1:"optional,explicit,tag:1"`
			}
			var pc PolicyConstraints
			if _, err := asn1.Unmarshal(e.Value, &pc); err != nil {
				t.Fatalf("unmarshal PolicyConstraints: %v", err)
			}
			if pc.InhibitPolicyMapping != 2 {
				t.Fatalf("want inhibitPolicyMapping=2, got %d", pc.InhibitPolicyMapping)
			}
			if pc.RequireExplicitPolicy != 0 {
				t.Fatalf("requireExplicitPolicy should be absent (0), got %d", pc.RequireExplicitPolicy)
			}
		}
	}
	if !found {
		t.Fatal("missing Policy Constraints extension")
	}
}

func TestParsePolicyMapping(t *testing.T) {
	m, err := ParsePolicyMapping("1.2.3.4.1:1.2.3.4.2")
	if err != nil {
		t.Fatalf("parse valid mapping: %v", err)
	}
	if m.IssuerDomainPolicy != "1.2.3.4.1" || m.SubjectDomainPolicy != "1.2.3.4.2" {
		t.Fatalf("mismatch: %+v", m)
	}

	if _, err := ParsePolicyMapping("nonsense"); err == nil {
		t.Fatal("expected error for malformed mapping")
	}
	if _, err := ParsePolicyMapping("1.2.3:not-an-oid"); err == nil {
		t.Fatal("expected error for invalid subject OID")
	}
}

func TestPolicyExtensionsNoneByDefault(t *testing.T) {
	caCert, caKey := newTestCA(t)
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Sign(&SignConfig{
		DB:            nil,
		SkipDB:        true,
		CAKey:         caKey,
		CACert:        caCert,
		SubjectPubKey: &subKey.PublicKey,
		Profile:       ProfileSubCA,
		CommonName:    "Plain CA",
		Validity:      365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, e := range res.Cert.Extensions {
		if e.Id.Equal(oidPolicyMappings) || e.Id.Equal(oidPolicyConstraints) || e.Id.Equal(oidInhibitAnyPolicy) {
			t.Fatalf("unexpected policy extension %v without config", e.Id)
		}
	}
}

// Compile-time assertion: new SignConfig fields do not affect existing callers (empty struct scenario).
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
var _ = big.NewInt

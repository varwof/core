package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDelegationModeConstants(t *testing.T) {
	if DelegationAuthorized != 0 {
		t.Fatalf("DelegationAuthorized: expected 0, got %d", DelegationAuthorized)
	}
	if DelegationRepresentative != 1 {
		t.Fatalf("DelegationRepresentative: expected 1, got %d", DelegationRepresentative)
	}
}

func TestBuildAIC_EmptyAgentId(t *testing.T) {
	_, err := BuildAIC(AICConfig{
		AgentId:      "",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
	})
	if err == nil {
		t.Fatal("expected error for empty AgentId")
	}
}

func TestBuildAIC_EmptyPrincipalUid(t *testing.T) {
	_, err := BuildAIC(AICConfig{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{},
	})
	if err == nil {
		t.Fatal("expected error for empty PrincipalUid")
	}
}

func TestBuildAIC_RealmIdentifierBounds(t *testing.T) {
	base := func(pu PrincipalUid) AICConfig {
		return AICConfig{
			AgentId:                 "agent-1",
			PrincipalUid:            pu,
			Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"}},
			DelegationAuthorization: testAICDelegation(),
		}
	}
	cases := []struct {
		name string
		pu   PrincipalUid
	}{
		{"empty realm", PrincipalUid{Realm: "", Identifier: "i", KeyHash: testAICKeyHash()}},
		{"realm too long", PrincipalUid{Realm: strings.Repeat("r", 129), Identifier: "i", KeyHash: testAICKeyHash()}},
		{"empty identifier", PrincipalUid{Realm: "r", Identifier: "", KeyHash: testAICKeyHash()}},
		{"identifier too long", PrincipalUid{Realm: "r", Identifier: strings.Repeat("i", 257), KeyHash: testAICKeyHash()}},
	}
	for _, c := range cases {
		if _, err := BuildAIC(base(c.pu)); err == nil {
			t.Fatalf("expected error for %s", c.name)
		}
	}
	// Boundary: max legal realm/identifier must pass.
	max := PrincipalUid{
		Realm:      strings.Repeat("r", 128),
		Identifier: strings.Repeat("i", 256),
		KeyHash:    testAICKeyHash(),
	}
	if _, err := BuildAIC(base(max)); err != nil {
		t.Fatalf("expected max-length realm/identifier to pass: %v", err)
	}
}

func TestBuildAIC_RoundTrip(t *testing.T) {
	cfg := AICConfig{
		AgentId:      "agent-001",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "admin@varwof.com", KeyHash: testAICKeyHash()},
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"},
		},
		DelegationAuthorization: testAICDelegation(),
	}
	ext, err := BuildAIC(cfg)
	if err != nil {
		t.Fatalf("BuildAIC: %v", err)
	}
	if !ext.Id.Equal(OIDAIC) {
		t.Fatalf("OID mismatch: expected %v, got %v", OIDAIC, ext.Id)
	}
	if ext.Critical {
		t.Fatal("AIC extension should NOT be critical (non-critical allows standard TLS to ignore it; gateway parses at application layer)")
	}

	parsed, err := ParseAIC(certFromExt(ext))
	if err != nil {
		t.Fatalf("ParseAIC: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed AIC")
	}
	if parsed.AgentId != "agent-001" {
		t.Fatalf("AgentId: expected agent-001, got %s", parsed.AgentId)
	}
	if parsed.PrincipalUid.Identifier != "admin@varwof.com" {
		t.Fatalf("PrincipalUid.Identifier: expected admin@varwof.com, got %s", parsed.PrincipalUid.Identifier)
	}
	if len(parsed.Capabilities) != 1 {
		t.Fatalf("Capabilities len: expected 1, got %d", len(parsed.Capabilities))
	}
	if parsed.Capabilities[0].CapabilityId != "gateway:admin" {
		t.Fatalf("CapabilityId: expected gateway:admin, got %s", parsed.Capabilities[0].CapabilityId)
	}
}

func TestBuildAIC_WithDelegationAuthorization(t *testing.T) {
	cfg := AICConfig{
		AgentId:      "agent-004",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: testAICKeyHash()},
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"},
		},
		DelegationAuthorization: &DelegationAuthorization{
			Reason:             Reason{ReasonCode: "ROTATION", Description: "key rotation"},
			SignatureValue:     []byte{0xde, 0xad, 0xbe, 0xef},
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			Timestamp:          time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
			Nonce:              make([]byte, 32),
			RequestedLifetime:  86400,
		},
	}
	ext, err := BuildAIC(cfg)
	if err != nil {
		t.Fatalf("BuildAIC: %v", err)
	}
	parsed, _ := ParseAIC(certFromExt(ext))
	if parsed == nil {
		t.Fatal("expected non-nil parsed AIC")
	}
	if !parsed.DelegationAuthorization.SignatureAlgorithm.Algorithm.Equal(OIDSigECDSAWithSHA256) {
		t.Fatalf("SignatureAlgorithm: got %v", parsed.DelegationAuthorization.SignatureAlgorithm)
	}
	if parsed.DelegationAuthorization.Timestamp.Year() != 2026 {
		t.Fatalf("Timestamp year: expected 2026, got %d", parsed.DelegationAuthorization.Timestamp.Year())
	}
}

func TestBuildAIC_NilCapabilitiesBecomesEmpty(t *testing.T) {
	cfg := AICConfig{
		AgentId:      "agent-005",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: testAICKeyHash()},
	// V16: capabilities and authorizationConstraints must not both be empty → provide one constraint
		AuthorizationConstraints: []Capability{
			{SchemeId: "constraint", CapabilityId: "session:max-1h"},
		},
		DelegationAuthorization: testAICDelegation(),
	}
	ext, err := BuildAIC(cfg)
	if err != nil {
		t.Fatalf("BuildAIC: %v", err)
	}
	parsed, _ := ParseAIC(certFromExt(ext))
	if parsed == nil {
		t.Fatal("expected non-nil parsed AIC")
	}
	if parsed.Capabilities == nil {
		t.Fatal("Capabilities should be empty slice, not nil")
	}
	if len(parsed.Capabilities) != 0 {
		t.Fatalf("Capabilities: expected 0, got %d", len(parsed.Capabilities))
	}
}

func TestParseAIC_NoExt(t *testing.T) {
	parsed, err := ParseAIC(&x509.Certificate{})
	if err != nil {
		t.Fatalf("ParseAIC on empty cert: %v", err)
	}
	if parsed != nil {
		t.Fatal("expected nil for cert without AIC extension")
	}
}

func TestParseAIC_Malformed(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDAIC,
		Value: []byte{0xff, 0xfe, 0xfd},
	}
	_, err := ParseAIC(certFromExt(ext))
	if err == nil {
		t.Fatal("expected error for malformed AIC extension")
	}
}

func TestParseAIC_MultipleExtensions(t *testing.T) {
	cfg := AICConfig{
		AgentId:                 "agent-multi",
		PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: testAICKeyHash()},
		Capabilities:            []Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}},
		DelegationAuthorization: testAICDelegation(),
	}
	ext, _ := BuildAIC(cfg)

	otherExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte{0x05},
	}

	cert := &x509.Certificate{
		Extensions: []pkix.Extension{otherExt, ext},
	}
	parsed, err := ParseAIC(cert)
	if err != nil {
		t.Fatalf("ParseAIC: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed AIC")
	}
	if parsed.AgentId != "agent-multi" {
		t.Fatalf("AgentId: expected agent-multi, got %s", parsed.AgentId)
	}
}

func TestAICCheckPermission_Found(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "http", CapabilityId: "gateway:read"},
		},
	}
	ok, err := aic.CheckPermission("gateway:admin")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !ok {
		t.Fatal("expected true for gateway:admin")
	}
}

func TestAICCheckPermission_NotFound(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
		},
	}
	ok, err := aic.CheckPermission("gateway:admin")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if ok {
		t.Fatal("expected false for gateway:admin (not in capabilities)")
	}
}

func TestAICCheckPermission_NilExtension(t *testing.T) {
	var aic *AIC
	_, err := aic.CheckPermission("gateway:admin")
	if err == nil {
		t.Fatal("expected error for nil AIC extension")
	}
}

func TestAICCheckPermission_NoCapabilities(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{},
	}
	_, err := aic.CheckPermission("gateway:admin")
	if err == nil {
		t.Fatal("expected error for no capabilities")
	}
}

func TestAICPrincipal_Nil(t *testing.T) {
	var aic *AIC
	if p := aic.Principal(); p != "" {
		t.Fatalf("Principal on nil: expected empty, got %s", p)
	}
}

func TestAICPrincipal_Valid(t *testing.T) {
	aic := &AIC{PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "admin@varwof.com"}}
	if p := aic.Principal(); p != "varwof:admin@varwof.com:" {
		t.Fatalf("Principal: expected varwof:admin@varwof.com:, got %s", p)
	}
}

func TestAICHasProtocol_Found(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:admin"},
			{SchemeId: "varwof-tsa-v1", CapabilityId: "tsa:sign"},
		},
	}
	if !aic.HasProtocol("varwof-gateway-v1") {
		t.Fatal("HasProtocol: expected true for varwof-gateway-v1")
	}
	if !aic.HasProtocol("varwof-tsa-v1") {
		t.Fatal("HasProtocol: expected true for varwof-tsa-v1")
	}
}

func TestAICHasProtocol_NotFound(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"},
		},
	}
	if aic.HasProtocol("unknown-scheme") {
		t.Fatal("HasProtocol: expected false for unknown scheme")
	}
}

func TestAICHasProtocol_Nil(t *testing.T) {
	var aic *AIC
	if aic.HasProtocol("anything") {
		t.Fatal("HasProtocol on nil: expected false")
	}
}

func TestAICIntersectPermissions_SomeMatch(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "http", CapabilityId: "gateway:ops"},
		},
	}
	userPerms := []string{"gateway:admin", "gateway:read", "gateway:audit"}
	result := aic.IntersectPermissions(userPerms)
	if len(result) != 1 || result[0] != "gateway:admin" {
		t.Fatalf("IntersectPermissions: expected [gateway:admin], got %v", result)
	}
}

func TestAICIntersectPermissions_AllMatch(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "http", CapabilityId: "gateway:ops"},
		},
	}
	userPerms := []string{"gateway:admin", "gateway:ops"}
	result := aic.IntersectPermissions(userPerms)
	if len(result) != 2 {
		t.Fatalf("IntersectPermissions: expected 2, got %d: %v", len(result), result)
	}
}

func TestAICIntersectPermissions_NoneMatch(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
		},
	}
	userPerms := []string{"gateway:read", "gateway:audit"}
	result := aic.IntersectPermissions(userPerms)
	if len(result) != 0 {
		t.Fatalf("IntersectPermissions: expected empty, got %v", result)
	}
}

func TestAICIntersectPermissions_NilAIC(t *testing.T) {
	var aic *AIC
	userPerms := []string{"gateway:admin", "gateway:ops"}
	result := aic.IntersectPermissions(userPerms)
	if len(result) != 2 {
		t.Fatalf("IntersectPermissions on nil: expected original perms, got %v", result)
	}
}

func TestAICIntersectPermissions_EmptyCapabilities(t *testing.T) {
	aic := &AIC{Capabilities: []Capability{}}
	userPerms := []string{"gateway:admin"}
	result := aic.IntersectPermissions(userPerms)
	if len(result) != 1 {
		t.Fatalf("IntersectPermissions empty caps: expected original perms, got %v", result)
	}
}

func TestCapabilityStruct(t *testing.T) {
	cap := Capability{
		SchemeId:     "test-scheme",
		CapabilityId: "test-capability",
		Parameters:   []byte{0x01, 0x02},
	}
	val, err := asn1.Marshal(cap)
	if err != nil {
		t.Fatalf("Marshal Capability: %v", err)
	}
	var parsed Capability
	_, err = asn1.Unmarshal(val, &parsed)
	if err != nil {
		t.Fatalf("Unmarshal Capability: %v", err)
	}
	if parsed.SchemeId != "test-scheme" {
		t.Fatalf("SchemeId: got %s", parsed.SchemeId)
	}
	if parsed.CapabilityId != "test-capability" {
		t.Fatalf("CapabilityId: got %s", parsed.CapabilityId)
	}
	if len(parsed.Parameters) != 2 || parsed.Parameters[0] != 0x01 {
		t.Fatalf("Parameters: got %v", parsed.Parameters)
	}
}

func TestBuildAIC_CapabilityOverflow(t *testing.T) {
	caps := make([]Capability, 257)
	for i := range caps {
		caps[i] = Capability{SchemeId: "test", CapabilityId: "cap", Parameters: []byte{0x01}}
	}
	cfg := AICConfig{
		AgentId:                 "agent-over",
		PrincipalUid:            PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: testAICKeyHash()},
		Capabilities:            caps,
		DelegationAuthorization: testAICDelegation(),
	}
	_, err := BuildAIC(cfg)
	if err == nil || err.Error() != "aic: capabilities exceed max limit (256 entries)" {
		t.Fatalf("expected capability overflow error, got: %v", err)
	}

	// 256 entries should be OK
	okCaps := make([]Capability, 256)
	for i := range okCaps {
		okCaps[i] = Capability{SchemeId: "test", CapabilityId: "cap", Parameters: []byte{0x01}}
	}
	cfg.Capabilities = okCaps
	ext, err := BuildAIC(cfg)
	if err != nil {
		t.Fatalf("expected success for 256 caps, got: %v", err)
	}
	parsed, _ := ParseAIC(certFromExt(ext))
	if parsed == nil || len(parsed.Capabilities) != 256 {
		t.Fatalf("expected 256 capabilities roundtrip, got %d", len(parsed.Capabilities))
	}
}

func certFromExt(ext pkix.Extension) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Extensions:   []pkix.Extension{ext},
	}
}

// testAICKeyHash returns a 32-byte keyHash (SHA-256 length).
func testAICKeyHash() []byte {
	return make([]byte, 32)
}

// testAICDelegation returns a valid DelegationAuthorization with all required fields (v1.7.1).
func testAICDelegation() *DelegationAuthorization {
	return &DelegationAuthorization{
		Reason:             Reason{ReasonCode: "ROTATION", Description: "test AIC delegation"},
		SignatureValue:     []byte{0xde, 0xad, 0xbe, 0xef},
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		Timestamp:          time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
		Nonce:              make([]byte, 32),
		RequestedLifetime:  3600,
	}
}

// testPrincipalUID constructs a PrincipalUid in wire format consistent with testAICKeyHash.
func testPrincipalUID(realm, identifier string) string {
	return PrincipalUid{Version: 1, Realm: realm, Identifier: identifier, KeyHash: testAICKeyHash()}.String()
}

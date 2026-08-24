// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func ed25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// ─── ExtractTrustAnchorFields ────────────────────────────────────

func TestExtractTrustAnchorFields_CoverageBoost(t *testing.T) {
	key, _ := rsa.GenerateKey(nil, 2048)
	template := &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"TestOrg"}, CommonName: "TA"},
		PublicKey: &key.PublicKey,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	o, c, keyAlgo, keySize, sha1fp, pathLen := ExtractTrustAnchorFields(cert)
	if o != "TestOrg" {
		t.Fatalf("expected TestOrg, got %s", o)
	}
	if c != "" {
		t.Fatalf("expected empty country, got %s", c)
	}
	if keyAlgo != "RSA" || keySize != 2048 {
		t.Fatalf("expected RSA/2048, got %s/%d", keyAlgo, keySize)
	}
	if sha1fp == "" {
		t.Fatal("expected non-empty sha1 fingerprint")
	}
	// MaxPathLen zero, MaxPathLenZero false → pathLen == -1
	if pathLen != -1 {
		t.Fatalf("expected -1, got %d", pathLen)
	}
}

func TestExtractTrustAnchorFields_PathLen(t *testing.T) {
	key, _ := rsa.GenerateKey(nil, 2048)
	template := &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Org"}},
		PublicKey:             &key.PublicKey,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	_, _, _, _, _, pathLen := ExtractTrustAnchorFields(cert)
	if pathLen != 2 {
		t.Fatalf("expected 2, got %d", pathLen)
	}
}

func TestExtractTrustAnchorFields_ZeroPathLen(t *testing.T) {
	key, _ := rsa.GenerateKey(nil, 2048)
	template := &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Org"}},
		PublicKey:             &key.PublicKey,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	_, _, _, _, _, pathLen := ExtractTrustAnchorFields(cert)
	if pathLen != 0 {
		t.Fatalf("expected 0, got %d", pathLen)
	}
}

// ─── pubKeyInfo variants ─────────────────────────────────────────

func TestPubKeyInfo_Ed25519(t *testing.T) {
	pub, _, _ := ed25519Key()
	algo, size := pubKeyInfo(pub)
	if algo != "Ed25519" || size != 256 {
		t.Fatalf("expected Ed25519/256, got %s/%d", algo, size)
	}
}

func TestPubKeyInfo_Unknown(t *testing.T) {
	algo, size := pubKeyInfo("not-a-key")
	if algo != "Unknown" || size != 0 {
		t.Fatalf("expected Unknown/0, got %s/%d", algo, size)
	}
}

// ─── IsRootCAProfile ─────────────────────────────────────────────

func TestIsRootCAProfile(t *testing.T) {
	if !IsRootCAProfile(ProfileRootCA) {
		t.Fatal("expected true for ProfileRootCA")
	}
	if IsRootCAProfile("anything") {
		t.Fatal("expected false for non-root profile")
	}
}

// ─── PrincipalAuthorization methods ──────────────────────────────

func TestPrincipalAuthorization_GrantIds(t *testing.T) {
	pa := &PrincipalAuthorization{
		Grants: []Capability{
			{CapabilityId: "g1"},
			{CapabilityId: "g2"},
		},
	}
	ids := pa.GrantIds()
	if len(ids) != 2 || ids[0] != "g1" || ids[1] != "g2" {
		t.Fatalf("unexpected: %v", ids)
	}
}

func TestPrincipalAuthorization_GrantIds_Nil(t *testing.T) {
	var pa *PrincipalAuthorization
	if pa.GrantIds() != nil {
		t.Fatal("expected nil")
	}
}

func TestPrincipalAuthorization_AllowsRepresentative(t *testing.T) {
	pa := &PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: int(DelegationModeRepresentativeAllowed)},
	}
	if !pa.AllowsRepresentative() {
		t.Fatal("expected true")
	}
	pa.DelegationPolicy.AllowedMode = int(DelegationModeAuthorizedOnly)
	if pa.AllowsRepresentative() {
		t.Fatal("expected false")
	}
}

func TestPrincipalAuthorization_AllowsRepresentative_Nil(t *testing.T) {
	var pa *PrincipalAuthorization
	if pa.AllowsRepresentative() {
		t.Fatal("expected false")
	}
}

func TestPrincipalAuthorization_PermIds(t *testing.T) {
	pa := &PrincipalAuthorization{
		Grants: []Capability{{CapabilityId: "x1"}},
	}
	ids := pa.PermIds()
	if len(ids) != 1 || ids[0] != "x1" {
		t.Fatalf("unexpected: %v", ids)
	}
}

// ─── BuildPrincipalAuthorizationExtension roundtrip ──────────────

func TestBuildPrincipalAuthorizationExtension_Roundtrip(t *testing.T) {
	cfg := PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "s", CapabilityId: "c1"}},
		DelegationPolicy: &DelegationPolicy{
			MaxAgents:       3,
			AllowedMode:     int(DelegationModeRepresentativeAllowed),
			MaxSessionHours: 24,
		},
	}
	ext, err := BuildPrincipalAuthorizationExtension(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pa, err := ParsePrincipalAuthorizationExtension([]pkix.Extension{ext})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pa.Grants) != 1 || pa.Grants[0].CapabilityId != "c1" {
		t.Fatalf("unexpected grants: %v", pa.Grants)
	}
	if pa.DelegationPolicy.MaxAgents != 3 {
		t.Fatalf("unexpected maxAgents: %d", pa.DelegationPolicy.MaxAgents)
	}
	if pa.DelegationPolicy.AllowedMode != int(DelegationModeRepresentativeAllowed) {
		t.Fatal("unexpected allowedMode")
	}
}

func TestParsePrincipalAuthorizationExtension_NotFound(t *testing.T) {
	pa, err := ParsePrincipalAuthorizationExtension([]pkix.Extension{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pa != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestBuildPrincipalAuthorizationExtension_Empty(t *testing.T) {
	ext, err := BuildPrincipalAuthorizationExtension(PrincipalAuthorizationConfig{})
	if err != nil {
		t.Fatalf("build empty: %v", err)
	}
	if ext.Critical {
		t.Fatal("expected non-critical (Varwof private extension must not break standard TLS verification)")
	}
}

// ─── JobQueue ────────────────────────────────────────────────────

type mockProcessor struct {
	called int
}

func (m *mockProcessor) Process(items []JobRequestItem) []JobResultItem {
	m.called++
	results := make([]JobResultItem, len(items))
	for i, item := range items {
		results[i] = JobResultItem{CN: item.CN, Status: "ok", Serial: "abc123"}
	}
	return results
}

func TestJobQueue_SubmitAndGet(t *testing.T) {
	proc := &mockProcessor{}
	q := NewJobQueue(2, 5*time.Minute, proc)
	defer q.Close()

	items := []JobRequestItem{
		{CN: "test1.example.com", Profile: "server"},
		{CN: "test2.example.com", Profile: "server"},
	}
	id := q.Submit(items)
	if id == "" {
		t.Fatal("expected non-empty job ID")
	}

	// Wait briefly for processing
	time.Sleep(100 * time.Millisecond)

	job := q.GetJob(id)
	if job == nil {
		t.Fatal("expected non-nil job")
	}
	if job.ID != id {
		t.Fatalf("expected ID %s, got %s", id, job.ID)
	}
	if job.Total != 2 {
		t.Fatalf("expected total 2, got %d", job.Total)
	}
}

func TestJobQueue_GetJob_NotFound(t *testing.T) {
	proc := &mockProcessor{}
	q := NewJobQueue(1, time.Minute, proc)
	defer q.Close()

	if q.GetJob("nonexistent") != nil {
		t.Fatal("expected nil")
	}
}

func TestJobQueue_DefaultWorkers(t *testing.T) {
	proc := &mockProcessor{}
	q := NewJobQueue(0, 0, proc) // defaults: 4 workers, 5min TTL
	defer q.Close()

	if q.workers != 4 {
		t.Fatalf("expected 4 workers, got %d", q.workers)
	}
	if q.ttl != 5*time.Minute {
		t.Fatalf("expected 5min ttl, got %v", q.ttl)
	}
}

func TestJobQueue_NextID_Unique(t *testing.T) {
	proc := &mockProcessor{}
	q := NewJobQueue(1, time.Minute, proc)
	defer q.Close()

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := q.nextID()
		if ids[id] {
			t.Fatalf("duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

func TestJobQueue_ProcessorError(t *testing.T) {
	errProc := &errProcessor{}
	q := NewJobQueue(1, time.Minute, errProc)
	defer q.Close()

	id := q.Submit([]JobRequestItem{{CN: "fail.test"}})
	time.Sleep(100 * time.Millisecond)

	job := q.GetJob(id)
	if job == nil {
		t.Fatal("expected non-nil job")
	}
	if job.Status != JobFailed {
		t.Fatalf("expected failed status, got %s", job.Status)
	}
}

type errProcessor struct{}

func (e *errProcessor) Process(items []JobRequestItem) []JobResultItem {
	return []JobResultItem{{CN: "fail", Status: "error", Error: "boom"}}
}

// ─── bytesHex/formatSANs/subjectFirst ────────────────────────────

func TestBytesHex(t *testing.T) {
	if bytesHex(nil) != "" {
		t.Fatal("expected empty for nil")
	}
	if bytesHex([]byte{0xab, 0xcd}) != "abcd" {
		t.Fatal("expected abcd")
	}
}

func TestSubjectFirst(t *testing.T) {
	if subjectFirst([]string{"a", "b"}) != "a" {
		t.Fatal("expected a")
	}
	if subjectFirst(nil) != "" {
		t.Fatal("expected empty")
	}
}

func TestFormatSANs_Empty(t *testing.T) {
	cert := &x509.Certificate{}
	if formatSANs(cert) != "" {
		t.Fatal("expected empty")
	}
}

func TestFormatSANs_Full(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"a.example.com"},
		EmailAddresses: []string{"a@x.com"},
	}
	s := formatSANs(cert)
	if !containsStr(s, "DNS:a.example.com") || !containsStr(s, "email:a@x.com") {
		t.Fatalf("unexpected: %s", s)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── ASN.1 marshal + validation for PrincipalAuthorization ──────────────

func TestBuildPrincipalAuthorizationExtension_MarshalRoundtrip(t *testing.T) {
	// Empty schemeId → validatePA rejects (P1-A-24).
	if _, err := BuildPrincipalAuthorizationExtension(PrincipalAuthorizationConfig{
		Grants: []Capability{{SchemeId: "", CapabilityId: ""}},
	}); err == nil {
		t.Fatal("empty schemeId should be rejected by validatePA")
	}
	// Valid grants → roundtrip succeeds.
	cfg := PrincipalAuthorizationConfig{
		Grants: []Capability{
			{SchemeId: "gateway", CapabilityId: "mysql:query"},
			{SchemeId: "gateway", CapabilityId: "redis:get"},
		},
	}
	ext, err := BuildPrincipalAuthorizationExtension(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Verify OID
	if !ext.Id.Equal(OIDPrincipalAuthorization) {
		t.Fatal("unexpected OID")
	}
	// Unmarshal directly
	var pa PrincipalAuthorization
	if _, err := asn1.Unmarshal(ext.Value, &pa); err != nil {
		t.Fatalf("direct unmarshal: %v", err)
	}
	if len(pa.Grants) != 2 || pa.Grants[1].CapabilityId != "redis:get" {
		t.Fatalf("unexpected grants: %+v", pa.Grants)
	}
	// validatePA upper limit 256 (P1-A-24).
	tooMany := make([]Capability, MaxGrantEntries+1)
	for i := range tooMany {
		tooMany[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	if err := validatePA(tooMany); err == nil {
		t.Fatal("grants > MaxGrantEntries should error")
	}
}

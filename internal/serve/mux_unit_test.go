// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/capregistry"
	"github.com/varwof/engine/db"
)

// TestGetCertStatus_EngineAndFallback verifies the status lookup prefers the
// memory engine when it has the record and falls back to the DB on a miss.
func TestGetCertStatus_EngineAndFallback(t *testing.T) {
	srv, _, _ := newTestServerWithEngine(t)
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}
	serial := "A10000000000000000000000000000000000001"
	if err := e.IssueCert(&db.CertRecord{
		SerialNumber: serial,
		CAName:       "test-ca",
		Status:       "V",
		CommonName:   "eng.example.com",
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		CertDER:      []byte("cert"),
	}); err != nil {
		t.Fatal(err)
	}
	st, err := srv.getCertStatus("test-ca", serial)
	if err != nil || st.Status != "V" {
		t.Fatalf("engine path: status=%+v err=%v", st, err)
	}

	srv2, _ := newTestServerWithDB(t)
	d := srv2.getDB()
	installAICCertRecord(t, d, "test-ca", "B10000000000000000000000000000000000001", "fallback@example.com")
	st, err = srv2.getCertStatus("test-ca", "B10000000000000000000000000000000000001")
	if err != nil || st.Status != "V" {
		t.Fatalf("db path: status=%+v err=%v", st, err)
	}
}

// TestLoadRouteRules_Branches covers the four loadRouteRules outcomes:
// embedded default, file load, fail-closed keep-previous on reload, and the
// startup panic when a configured file is unreadable with no prior rules.
func TestLoadRouteRules_Branches(t *testing.T) {
	dir := t.TempDir()

	s := &Server{}
	cfg := &internal.Config{}
	s.loadRouteRules(cfg)
	if s.getRouteRules() == nil {
		t.Fatal("embedded default route rules not installed")
	}

	valid := filepath.Join(dir, "routes.json")
	os.WriteFile(valid, []byte(`{"version":"1","rules":[{"method":"GET","path":"/healthz","permission":"public"}]}`), 0o644)
	cfg2 := &internal.Config{RoutesFile: valid}
	s2 := &Server{}
	s2.loadRouteRules(cfg2)
	if rr := s2.getRouteRules(); rr == nil || rr.Match("GET", "/healthz") == nil {
		t.Fatal("rules file not applied")
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{{{`), 0o644)
	cfg3 := &internal.Config{RoutesFile: bad}
	prev := s.getRouteRules()
	s.loadRouteRules(cfg3)
	if cur := s.getRouteRules(); cur != prev {
		t.Fatal("invalid reload must keep the previously working rules")
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("unreadable routes_file without prior rules must panic fail-closed")
			}
		}()
		s3 := &Server{}
		s3.loadRouteRules(cfg3)
	}()
}

// TestLoginThrottle covers the lockout lifecycle, the TTL sweep and the
// maxLoginAttemptEntries memory cap.
func TestLoginThrottleSweepAndCap(t *testing.T) {
	s := &Server{}

	for i := 0; i < maxLoginFailures; i++ {
		s.recordLoginFailure("alice")
	}
	if !s.loginThrottled("alice") {
		t.Fatal("expected lockout after maxLoginFailures")
	}
	s.resetLoginThrottle("alice")
	if s.loginThrottled("alice") {
		t.Fatal("expected throttle reset after successful login")
	}
	if s.loginThrottled("unknown") {
		t.Fatal("unknown user must not be throttled")
	}

	s.loginAttempts = map[string]loginAttempt{
		"old": {lastSeen: time.Now().Add(-2 * loginAttemptTTL)},
	}
	s.recordLoginFailure("bob")
	if _, ok := s.loginAttempts["old"]; ok {
		t.Fatal("stale attempt not purged by TTL sweep")
	}

	big := make(map[string]loginAttempt, maxLoginAttemptEntries+2)
	for i := 0; i < maxLoginAttemptEntries+2; i++ {
		big["u"+strconv.Itoa(i)] = loginAttempt{lastSeen: time.Now()}
	}
	s.loginAttempts = big
	s.recordLoginFailure("sweeper")
	if len(s.loginAttempts) > maxLoginAttemptEntries {
		t.Fatalf("attempt map exceeded cap: %d", len(s.loginAttempts))
	}
}

// TestGetCertBySPKIHashFallback drives the SPKI-hash lookup through the
// engine-miss path so it falls back to the DB (both stores empty here, which
// still exercises the ErrNotFound fallback).
func TestGetCertBySPKIHashFallback(t *testing.T) {
	srv, _, _ := newTestServerWithEngine(t)
	if srv.getEngine() == nil {
		t.Fatal("engine not enabled")
	}
	recs, err := srv.getCertBySPKIHash("ffffff0000000000000000000000000000000000", "test-ca", "active")
	if err != nil {
		t.Fatalf("engine miss must fall back to DB without error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no records on empty stores, got %d", len(recs))
	}
}

// TestCapRegistryNilAndValidation covers SetCapRegistry/CapRegistry plumbing
// and the validateCapabilities no-op behavior: a missing or not-yet-loaded
// registry must not block issuance.
func TestCapRegistryNilAndValidation(t *testing.T) {
	s := &Server{}
	if s.CapRegistry() != nil {
		t.Fatal("fresh server must have no capability registry")
	}
	if err := s.validateCapabilities(nil); err != nil {
		t.Fatal(err)
	}
	s.SetCapRegistry(capregistry.New())
	if s.CapRegistry() == nil {
		t.Fatal("registry not stored")
	}
	if err := s.validateCapabilities([]string{"cert:issue"}); err != nil {
		t.Fatal(err)
	}
}

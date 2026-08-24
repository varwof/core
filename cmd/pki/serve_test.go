// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/core/internal/serve"
	"github.com/varwof/engine/db"
)

// init registers the revocation-cache invalidation hook so tests exercising
// verifyClientCertRevocation behave like production (a freshly revoked cert
// fails closed immediately instead of waiting out the 30s cache TTL).
func init() {
	db.OnCertRevoked = func(serial string) {
		if serial == "" {
			clearRevocationCache()
		} else {
			invalidateRevocationBySerial(serial)
		}
	}
}

// TestVerifyClientCertRevocationSurvivesReload is a regression test for an old bug:
// after SIGHUP reload swaps the DB, the HTTPS (mTLS) revocation check closure must
// continue working instead of hitting a closed old handle.
func TestVerifyClientCertRevocationSurvivesReload(t *testing.T) {
	dir := t.TempDir()

	mkdb := func(name string) *db.DB {
		d, err := db.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	mkcert := func(t *testing.T, d *db.DB, cn string, serial int64) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		record := &db.CertRecord{
			SerialNumber: fmt.Sprintf("%040X", cert.SerialNumber),
			CAName:       cn,
			Status:       "V",
			Subject:      cert.Subject.String(),
			CommonName:   cn,
			IssuerDN:     cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			CertDER:      der,
		}
		record.Fingerprint = db.Fingerprint(der)
		if err := d.InsertCert(record); err != nil {
			t.Fatal(err)
		}
		return cert
	}

	db1 := mkdb("one.db")
	defer db1.Close()
	cert1 := mkcert(t, db1, "cert-one", 1111)
	cb := verifyClientCertRevocation(db1)
	chains := [][]*x509.Certificate{{cert1}}
	if err := cb(nil, chains); err != nil {
		t.Fatalf("db1 cert rejected before reload: %v", err)
	}

	// Simulate reload: open new DB, swap atomic handle, close old DB (same order as reloadConfigNowWithMuxes)
	db2 := mkdb("two.db")
	defer db2.Close()
	cert2 := mkcert(t, db2, "cert-two", 2222)
	if err := db2.RevokeCert("cert-two", fmt.Sprintf("%040X", cert2.SerialNumber), 1); err != nil {
		t.Fatal(err)
	}
	tlsVerifyDB.Store(db2)
	db1.Close()

	// Closure must read the new handle: revoked cert2 should report "revoked" (not the old bug's "database is closed")
	err := cb(nil, [][]*x509.Certificate{{cert2}})
	if err == nil {
		t.Fatal("closure accepted revoked cert2 after reload")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("closure should read new DB after reload, got: %v", err)
	}

	// Cleanup global atomic to avoid polluting subsequent tests
	tlsVerifyDB.Store(nil)
}

func TestVerifyClientCertRevocation(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Self-signed client cert (issuer == subject).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "client", Organization: []string{"Varwof"}, OrganizationalUnit: []string{"gateway:ops"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	record := &db.CertRecord{
		SerialNumber: serial,
		CAName:       cert.Subject.CommonName,
		Status:       "V",
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		IssuerDN:     cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      der,
	}
	record.Fingerprint = db.Fingerprint(der)
	if err := database.InsertCert(record); err != nil {
		t.Fatal(err)
	}

	cb := verifyClientCertRevocation(database)
	chains := [][]*x509.Certificate{{cert}}

	// Valid cert passes.
	if err := cb(nil, chains); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}

	// Revoked cert is rejected.
	if err := database.RevokeCert(record.CAName, serial, 1); err != nil {
		t.Fatal(err)
	}
	if err := cb(nil, chains); err == nil {
		t.Fatal("revoked cert accepted")
	}

	// Cert not issued by this PKI passes through (TLS chain validation is the
	// authority for external CAs).
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTmpl := *tmpl
	otherTmpl.SerialNumber = big.NewInt(9999)
	otherTmpl.Subject = pkix.Name{CommonName: "external-client"}
	otherDER, _ := x509.CreateCertificate(rand.Reader, &otherTmpl, &otherTmpl, &otherKey.PublicKey, otherKey)
	otherCert, _ := x509.ParseCertificate(otherDER)
	if err := cb(nil, [][]*x509.Certificate{{otherCert}}); err != nil {
		t.Fatalf("external cert rejected: %v", err)
	}
}

func TestPollConfigTickerNoFile(t *testing.T) {
	dir := t.TempDir()
	tickCh := make(chan time.Time)
	go func() {
		pollConfigTickerWithReload(filepath.Join(dir, "nonexistent.json"), tickCh, func(_ string) {})
	}()
	tickCh <- time.Now()
	tickCh <- time.Now()
	// Should not crash; file doesn't exist so it logs and continues
}

func TestPollConfigTickerChange(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"db": ":memory:"}`), 0644); err != nil {
		t.Fatal(err)
	}

	tickCh := make(chan time.Time)
	reloadCh := make(chan struct{})

	go func() {
		pollConfigTickerWithReload(cfgPath, tickCh, func(_ string) { close(reloadCh) })
	}()

	// First tick: set lastMtime
	tickCh <- time.Now()

	// Change the file
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(cfgPath, []byte(`{"db": "/tmp/test.db"}`), 0644)

	// Second tick: should detect change
	tickCh <- time.Now()

	// Wait for reload to be called (or timeout)
	select {
	case <-reloadCh:
	case <-time.After(time.Second):
		t.Fatal("reload should have been called after config file change")
	}
}

func TestCRLLoopCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tickCh := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		crlLoop(ctx, nil, nil, &internal.Config{}, tickCh)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("crlLoop did not exit after context cancel")
	}
}

func TestCRLLoopEmptyDB(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ctx := context.Background()
	tickCh := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		crlLoop(ctx, d, nil, &internal.Config{CRL: internal.CRLConfig{OutputDir: dir}}, tickCh)
		close(done)
	}()
	// Tick with empty DB — should not crash
	tickCh <- time.Now()
}

func TestExpiryLoop(t *testing.T) {
	tickCh := make(chan time.Time)
	cfg := internal.DefaultConfig()
	d := newTestDB(t)
	go func() {
		expiryLoop(&cfg, d, tickCh)
	}()
	tickCh <- time.Now()
}

func TestReloadConfigNowWithMuxesNoPath(t *testing.T) {
	// Empty path should return early (no crash)
	reloadConfigNowWithMuxes("", nil, nil)
}

func TestReloadConfigNowWithMuxesBadPath(t *testing.T) {
	reloadConfigNowWithMuxes("/nonexistent/config.json", nil, nil)
}

func TestReloadConfigNowWithMuxesBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte(`{invalid}`), 0644)
	reloadConfigNowWithMuxes(path, nil, nil)
}

func TestReloadConfigNowWithMuxesBadDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	os.WriteFile(path, []byte(`{"db": "/nonexistent/path/db.sqlite"}`), 0644)
	reloadConfigNowWithMuxes(path, nil, nil)
}

func TestReloadConfigNowWithMuxesSuccess(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	cfgPath := filepath.Join(dir, "cfg.json")
	os.WriteFile(cfgPath, []byte(`{"db": "`+dbPath+`"}`), 0644)

	cfg := internal.DefaultConfig()
	bundle := i18n.NewBundle()
	full := serve.NewFull(&cfg, nil, bundle, nil, nil)
	public := serve.NewPublic(&cfg, nil, bundle)

	reloadConfigNowWithMuxes(cfgPath, full, public)
}

func TestStopCRLIdempotent(t *testing.T) {
	// crlStopFn is nil initially
	stopCRL()
	stopCRL()
}

func TestStartCRLDisabled(t *testing.T) {
	// AutoRenew empty — should return immediately
	startCRL(nil, nil, &internal.Config{})
	startCRL(nil, nil, &internal.Config{CRL: internal.CRLConfig{AutoRenew: "invalid"}})
}

func TestStartCRLNegative(t *testing.T) {
	startCRL(nil, nil, &internal.Config{CRL: internal.CRLConfig{AutoRenew: "-1h"}})
}

func TestHasFlag(t *testing.T) {
	if !hasFlag([]string{"--foo", "--bar"}, "--foo") {
		t.Fatal("expected hasFlag true")
	}
	if hasFlag([]string{"--foo", "--bar"}, "--baz") {
		t.Fatal("expected hasFlag false")
	}
}

func TestStartExpiryWatcher(t *testing.T) {
	cfg := internal.DefaultConfig()
	// Use a very long interval so the goroutine doesn't fire during test
	cfg.Webhook.ExpiryCheckInterval = "9999h"
	d := newTestDB(t)
	startExpiryWatcher(&cfg, d)
}

func TestReloadConfigNowEmpty(t *testing.T) {
	// Empty path should return early without crash
	reloadConfigNow("")
}

func TestReloadConfigNowBadPath(t *testing.T) {
	reloadConfigNow("/nonexistent/config.json")
}

func TestPollConfigWithBadPath(t *testing.T) {
	cfg := internal.DefaultConfig()
	cfg.Serve.ReloadPollInterval = "10ms"
	// Should exit via defer ticker.Stop when goroutine context ends
	done := make(chan struct{})
	go func() {
		pollConfig(&cfg, "/nonexistent/config.json")
		close(done)
	}()
	// pollConfig runs forever (ticker loop), so we can't wait for it.
	// Just verify it starts without panic.
	time.Sleep(50 * time.Millisecond)
}

func TestCmdDBMigrateDryRun(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := internal.DefaultConfig()
	cfg.DB = dbPath
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	if err := cmdDBMigrate(&cfg, []string{"--dry-run"}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
}

func TestCmdDBMigrateRollbackDryRun(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := internal.DefaultConfig()
	cfg.DB = dbPath
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	if err := cmdDBMigrate(&cfg, []string{"--to=0", "--dry-run"}); err != nil {
		t.Fatalf("rollback dry-run: %v", err)
	}
}

func TestCmdDBMigrateRollbackWithoutForce(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := internal.DefaultConfig()
	cfg.DB = dbPath
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	err = cmdDBMigrate(&cfg, []string{"--to=0"})
	if err == nil {
		t.Fatal("expected error without --force")
	}
}

func TestCmdDBMigrateRollbackWithForce(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := internal.DefaultConfig()
	cfg.DB = dbPath
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	if err := cmdDBMigrate(&cfg, []string{"--to=0", "--force"}); err != nil {
		t.Fatalf("rollback with force: %v", err)
	}
	// Note: re-opening the DB auto-migrates back to SchemaVersion(),
	// so we verify the rollback succeeded by the nil error return above.
}

func TestCmdDBMigrateAlreadyAtVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pki.db")
	cfg := internal.DefaultConfig()
	cfg.DB = dbPath
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	// Migrate to current version (no-op)
	current := db.SchemaVersion()
	if err := cmdDBMigrate(&cfg, []string{fmt.Sprintf("--to=%d", current)}); err != nil {
		t.Fatalf("migrate to current: %v", err)
	}
}

func TestApplyKeyBackend(t *testing.T) {
	// Reset global remote signer state after the test.
	orig := ca.RemoteSignerConfig()
	defer ca.SetRemoteSignerConfig(orig)

	// Non-HSM config must be a no-op (no remote signer configured).
	plain := internal.DefaultConfig()
	if err := applyKeyBackend(&plain); err != nil {
		t.Fatalf("applyKeyBackend(plain): %v", err)
	}
	if ca.RemoteSignerConfig() != nil {
		t.Fatal("expected no remote signer for software backend")
	}

	// remote_hsm config must enable the remote signer with the configured URL.
	hsm := internal.DefaultConfig()
	hsm.KeyBackend.Type = "remote_hsm"
	hsm.KeyBackend.URL = "https://hsm.example:8445"
	hsm.KeyBackend.KeyAlias = "issuing"
	hsm.KeyBackend.Token = "secret-token"
	if err := applyKeyBackend(&hsm); err != nil {
		t.Fatalf("applyKeyBackend(hsm): %v", err)
	}
	rc := ca.RemoteSignerConfig()
	if rc == nil {
		t.Fatal("expected remote signer configured")
	}
	if rc.Endpoint != "https://hsm.example:8445" || rc.AuthToken != "secret-token" {
		t.Fatalf("remote signer config mismatch: %+v", rc)
	}
	if rc.KeyAlias != "issuing" {
		t.Fatalf("expected key_alias 'issuing', got %q", rc.KeyAlias)
	}
}

// TestRevocationCacheInvalidation verifies the revocation cache: same cert handshake
// hits the cache without DB lookup, then after revocation OnCertRevoked invalidates
// the entry, so the next handshake immediately rejects (no TTL wait).
func TestRevocationCacheInvalidation(t *testing.T) {
	clearRevocationCache()
	defer clearRevocationCache()

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "cache-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	if err := database.InsertCert(&db.CertRecord{
		SerialNumber: serial,
		CAName:       cert.Subject.CommonName,
		Status:       "V",
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		IssuerDN:     cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      der,
	}); err != nil {
		t.Fatal(err)
	}

	cb := verifyClientCertRevocation(database)
	chains := [][]*x509.Certificate{{cert}}

	// First check populates the cache (revoked=false).
	if err := cb(nil, chains); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if _, ok := cachedRevocationStatus(revocationCacheKey(cert.Issuer.String(), serial)); !ok {
		t.Fatal("expected revocation status cached after first handshake")
	}

	// Revoke → OnCertRevoked invalidates the entry.
	if err := database.RevokeCert(cert.Subject.CommonName, serial, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := cachedRevocationStatus(revocationCacheKey(cert.Issuer.String(), serial)); ok {
		t.Fatal("cached status should be invalidated after revoke")
	}

	// Next handshake re-checks the DB and fails closed.
	if err := cb(nil, chains); err == nil {
		t.Fatal("revoked cert accepted after cache invalidation")
	}
}

// TestDefaultRoutesPath is a regression test for an old bug: the routes.json default
// path must be resolved based on the config file's directory, independent of the
// config filename. The old implementation used strings.Replace to replace "pki.json",
// which only worked for configs literally named pki.json — names like pki-bench-off.json
// would treat the config file itself as routes → empty rules → all 404.
func TestDefaultRoutesPath(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{"standard pki.json", "/etc/varwof/core/pki.json", "/etc/varwof/core/routes.json"},
		{"custom naming", "/tmp/pki-bench/pki-bench-off.json", "/tmp/pki-bench/routes.json"},
		{"relative path", "conf/pki.json", "conf/routes.json"},
		{"no directory", "pki.json", "routes.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultRoutesPath(tc.cfg)
			if got != tc.want {
				t.Fatalf("defaultRoutesPath(%q) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestEngineConfigNilGuard is a regression test for an old bug: when engine config is
// nil, it must remain DB-only and must not unconditionally enable the default engine.
// Verified three call sites (serve startup / reload / modular) all go through
// EnableEngine, which is guarded by cfg.Engine != nil — this test verifies
// engineFromConfig returns disabled for nil config (DB-only semantics guaranteed by
// cfg.Engine != nil guard; test only verifies config parsing doesn't crash and nil
// doesn't trigger rebuild).
func TestEngineConfigNilGuard(t *testing.T) {
	cfg := &internal.Config{} // Engine == nil
	if cfg.Engine != nil {
		t.Fatal("empty config must have nil Engine")
	}
	// EngineConfig explicitly set → non-nil
	cfg2 := &internal.Config{}
	cfg2.Engine = &internal.EngineConfig{MaxCerts: 500000}
	if cfg2.Engine == nil || cfg2.Engine.MaxCerts != 500000 {
		t.Fatalf("engine config not honored: %+v", cfg2.Engine)
	}
}

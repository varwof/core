// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func TestValidateValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected no error for default config: %v", err)
	}
}

func TestValidateBadKeyType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Defaults.KeyType = "rsa-1024"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestValidateBadHash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Defaults.Hash = "md5"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid hash")
	}
}

func TestValidateBadDuration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Webhook.ExpiryCheckInterval = "forever"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
}

func TestValidateCapabilitySchemesDir(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CapabilitySchemes = dir
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected capability_schemes directory to pass validation: %v", err)
	}

	file := dir + "/schemes.json"
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CapabilitySchemes = file
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected capability_schemes file path to be rejected (must be a directory)")
	}
}

func TestValidateLogDest(t *testing.T) {
	for _, dest := range []string{"stderr", "syslog", "file:/var/log/pki.log", ""} {
		cfg := DefaultConfig()
		cfg.Serve.LogDest = dest
		if err := Validate(&cfg); err != nil {
			t.Fatalf("expected no error for log_dest=%q: %v", dest, err)
		}
	}
	for _, bad := range []string{"tcp://1.2.3.4:514", "udp://", "filex", "/var/log/x"} {
		cfg := DefaultConfig()
		cfg.Serve.LogDest = bad
		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected error for log_dest=%q", bad)
		}
	}
}

func TestValidateZeroPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Serve.Addr = ":0"
	err := Validate(&cfg)
	if err != nil {
		t.Fatalf("port 0 should be valid (dynamic port), got: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DB != "/etc/varwof/core/pki.db" {
		t.Fatalf("expected %q, got %q", "/etc/varwof/core/pki.db", cfg.DB)
	}
	if cfg.TSA.Addr != ":8443" {
		t.Fatalf("expected :8443, got %q", cfg.TSA.Addr)
	}
	if cfg.OCSP.Addr != ":8443" {
		t.Fatalf("expected :8443, got %q", cfg.OCSP.Addr)
	}
	if cfg.Defaults.CA != "issuing" {
		t.Fatalf("expected issuing, got %q", cfg.Defaults.CA)
	}
	if cfg.Defaults.Profile != "tls-server" {
		t.Fatalf("expected tls-server, got %q", cfg.Defaults.Profile)
	}
	if _, ok := cfg.CAs["root"]; !ok {
		t.Fatal("missing root CA config")
	}
	if _, ok := cfg.CAs["issuing"]; !ok {
		t.Fatal("missing issuing CA config")
	}
	if _, ok := cfg.CAs["tsa"]; !ok {
		t.Fatal("missing tsa CA config")
	}
}

func TestLoadConfig(t *testing.T) {
	json := `{
		"db": "/tmp/test.db",
		"tsa": { "addr": ":3181" },
		"defaults": { "profile": "codesigning" }
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(json), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB != "/tmp/test.db" {
		t.Fatalf("expected /tmp/test.db, got %q", cfg.DB)
	}
	if cfg.TSA.Addr != ":3181" {
		t.Fatalf("expected :3181, got %q", cfg.TSA.Addr)
	}
	if cfg.Defaults.Profile != "codesigning" {
		t.Fatalf("expected codesigning, got %q", cfg.Defaults.Profile)
	}
}

func TestLoadConfigDefaultsOrgAlias(t *testing.T) {
	// init-full generated configs use legacy key "defaults.org",
	// which must be normalized to DefaultOrg (previously ignored due to JSON tag mismatch).
	json := `{
		"defaults": { "org": "AcmeCorp", "country": "CN" }
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(json), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.DefaultOrg != "AcmeCorp" {
		t.Fatalf("expected defaults.org alias to map to DefaultOrg, got %q", cfg.Defaults.DefaultOrg)
	}
}

func TestMergeConfigDefaultsOrg(t *testing.T) {
	// MergeConfig should also sync the legacy org alias.
	base := DefaultConfig()
	override := &Config{Defaults: DefaultsConfig{Org: "MergedOrg"}}
	merged := MergeConfig(&base, override)
	if merged.Defaults.DefaultOrg != "MergedOrg" {
		t.Fatalf("expected merged DefaultOrg from org alias, got %q", merged.Defaults.DefaultOrg)
	}
}

func TestLoadConfigMissingDefaults(t *testing.T) {
	// Without defaults.org, DefaultOrg remains empty (LoadConfig only parses JSON,
	// built-in defaults are provided by DefaultConfig()).
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"db": "/x.db"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.DefaultOrg != "" {
		t.Fatalf("expected empty DefaultOrg, got %q", cfg.Defaults.DefaultOrg)
	}
}

func TestMergeConfig(t *testing.T) {
	base := DefaultConfig()
	override := &Config{
		DB:  "/custom/db",
		TSA: TSAConfig{Addr: ":3182"},
	}
	merged := MergeConfig(&base, override)
	if merged.DB != "/custom/db" {
		t.Fatalf("expected /custom/db, got %q", merged.DB)
	}
	if merged.TSA.Addr != ":3182" {
		t.Fatalf("expected :3182, got %q", merged.TSA.Addr)
	}
	if merged.OCSP.Addr != ":8443" {
		t.Fatalf("OCSP addr should retain default, got %q", merged.OCSP.Addr)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestMergeConfigNilOverride(t *testing.T) {
	base := DefaultConfig()
	merged := MergeConfig(&base, nil)
	if merged.DB != base.DB {
		t.Fatal("nil override should return base unchanged")
	}
}

func TestMergeConfigAllFields(t *testing.T) {
	base := DefaultConfig()
	override := &Config{
		DB: "/new/db",
		TSA: TSAConfig{
			Addr: ":3183", SignerCert: "/tsa/cert", SignerKey: "/tsa/key", Chain: "/tsa/chain",
		},
		OCSP: OCSPConfig{
			Addr: ":9081", SignerCert: "/ocsp/cert", SignerKey: "/ocsp/key",
			CacheSize: 100, CacheTTL: "5m",
		},
		CAs: map[string]CAConfig{
			"newca": {Cert: "/new/ca.pem", Key: "/new/ca.key", Chain: "/new/chain.pem"},
		},
		Serve: ServeConfig{
			Addr: ":8080", Static: "/static", TLSAddr: ":443", TLSCert: "/cert", TLSKey: "/key",
			ReloadPollInterval: "30s", ShutdownTimeout: "15s",
		},
		Defaults: DefaultsConfig{
			CA: "newca", Profile: "tls-server", KeyType: "RSA-4096", Hash: "SHA-512",
			DefaultCountry: "US", DefaultOrg: "ExampleCorp", CertValidity: "720h",
		},
		CRL: CRLConfig{ValidityDays: 90, OutputDir: "/crl", CRLBaseURL: "http://crl.example.com", AutoRenew: "12h"},
		Webhook: WebhookConfig{
			URL: "http://hook.example.com", Timeout: "5s",
			ExpiryCheckInterval: "12h", ExpiryThresholds: []int{14, 3},
		},
		KeyEscrow: KeyEscrowConfig{AdminPublicKey: "/escrow/key"},
		CTLog:     CTLogConfig{URL: "http://ct.example.com", APIKey: "sk-xxx"},
		RA:        RAConfig{RequiredApprovals: 2, DefaultCA: "raca", DefaultProfile: "ra-prof"},
		RateLimit: RateLimitConfig{Enabled: BoolPtr(true), Rate: 100, Burst: 50},
		LDAP: ca.LDAPConfig{
			URL: "ldap://ldap.example.com", BindDN: "cn=admin", BindPassword: "secret",
			BaseDN: "dc=example", Filter: "(objectClass=person)", UIDAttr: "uid",
			MapCN: "cn", MapOrg: "o", MapOU: "ou", MapL: "l", MapST: "st",
			MapC: "c", MapEmail: "mail",
		},
	}
	merged := MergeConfig(&base, override)
	if merged.DB != "/new/db" {
		t.Fatalf("DB")
	}
	if merged.TSA.Addr != ":3183" || merged.TSA.SignerCert != "/tsa/cert" || merged.TSA.Chain != "/tsa/chain" {
		t.Fatalf("TSA")
	}
	if merged.OCSP.Addr != ":9081" || merged.OCSP.CacheSize != 100 || merged.OCSP.CacheTTL != "5m" {
		t.Fatalf("OCSP")
	}
	if merged.Serve.Addr != ":8080" || merged.Serve.TLSCert != "/cert" || merged.Serve.ReloadPollInterval != "30s" || merged.Serve.ShutdownTimeout != "15s" {
		t.Fatalf("Serve")
	}
	if merged.Defaults.CA != "newca" || merged.Defaults.Hash != "SHA-512" || merged.Defaults.DefaultCountry != "US" || merged.Defaults.DefaultOrg != "ExampleCorp" || merged.Defaults.CertValidity != "720h" {
		t.Fatalf("Defaults")
	}
	if merged.CRL.ValidityDays != 90 || merged.CRL.OutputDir != "/crl" || merged.CRL.AutoRenew != "12h" {
		t.Fatalf("CRL")
	}
	if merged.Webhook.URL != "http://hook.example.com" || merged.Webhook.Timeout != "5s" || merged.Webhook.ExpiryCheckInterval != "12h" || len(merged.Webhook.ExpiryThresholds) != 2 || merged.Webhook.ExpiryThresholds[0] != 14 {
		t.Fatalf("Webhook")
	}
	if merged.KeyEscrow.AdminPublicKey != "/escrow/key" {
		t.Fatalf("KeyEscrow")
	}
	if merged.CTLog.URL != "http://ct.example.com" || merged.CTLog.APIKey != "sk-xxx" {
		t.Fatalf("CTLog")
	}
	if merged.RA.RequiredApprovals != 2 || merged.RA.DefaultCA != "raca" {
		t.Fatalf("RA")
	}
	if !BoolOr(merged.RateLimit.Enabled, false) || merged.RateLimit.Rate != 100 || merged.RateLimit.Burst != 50 {
		t.Fatalf("RateLimit")
	}
	if merged.LDAP.URL != "ldap://ldap.example.com" || merged.LDAP.BindDN != "cn=admin" || merged.LDAP.Filter != "(objectClass=person)" || merged.LDAP.MapCN != "cn" {
		t.Fatalf("LDAP")
	}
	if merged.CAs["newca"].Cert != "/new/ca.pem" || merged.CAs["newca"].Key != "/new/ca.key" {
		t.Fatalf("CAs")
	}
}

func TestMergeConfigDeepFields(t *testing.T) {
	base := DefaultConfig()
	ptr := func(b bool) *bool { return &b }
	intPtr := func(i int) *int { return &i }
	override := &Config{
		TSA: TSAConfig{
			TSAPolicy: "1.2.3", Ordering: ptr(true), AccuracySeconds: 1,
			AccuracyMillis: 2, AccuracyMicros: 3, CoreURL: "http://core", CAName: "tsa-ca",
			ValidityDays: 30, RenewalWindow: "72h", CheckInterval: "6h",
			TLSClientCert: "/c.pem", TLSClientKey: "/c.key", TLSCACert: "/ca.pem",
		},
		OCSP: OCSPConfig{NextUpdate: "24h"},
		Defaults: DefaultsConfig{
			Org: "OrgAlias", OCSPURL: "http://ocsp", IssuerURL: "http://issuer",
			IssuerAltNames: []string{"a", "b"}, SubjectInfoAccess: []string{"x"},
			PolicyOIDs: []string{"1.2.3"}, ReportMaxRows: 500,
		},
		Serve: ServeConfig{
			APIAddr: ":8181", TLSClientCA: "/client.pem", AuthUsername: "u",
			AuthPassword: "p", MetricsEnabled: ptr(true), LogFormat: "json",
			LogDest:            "file:/var/log/pki.log",
			AgentSessionMaxTTL: "24h", TrustedGatewayOUs: []string{"gw", "gw2"},
			AuditSalt: AuditSaltConfig{
				Enabled: ptr(true), RetentionDays: 90, CleanupInterval: "12h",
			},
		},
		CRL: CRLConfig{Addr: ":9082", RenewInterval: "6h", Partitions: 4},
		PolicySigning: PolicySigningConfig{
			Enabled: false, CAFile: "/signer.pem", RequireAdminOU: ptr(true),
			Require: false, SigSuffix: ".signed",
		},
		Policy: "/policy.json", AuthorizationFile: "/authz.json", RoutesFile: "/routes.json",
		Hierarchy: "enterprise",
		PG: db.PGConfig{
			Host: "pg", Port: 5433, User: "u", Password: "p", DBName: "db", SSLMode: "verify", DSN: "dsn",
		},
		RBAC: RBACConfig{
			Enabled: ptr(true), PermissionMode: "enterprise",
			CAScopes: map[string][]string{"a": {"b"}},
		},
		Persist: PersistConfig{
			Mode: "record-buffer", BatchSize: 200, BatchInterval: "500ms",
			QueueSize: 1000, BufferDB: "/tmp/buf.db",
		},
		Aggregator: AggregatorConfig{
			WindowMs: 100, BatchMax: 50, Threshold: 10, BufferSize: 10000,
		},
		RecordBuffer: RecordBufferConfig{
			Disable: true, Threshold: 150, MaxPending: intPtr(5000), MaxLatency: "300ms",
		},
		AutoRenew: AutoRenewConfig{
			Enabled: ptr(true), Interval: "6h", WindowDays: 15,
			DefaultValidity: 360, Profiles: []string{"p"}, ExcludeCAs: []string{"x"},
			NotifyOnly: ptr(false), MaxRenewals: 3,
		},
		Archive: ArchiveConfig{
			Enabled: ptr(true), RetentionDays: 400, ExcludeCAs: []string{"y"},
			ArchiveExpired: ptr(true), ArchiveRevoked: ptr(false),
		},
		TrustBridge: TrustBridgeConfig{Bridges: []TrustBridgePolicy{{IssuerCA: "a", SubjectCA: "b"}}},
		SMTP: SMTPConfig{
			Host: "smtp", Port: 2525, Username: "u", Password: "p", From: "f",
			To: "t", TLS: ptr(true), InsecureSkipVerify: ptr(true), Events: "revoke",
		},
		KeyBackend: KeyBackendConfig{
			Type: "remote_hsm", URL: "http://signer", KeyAlias: "al",
			TLS: struct {
				Cert   string `json:"cert,omitempty"`
				Key    string `json:"key,omitempty"`
				CACert string `json:"ca_cert,omitempty"`
			}{Cert: "/c", Key: "/k", CACert: "/ca"},
			Token: "tok",
		},
		CTLog:   CTLogConfig{Logs: []CTLogEntry{{URL: "http://ct2", APIKey: "k"}}},
		Webhook: WebhookConfig{ExpiryCheckInterval: "6h", ExpiryThresholds: []int{7}},
	}
	merged := MergeConfig(&base, override)
	if merged.TSA.TSAPolicy != "1.2.3" || merged.TSA.ValidityDays != 30 || merged.TSA.CoreURL != "http://core" || merged.TSA.AccuracyMicros != 3 {
		t.Fatalf("TSA deep")
	}
	if merged.OCSP.NextUpdate != "24h" {
		t.Fatalf("OCSP deep")
	}
	if merged.Defaults.DefaultOrg != "OrgAlias" || merged.Defaults.OCSPURL != "http://ocsp" || len(merged.Defaults.IssuerAltNames) != 2 || merged.Defaults.ReportMaxRows != 500 {
		t.Fatalf("Defaults deep")
	}
	if merged.Serve.APIAddr != ":8181" || merged.Serve.MetricsEnabled == nil || !*merged.Serve.MetricsEnabled || merged.Serve.LogFormat != "json" || merged.Serve.LogDest != "file:/var/log/pki.log" || len(merged.Serve.TrustedGatewayOUs) != 2 || merged.Serve.AuditSalt.RetentionDays != 90 {
		t.Fatalf("Serve deep")
	}
	if merged.CRL.RenewInterval != "6h" || merged.CRL.Partitions != 4 {
		t.Fatalf("CRL deep")
	}
	if merged.Policy != "/policy.json" || merged.AuthorizationFile != "/authz.json" || merged.RoutesFile != "/routes.json" || merged.Hierarchy != "enterprise" {
		t.Fatalf("policy paths")
	}
	if merged.PolicySigning.CAFile != "/signer.pem" || merged.PolicySigning.SigSuffix != ".signed" {
		t.Fatalf("PolicySigning")
	}
	if merged.PG.DSN != "dsn" || merged.PG.SSLMode != "verify" {
		t.Fatalf("PG")
	}
	if merged.RBAC.PermissionMode != "enterprise" || merged.RBAC.CAScopes["a"][0] != "b" {
		t.Fatalf("RBAC")
	}
	if merged.Persist.Mode != "record-buffer" || merged.Persist.BufferDB != "/tmp/buf.db" {
		t.Fatalf("Persist")
	}
	if merged.Aggregator.Threshold != 10 || merged.Aggregator.BufferSize != 10000 {
		t.Fatalf("Aggregator")
	}
	if !merged.RecordBuffer.Disable || merged.RecordBuffer.Threshold != 150 || merged.RecordBuffer.MaxLatency != "300ms" {
		t.Fatalf("RecordBuffer")
	}
	if merged.AutoRenew.WindowDays != 15 || merged.AutoRenew.MaxRenewals != 3 || len(merged.AutoRenew.ExcludeCAs) != 1 {
		t.Fatalf("AutoRenew")
	}
	if merged.Archive.RetentionDays != 400 || merged.Archive.ArchiveRevoked == nil || *merged.Archive.ArchiveRevoked {
		t.Fatalf("Archive")
	}
	if len(merged.TrustBridge.Bridges) != 1 {
		t.Fatalf("TrustBridge")
	}
	if merged.SMTP.Host != "smtp" || merged.SMTP.Port != 2525 || merged.SMTP.Events != "revoke" {
		t.Fatalf("SMTP")
	}
	if merged.KeyBackend.Type != "remote_hsm" || merged.KeyBackend.TLS.CACert != "/ca" || merged.KeyBackend.Token != "tok" {
		t.Fatalf("KeyBackend")
	}
	if len(merged.CTLog.Logs) != 1 || merged.CTLog.Logs[0].URL != "http://ct2" {
		t.Fatalf("CTLog.Logs")
	}
	// CAs merge: nil map initialization branch
	if len(merged.CAs) == 0 {
		t.Fatalf("CAs")
	}
}

func TestLoadConfigEmptyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB != "" {
		t.Fatalf("expected empty db, got %q", cfg.DB)
	}
}

func TestLoadConfigBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json}"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Fatal("DefaultConfigPath should not be empty")
	}
	// On Linux, should return /etc/varwof/core/pki.json
	if path != "/etc/varwof/core/pki.json" {
		t.Logf("DefaultConfigPath = %q (platform-specific)", path)
	}
}

func TestSearchConfigPathNotFound(t *testing.T) {
	// No config files in temp directory, should return ""
	path := SearchConfigPath()
	_ = path // Accept any result; we just verify it doesn't panic
}

func TestSearchConfigPathFound(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, "pki.json")
	if err := os.WriteFile(candidate, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	// Temporarily change CWD
	origWd, _ := os.Getwd()
	defer os.Chdir(origWd)
	os.Chdir(dir)

	path := SearchConfigPath()
	if path != "pki.json" {
		t.Fatalf("expected pki.json, got %q", path)
	}
}

func TestMergeConfigBoolOverride(t *testing.T) {
	base := DefaultConfig()

	if BoolOr(base.Archive.ArchiveExpired, false) != true {
		t.Fatal("default archive_expired should be true")
	}
	if BoolOr(base.RateLimit.Enabled, false) != true {
		t.Fatal("default rate_limit.enabled should be true (AUTH-017)")
	}

	// Turn a default-off feature on.
	on := &Config{RateLimit: RateLimitConfig{Enabled: BoolPtr(true)}}
	merged := MergeConfig(&base, on)
	if !BoolOr(merged.RateLimit.Enabled, false) {
		t.Fatal("merge should enable rate_limit")
	}

	// Turn a default-on feature off (the *bool fix; plain bool could not do this).
	off := &Config{Archive: ArchiveConfig{ArchiveExpired: BoolPtr(false)}}
	merged = MergeConfig(&base, off)
	if BoolOr(merged.Archive.ArchiveExpired, true) {
		t.Fatal("merge should disable archive_expired")
	}
	if merged.Archive.RetentionDays != 365 {
		t.Fatal("unrelated archive fields must be preserved")
	}

	// Unrelated bools keep their defaults.
	if BoolOr(merged.RateLimit.Enabled, false) != true {
		t.Fatal("rate_limit.enabled should retain default true (AUTH-017)")
	}
}

func TestMergeConfigBoolRoundTrip(t *testing.T) {
	// A hot-reload PUT round-trips the merged config through JSON; ensure
	// *bool fields survive and remain overrideable.
	base := DefaultConfig()
	merged := MergeConfig(&base, &Config{Archive: ArchiveConfig{ArchiveExpired: BoolPtr(false)}})

	data, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded Config
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	if BoolOr(reloaded.Archive.ArchiveExpired, true) {
		t.Fatal("archive_expired should round-trip as false")
	}

	// Re-merge onto the round-tripped config: can it flip back on?
	again := MergeConfig(&reloaded, &Config{Archive: ArchiveConfig{ArchiveExpired: BoolPtr(true)}})
	if !BoolOr(again.Archive.ArchiveExpired, false) {
		t.Fatal("round-tripped config must still accept an override back to true")
	}
}

func TestBoolOrNil(t *testing.T) {
	if BoolOr(nil, false) != false {
		t.Fatal("nil with default false should return false")
	}
	if BoolOr(nil, true) != true {
		t.Fatal("nil with default true should return true")
	}
	v := BoolPtr(true)
	if BoolOr(v, false) != true {
		t.Fatal("pointer to true should return true")
	}
}

func TestValidatePGConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PG.Port = 70000
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for out-of-range pg.port")
	}
	cfg = DefaultConfig()
	cfg.PG.Port = 5432
	cfg.PG.SSLMode = "bogus"
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for invalid pg.sslmode")
	}
	cfg = DefaultConfig()
	cfg.PG.Port = 5432
	cfg.PG.SSLMode = "verify-full"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid pg config rejected: %v", err)
	}
}

func TestValidateLDAPURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LDAP.URL = "https://ldap.example.com"
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for non-ldap scheme")
	}
	cfg = DefaultConfig()
	cfg.LDAP.URL = "ldaps://ldap.example.com"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid ldaps url rejected: %v", err)
	}
}

func TestValidateNestedNegative(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Persist.BatchSize = -1 },
		func(c *Config) { c.Persist.QueueSize = -1 },
		func(c *Config) { c.Aggregator.WindowMs = -1 },
		func(c *Config) { c.Aggregator.BatchMax = -1 },
		func(c *Config) { c.Aggregator.Threshold = -1 },
		func(c *Config) { c.Aggregator.BufferSize = -1 },
	} {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected error for %T negative value", mutate)
		}
	}
}

func TestValidateListenerConflict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Serve.TLSAddr = cfg.Serve.Addr
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error when serve.addr == serve.tls_addr")
	}

	cfg = DefaultConfig()
	cfg.TSA.Addr = ":9999"
	cfg.OCSP.Addr = ":9999"
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error when explicit modular addrs collide")
	}

	cfg = DefaultConfig()
	cfg.TSA.Addr = ":9998"
	cfg.OCSP.Addr = ":9999"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("distinct modular addrs rejected: %v", err)
	}

	// Default config intentionally shares :8443 across services; must pass.
	cfg = DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

func TestValidateFilePath(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(realFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// User-explicit non-existent path must be rejected.
	cfg := DefaultConfig()
	cfg.Serve.TLSCert = filepath.Join(dir, "missing.pem")
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for non-existent explicit tls_cert")
	}

	// Existing explicit file passes.
	cfg = DefaultConfig()
	cfg.Serve.TLSCert = realFile
	if err := Validate(&cfg); err != nil {
		t.Fatalf("existing explicit tls_cert rejected: %v", err)
	}

	// Default (non-deployed) paths must NOT be rejected.
	cfg = DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("default paths rejected: %v", err)
	}

	// Directory fields reject files and vice versa.
	cfg = DefaultConfig()
	cfg.CRL.OutputDir = realFile
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error when output_dir points at a file")
	}
}

func TestValidateCASpecificPath(t *testing.T) {
	dir := t.TempDir()
	realCert := filepath.Join(dir, "issuing-ca.pem")
	if err := os.WriteFile(realCert, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.CAs["issuing"] = CAConfig{Cert: filepath.Join(dir, "nope.pem"), Key: "/does/not/exist.key"}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for non-existent CA cert")
	}

	cfg = DefaultConfig()
	cfg.CAs["issuing"] = CAConfig{Cert: realCert, Key: "/does/not/exist.key"}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected error for non-existent CA key")
	}

	// remote_hsm delegates key storage to the remote signer; keys are not checked.
	cfg = DefaultConfig()
	cfg.KeyBackend.Type = "remote_hsm"
	cfg.CAs["issuing"] = CAConfig{Cert: realCert, Key: "/does/not/exist.key"}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("remote_hsm CA key should not be validated: %v", err)
	}
}

func TestCTLogConfigAllLogs(t *testing.T) {
	// Only URL
	ct := CTLogConfig{URL: "https://log1.example.com", APIKey: "k1"}
	logs := ct.AllLogs()
	if len(logs) != 1 || logs[0].URL != "https://log1.example.com" || logs[0].APIKey != "k1" {
		t.Fatalf("single: %+v", logs)
	}
	// Only Logs list
	ct = CTLogConfig{Logs: []CTLogEntry{
		{URL: "https://log2.example.com", APIKey: "k2"},
		{URL: "https://log3.example.com"},
	}}
	logs = ct.AllLogs()
	if len(logs) != 2 || logs[0].URL != "https://log2.example.com" || logs[1].APIKey != "" {
		t.Fatalf("list: %+v", logs)
	}
	// URL + Logs merged
	ct = CTLogConfig{URL: "https://log0.example.com", Logs: []CTLogEntry{{URL: "https://log9.example.com"}}}
	logs = ct.AllLogs()
	if len(logs) != 2 || logs[0].URL != "https://log0.example.com" || logs[1].URL != "https://log9.example.com" {
		t.Fatalf("merged: %+v", logs)
	}
	// Empty
	ct = CTLogConfig{}
	logs = ct.AllLogs()
	if len(logs) != 0 {
		t.Fatalf("empty: %+v", logs)
	}
}

func TestParseOID(t *testing.T) {
	oid, err := ParseOID("1.2.3.4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(oid) != 4 || oid[0] != 1 || oid[3] != 4 {
		t.Fatalf("oid: %v", oid)
	}
	// Non-numeric
	if _, err := ParseOID("1.a.3"); err == nil {
		t.Fatal("expected error for non-numeric component")
	}
	// Out of range
	if _, err := ParseOID("1.256.3"); err == nil {
		t.Fatal("expected error for out-of-range component")
	}
	// Negative
	if _, err := ParseOID("1.-2.3"); err == nil {
		t.Fatal("expected error for negative component")
	}
	// Fewer than 2 components
	if _, err := ParseOID("1"); err == nil {
		t.Fatal("expected error for single component")
	}
	if _, err := ParseOID(""); err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestDefaultConfigPathWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only")
	}
	// Set PROGRAMDATA → preferred
	t.Setenv("PROGRAMDATA", "C:\\ProgramData")
	if got := DefaultConfigPath(); got != filepath.Join("C:\\ProgramData", "varwof", "core", "pki.json") {
		t.Fatalf("with programdata: %q", got)
	}
	// Clear PROGRAMDATA → APPDATA
	t.Setenv("PROGRAMDATA", "")
	t.Setenv("APPDATA", "C:\\Users\\x\\AppData\\Roaming")
	if got := DefaultConfigPath(); got != filepath.Join("C:\\Users\\x\\AppData\\Roaming", "varwof", "core", "pki.json") {
		t.Fatalf("with appdata: %q", got)
	}
}

// TestAgentProxyMaxValidityConfig verifies default value and merge of agent_proxy_max_validity.
func TestAgentProxyMaxValidityConfig(t *testing.T) {
	def := DefaultConfig()
	if def.Defaults.AgentProxyMaxValidity != "1h" {
		t.Fatalf("default agent_proxy_max_validity = %q, want 1h", def.Defaults.AgentProxyMaxValidity)
	}
	// merge: override default.
	base := DefaultConfig()
	override := Config{Defaults: DefaultsConfig{AgentProxyMaxValidity: "6h"}}
	merged := MergeConfig(&base, &override)
	if merged.Defaults.AgentProxyMaxValidity != "6h" {
		t.Fatalf("merged agent_proxy_max_validity = %q, want 6h", merged.Defaults.AgentProxyMaxValidity)
	}
	// merge: empty does not override.
	base2 := DefaultConfig()
	merged2 := MergeConfig(&base2, &Config{})
	if merged2.Defaults.AgentProxyMaxValidity != "1h" {
		t.Fatalf("empty override should keep 1h, got %q", merged2.Defaults.AgentProxyMaxValidity)
	}
}

func TestValidateIdentityConfig(t *testing.T) {
	// Valid ldap identity.
	cfg := DefaultConfig()
	cfg.Identity = &ca.IdentitySourceConfig{Type: ca.IdentitySourceLDAP, SourceURL: "http://127.0.0.1:8082"}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected valid identity config: %v", err)
	}
	// Missing source_url → error.
	cfg2 := DefaultConfig()
	cfg2.Identity = &ca.IdentitySourceConfig{Type: ca.IdentitySourceLDAP}
	if err := Validate(&cfg2); err == nil {
		t.Fatal("expected error for missing identity.source_url")
	}
	// Unknown type → error.
	cfg3 := DefaultConfig()
	cfg3.Identity = &ca.IdentitySourceConfig{SourceURL: "http://x", Type: "bogus"}
	if err := Validate(&cfg3); err == nil {
		t.Fatal("expected error for unknown identity.type")
	}
	// oauth without username/password → error.
	cfg4 := DefaultConfig()
	cfg4.Identity = &ca.IdentitySourceConfig{SourceURL: "http://x", Type: ca.IdentitySourceOAuth}
	if err := Validate(&cfg4); err == nil {
		t.Fatal("expected error for oauth missing automation account")
	}
	// oauth with account → ok.
	cfg5 := DefaultConfig()
	cfg5.Identity = &ca.IdentitySourceConfig{SourceURL: "http://x", Type: ca.IdentitySourceOAuth, Username: "svc", Password: "pw"}
	if err := Validate(&cfg5); err != nil {
		t.Fatalf("expected valid oauth identity: %v", err)
	}
	// Negative timeout → error.
	cfg6 := DefaultConfig()
	cfg6.Identity = &ca.IdentitySourceConfig{SourceURL: "http://x", TimeoutSec: -1}
	if err := Validate(&cfg6); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestMergeConfigIdentity(t *testing.T) {
	base := DefaultConfig()
	override := &Config{Identity: &ca.IdentitySourceConfig{
		Type: ca.IdentitySourceLDAP, SourceURL: "http://bridge:8082",
		Source: "ad-main", OUFromGroups: map[string]string{"admin": "gateway:admin"},
	}}
	merged := MergeConfig(&base, override)
	if merged.Identity == nil {
		t.Fatal("identity not merged")
	}
	if merged.Identity.SourceURL != "http://bridge:8082" || merged.Identity.Source != "ad-main" {
		t.Fatalf("identity fields not merged: %+v", merged.Identity)
	}
	if merged.Identity.OUFromGroups["admin"] != "gateway:admin" {
		t.Fatalf("OUFromGroups not merged: %+v", merged.Identity.OUFromGroups)
	}

	// Identity not set on base → created from override.
	base2 := DefaultConfig()
	base2.Identity = nil
	merged2 := MergeConfig(&base2, override)
	if merged2.Identity == nil || merged2.Identity.SourceURL != "http://bridge:8082" {
		t.Fatalf("identity created from override: %+v", merged2.Identity)
	}

	// override nil keeps existing.
	base3 := DefaultConfig()
	base3.Identity = &ca.IdentitySourceConfig{SourceURL: "http://orig"}
	merged3 := MergeConfig(&base3, &Config{})
	if merged3.Identity == nil || merged3.Identity.SourceURL != "http://orig" {
		t.Fatalf("nil override should keep existing: %+v", merged3.Identity)
	}
}

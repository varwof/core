package main

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/capregistry"
	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
	"github.com/varwof/core/internal/ocsp"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/remotesigner"
	"github.com/varwof/core/internal/routing"
	"github.com/varwof/core/internal/secrets"
	"github.com/varwof/core/internal/serve"
	"github.com/varwof/core/internal/tsa"
)

var (
	httpServer   *http.Server
	tlsServer    *http.Server
	fullMux      *serve.Server
	publicMux    *serve.Server
	crlStopFn    func()
	tsaStopFn    func()
	rbStopFn     func()
	engineStopFn func()
	rotationStopFn func()
	currentDB    *db.DB
	// tlsVerifyDB is the DB handle used by the HTTPS (mTLS) server's
	// VerifyPeerCertificate revocation check. It is initialized via
	// verifyClientCertRevocation at Serve startup and updated to a new DB
	// connection on SIGHUP hot-reload, preventing closures from holding a
	// closed old handle (old bug: after reload, mTLS handshake reports
	// "sql: database is closed").
	tlsVerifyDB atomic.Pointer[db.DB]
)

// fullMuxEngine returns the current memory engine of the full mux, or nil when
// disabled or not yet started. Used as a getter for read-side wiring (OCSP).
func fullMuxEngine() *engine.Engine {
	if fullMux == nil {
		return nil
	}
	return fullMux.Engine()
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func cmdServe(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	reload := fs.Bool("reload", false, bundle.T(curLang, "cli.flag_reload"))
	fs.Parse(args)

	// Wire the pluggable key backend (HSM / remote signer) into ca.LoadSigner
	// so both protocol handlers (ACME) and the API signing
	// paths delegate signing to the HSM proxy when configured (G-14).
	if err := applyKeyBackend(cfg); err != nil {
		return err
	}

	switch {
	case hasFlag(args, "--install"):
		return installService()
	case hasFlag(args, "--uninstall"):
		return removeService()
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	if err := startServers(cfg, database); err != nil {
		database.Close()
		return err
	}
	currentDB = database

	setReloadHandler(func() {
		reloadConfigNow(configPath)
	})

	if *reload {
		go pollConfig(cfg, configPath)
	}

	localCfg = cfg
	return serveWait(httpServer, tlsServer)
}

func pollConfig(cfg *internal.Config, cfgPath string) {
	interval := 10 * time.Second
	if cfg.Serve.ReloadPollInterval != "" {
		if d, err := time.ParseDuration(cfg.Serve.ReloadPollInterval); err == nil {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	pollConfigTickerWithReload(cfgPath, ticker.C, reloadConfigNow)
}

func pollConfigTickerWithReload(cfgPath string, tickCh <-chan time.Time, reloadFn func(string)) {
	var lastMtime time.Time
	for range tickCh {
		fi, err := os.Stat(cfgPath)
		if err != nil {
			slog.Debug("reload: stat config", "error", err)
			continue
		}
		mtime := fi.ModTime()
		if !lastMtime.IsZero() && mtime.After(lastMtime) {
			slog.Info("reload: config file changed")
			reloadFn(cfgPath)
		}
		lastMtime = mtime
	}
}

func stopCRL() {
	if crlStopFn != nil {
		crlStopFn()
		crlStopFn = nil
	}
}

// stopRecordBuffer flushes buffered cert records and stops the background
// flusher. No-op when the record buffer was never enabled.
func stopRecordBuffer() {
	if rbStopFn != nil {
		rbStopFn()
		rbStopFn = nil
	}
}

// stopEngine flushes pending engine writes and shuts down the memory engine.
// No-op when the engine was never enabled.
func stopEngine() {
	if engineStopFn != nil {
		engineStopFn()
		engineStopFn = nil
	}
}

// engineSource converts a possibly-nil *engine.Engine into a CRL revoked-
// entries source interface, mapping the typed-nil to a nil interface so
// CRLConfig falls back to the DB when the engine is disabled.
func engineSource(e *engine.Engine) ca.RevokedEntriesSource {
	if e == nil {
		return nil
	}
	return e
}

func startCRL(database *db.DB, revSrc ca.RevokedEntriesSource, cfg *internal.Config) {
	renewStr := cfg.CRL.RenewInterval
	if renewStr == "" {
		renewStr = cfg.CRL.AutoRenew
	}
	if renewStr == "" {
		return
	}
	interval, err := time.ParseDuration(renewStr)
	if err != nil || interval <= 0 {
		return
	}
	// H12 fix: seed the CRL number counter from persisted DB state so RFC 5280
	// §5.2.4 monotonicity holds across restarts. Seed to the maximum of the
	// current unix time (previous behavior) and every CA's last persisted CRL
	// number — the counter must never decrease.
	maxSeed := time.Now().Unix()
	if database != nil {
		if nums, err := database.ListCRLNumbers(); err == nil {
			for _, n := range nums {
				if n > maxSeed {
					maxSeed = n
				}
			}
		} else {
			slog.Warn("crl: failed to read persisted CRL numbers", "error", err)
		}
	}
	ca.SeedCRLNumber(maxSeed)
	ctx, cancel := context.WithCancel(context.Background())
	crlStopFn = cancel
	go crlLoop(ctx, database, revSrc, cfg, time.NewTicker(interval).C)
}

func stopTSARenewal() {
	if tsaStopFn != nil {
		tsaStopFn()
		tsaStopFn = nil
	}
}

// stopCARotationMonitor stops the CA rotation monitor goroutine.
func stopCARotationMonitor() {
	if rotationStopFn != nil {
		rotationStopFn()
		rotationStopFn = nil
	}
}

// auditSaltStopFn cancels the audit-salt retirement goroutine.
var auditSaltStopFn context.CancelFunc

// stopAuditSaltRetirement stops the daily audit-salt purge goroutine.
func stopAuditSaltRetirement() {
	if auditSaltStopFn != nil {
		auditSaltStopFn()
		auditSaltStopFn = nil
	}
}

// auditVerifyStopFn cancels the audit chain verifier goroutine.
var auditVerifyStopFn context.CancelFunc

// stopAuditChainVerifier stops the periodic audit Merkle chain verifier.
func stopAuditChainVerifier() {
	if auditVerifyStopFn != nil {
		auditVerifyStopFn()
		auditVerifyStopFn = nil
	}
}

// startAuditChainVerifier periodically recomputes the audit Merkle hash chain
// (AUTH-016). Any broken link — a row deleted or modified out-of-band — is
// logged with the offending entry ID so tampering is surfaced even when nobody
// runs `pki audit verify` manually. Configured via serve.audit_verify.
func startAuditChainVerifier(database *db.DB, cfg *internal.Config) {
	enabled := cfg.Serve.AuditVerify.Enabled == nil || *cfg.Serve.AuditVerify.Enabled
	if !enabled {
		return
	}
	interval := 24 * time.Hour
	if cfg.Serve.AuditVerify.Interval != "" {
		if d, err := time.ParseDuration(cfg.Serve.AuditVerify.Interval); err == nil && d > 0 {
			interval = d
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	auditVerifyStopFn = cancel
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := database.VerifyAuditChain()
				if err != nil {
					slog.Error("audit_verify: chain integrity check failed", "error", err)
					continue
				}
				slog.Info("audit_verify: chain verified", "entries", n)
			}
		}
	}()
}

// startAuditSaltRetirement periodically purges audit salt rows that are older
// than the configured retention window. Once a day's salt is removed, the
// masked audit identities written with it can no longer be recovered, which
// is what enforces the legal data-minimization guarantee. The Merkle chain
// over the masked values is unaffected.
func startAuditSaltRetirement(database *db.DB, cfg *internal.Config) {
	enabled := cfg.Serve.AuditSalt.Enabled == nil || *cfg.Serve.AuditSalt.Enabled
	if !enabled {
		return
	}
	interval := 24 * time.Hour
	if cfg.Serve.AuditSalt.CleanupInterval != "" {
		if d, err := time.ParseDuration(cfg.Serve.AuditSalt.CleanupInterval); err == nil && d > 0 {
			interval = d
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	auditSaltStopFn = cancel
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := database.RetireExpiredAuditSalts(cfg.Serve.AuditSalt.RetentionDays)
				if err != nil {
					slog.Error("audit_salt: retirement failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("audit_salt: purged expired salts", "count", n, "retention_days", cfg.Serve.AuditSalt.RetentionDays)
				}
			}
		}
	}()
}

func startTSARenewal(cfg *internal.Config, rc *tsa.RuntimeConfig) {
	if cfg.TSA.CoreURL == "" || rc == nil {
		return
	}
	stopCh := make(chan struct{})
	tsaStopFn = func() { close(stopCh) }

	renewCfg := &tsa.RenewalConfig{
		CoreURL:       cfg.TSA.CoreURL,
		CertFile:      cfg.TSA.SignerCert,
		KeyFile:       cfg.TSA.SignerKey,
		CACertFile:    cfg.TSA.TLSCACert,
		CAName:        cfg.TSA.CAName,
		ValidityDays:  cfg.TSA.ValidityDays,
		TLSClientCert: cfg.TSA.TLSClientCert,
		TLSClientKey:  cfg.TSA.TLSClientKey,
	}
	if cfg.TSA.RenewalWindow != "" {
		if d, err := time.ParseDuration(cfg.TSA.RenewalWindow); err == nil {
			renewCfg.RenewalWindow = d
		}
	}
	if cfg.TSA.CheckInterval != "" {
		if d, err := time.ParseDuration(cfg.TSA.CheckInterval); err == nil {
			renewCfg.CheckInterval = d
		}
	}
	go tsa.SignerRenewLoop(rc, renewCfg, stopCh)
}

type crlSignerCache struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
}

func crlLoop(ctx context.Context, database *db.DB, revSrc ca.RevokedEntriesSource, cfg *internal.Config, tickCh <-chan time.Time) {
	cache := make(map[string]*crlSignerCache)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tickCh:
				// Try distributed lock: only one instance generates CRLs
				lock := database.NewDistLock()
				locked, _ := lock.TryLock(ctx, db.LockKeyCRLRenew)
				if !locked {
					slog.Debug("crl: skipped (another instance holds the lock)")
					continue
				}
			metas, err := database.ListCAMetas()
			if err != nil {
				slog.Error("crl: list ca_meta", "error", err)
				continue
			}
			for _, m := range metas {
				caCfg, ok := cfg.CAs[m.Name]
				if !ok || caCfg.Cert == "" || caCfg.Key == "" {
					continue
				}
				cached, ok := cache[m.Name]
				if !ok {
					caCert, caKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, secrets.ResolveCAKeyPassword(m.Name, caCfg.Password))
					if err != nil {
						slog.Error("crl: load signer", "ca", m.Name, "error", err)
						continue
					}
					cache[m.Name] = &crlSignerCache{caCert: caCert, caKey: caKey}
					cached = cache[m.Name]
				}
				partitions := cfg.CRL.Partitions
				if partitions <= 1 {
					partitions = 1
				}
				for p := 0; p < partitions; p++ {
					crlDER, err := ca.GenerateCRL(&ca.CRLConfig{
						DB:                   database,
						RevokedEntriesSource: revSrc,
						CACert:               cached.caCert,
						CAKey:                cached.caKey,
						CAName:               m.Name,
						ValidityDays:         cfg.CRL.ValidityDays,
						Partition:            p,
						TotalPartitions:      partitions,
						NumberStore:          database,
					})
					if err != nil {
						slog.Error("crl: generate", "ca", m.Name, "partition", p, "error", err)
						continue
					}
					if cfg.CRL.OutputDir != "" {
						filename := ca.CRLFilename(m.Name, p, partitions)
						path := filepath.Join(cfg.CRL.OutputDir, filename)
						if err := os.WriteFile(path, crlDER, 0644); err != nil {
							slog.Error("crl: write file", "path", path, "error", err)
						}
					}
				}
				slog.Debug("crl: renewed", "ca", m.Name)
			}
		}
	}
}

func loadTSAConfig(cfg *internal.Config) (http.Handler, *tsa.RuntimeConfig, error) {
	tsaSignerCert, tsaSignerKey, err := ca.LoadSigner(cfg.TSA.SignerCert, cfg.TSA.SignerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load TSA signer: %w", err)
	}
	var tsaChain []*x509.Certificate
	if cfg.TSA.Chain != "" {
		chainCert, _, err := ca.LoadSigner(cfg.TSA.Chain, cfg.TSA.SignerKey)
		if err == nil {
			tsaChain = []*x509.Certificate{chainCert}
		}
	}

	var tstInfoCfg *tsa.TSTInfoConfig
	if cfg.TSA.TSAPolicy != "" || internal.BoolOr(cfg.TSA.Ordering, false) || cfg.TSA.AccuracySeconds != 0 || cfg.TSA.AccuracyMillis != 0 || cfg.TSA.AccuracyMicros != 0 {
		tstInfoCfg = &tsa.TSTInfoConfig{
			Ordering:        internal.BoolOr(cfg.TSA.Ordering, false),
			AccuracySeconds: cfg.TSA.AccuracySeconds,
			AccuracyMillis:  cfg.TSA.AccuracyMillis,
			AccuracyMicros:  cfg.TSA.AccuracyMicros,
		}
		if cfg.TSA.TSAPolicy != "" {
			oid, err := internal.ParseOID(cfg.TSA.TSAPolicy)
			if err != nil {
				return nil, nil, fmt.Errorf("parse tsa_policy: %w", err)
			}
			tstInfoCfg.Policy = oid
		}
	}

	tsaCfg := &tsa.TSAConfig{
		SignerCert: tsaSignerCert,
		SignerKey:  tsaSignerKey,
		Chain:      tsaChain,
		TSTInfo:    tstInfoCfg,
	}
	rc := tsa.NewRuntimeConfig(tsaCfg)
	h := tsa.NewHandlerWithRuntime(rc)
	return h, rc, nil
}

func loadOCSPConfig(cfg *internal.Config, database *db.DB) (http.Handler, error) {
	ocspSignerCert, ocspSignerKey, err := ca.LoadSigner(cfg.OCSP.SignerCert, cfg.OCSP.SignerKey)
	if err != nil {
		return nil, fmt.Errorf("load OCSP signer: %w", err)
	}
	issuingCert, _, err := ca.LoadSigner(cfg.CAs[cfg.Defaults.CA].Cert, cfg.CAs[cfg.Defaults.CA].Key, secrets.ResolveCAKeyPassword(cfg.Defaults.CA, cfg.CAs[cfg.Defaults.CA].Password))
	if err != nil {
		return nil, fmt.Errorf("load issuing CA cert: %w", err)
	}
	var ocspNextUpdate time.Duration
	if cfg.OCSP.NextUpdate != "" {
		ocspNextUpdate, _ = time.ParseDuration(cfg.OCSP.NextUpdate)
	}
	h := ocsp.NewHandler(&ocsp.Config{
		DB:         database,
		Engine:     fullMuxEngine,
		CACert:     issuingCert,
		CAName:     cfg.Defaults.CA,
		SignerCert: ocspSignerCert,
		SignerKey:  ocspSignerKey,
		NextUpdate: ocspNextUpdate,
		MetricsHook: serve.RecordOCSPResponse,
		CacheFile:   cfg.OCSP.CacheFile,
	})

	if cfg.OCSP.CacheFile == "" && cfg.OCSP.CacheSize > 0 {
		cacheTTL := 1 * time.Hour
		if cfg.OCSP.CacheTTL != "" {
			if d, err := time.ParseDuration(cfg.OCSP.CacheTTL); err == nil {
				cacheTTL = d
			}
		}
		cache := ocsp.NewCache(cfg.OCSP.CacheSize, cacheTTL)
		h.SetCache(cache)
	}

	return h, nil
}

// applyKeyBackend configures the pluggable signing backend. When
// KeyBackend.Type is "remote_hsm" every ca.LoadSigner call (and therefore the
// ACME protocol handlers plus the API signing paths) delegates
// private-key operations to the remote signer instead of a local key file.
func applyKeyBackend(cfg *internal.Config) error {
	if cfg.KeyBackend.Type != "remote_hsm" || cfg.KeyBackend.URL == "" {
		return nil
	}
	rc := &remotesigner.Config{
		Endpoint:  cfg.KeyBackend.URL,
		KeyAlias:  cfg.KeyBackend.KeyAlias,
		TLSCert:   cfg.KeyBackend.TLS.Cert,
		TLSKey:    cfg.KeyBackend.TLS.Key,
		CACert:    cfg.KeyBackend.TLS.CACert,
		AuthToken: cfg.KeyBackend.Token,
	}
	ca.SetRemoteSignerConfig(rc)
	slog.Info("remote signer enabled", "url", cfg.KeyBackend.URL, "key_alias", cfg.KeyBackend.KeyAlias)
	return nil
}

// parseAgentSessionMaxTTL converts the Serve.AgentSessionMaxTTL config string
// to a duration for the provisioner path, falling back to 24h on empty or
// invalid values (matching Server.agentSessionMaxTTL).
func parseAgentSessionMaxTTL(s string) time.Duration {
	if s == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// verifyClientCertRevocation returns a TLS VerifyPeerCertificate callback that
// rejects client certificates marked revoked in the local PKI database.
// The check runs against every certificate in the presented chain, keyed by
// (issuer DN, serial) which uniquely identifies certificates issued by this
// PKI. Certificates not issued by this PKI (no DB record) pass through to TLS
// chain validation + RBAC; DB errors fail closed.
//
// High-throughput mTLS clients reuse one client certificate across many
// handshakes. Querying the DB on every handshake makes handshake contention
// (SQLite's global page-cache mutex) dominate at w16+ concurrency and
// collapses throughput. A short-TTL status cache eliminates the repeated
// queries; revocation is picked up within revocationCheckCacheTTL. See
// invalidateRevocationCache (called on revoke) for the fast path.
//
// When the memory engine is enabled it serves the status lookup from the
// in-memory index (zero SQL); a miss falls back to the DB so certificates
// written out-of-band (CLI direct DB access) stay visible.
func verifyClientCertRevocation(database *db.DB) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	tlsVerifyDB.Store(database)
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return nil
		}
		d := tlsVerifyDB.Load()
		if d == nil {
			d = database
		}
		for _, c := range verifiedChains[0] {
			serial := fmt.Sprintf("%040X", c.SerialNumber)
			issuerDN := c.Issuer.String()
			key := revocationCacheKey(issuerDN, serial)
			if revoked, ok := cachedRevocationStatus(key); ok {
				if revoked {
					return fmt.Errorf("client certificate revoked: issuer=%s serial=%s", c.Issuer.CommonName, serial)
				}
				continue
			}
			var status *db.CertStatus
			if e := fullMuxEngine(); e != nil {
				st, err := e.GetCertStatusByIssuer(issuerDN, serial)
				if err == nil {
					status = st
				} else if !errors.Is(err, engine.ErrNotFound) {
					return fmt.Errorf("check client cert revocation: %w", err)
				}
			}
			if status == nil {
				var err error
				status, err = d.GetCertStatusByIssuer(issuerDN, serial)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						rememberRevocationStatus(key, false)
						continue // not issued by this PKI
					}
					return fmt.Errorf("check client cert revocation: %w", err)
				}
			}
			revoked := status.Status == "R" || status.RevokedAt != nil
			rememberRevocationStatus(key, revoked)
			if revoked {
				return fmt.Errorf("client certificate revoked: issuer=%s serial=%s", c.Issuer.CommonName, serial)
			}
		}
		return nil
	}
}

// revocationCheckCacheTTL bounds how long an mTLS handshake revocation
// status stays cached. Active revocation invalidates entries immediately via
// invalidateRevocationCache, so the TTL is only a safety net for out-of-band
// revocations. A short TTL keeps the stale-revocation window small while
// eliminating per-handshake DB queries.
var revocationCheckCacheTTL = 30 * time.Second

// revocationCacheMaxEntries bounds the cache to avoid unbounded growth from
// many distinct client certificates.
const revocationCacheMaxEntries = 4096

var (
	revocationMu    sync.Mutex
	revocationCache map[string]revocationEntry
)

type revocationEntry struct {
	revoked bool
	exp     time.Time
}

func revocationCacheKey(issuerDN, serial string) string {
	return issuerDN + "\x00" + serial
}

func cachedRevocationStatus(key string) (revoked bool, ok bool) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	e, ok := revocationCache[key]
	if !ok {
		return false, false
	}
	if time.Now().After(e.exp) {
		delete(revocationCache, key)
		return false, false
	}
	return e.revoked, true
}

func rememberRevocationStatus(key string, revoked bool) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	if revocationCache == nil {
		revocationCache = make(map[string]revocationEntry)
	}
	if len(revocationCache) >= revocationCacheMaxEntries {
		now := time.Now()
		for k, e := range revocationCache {
			if now.After(e.exp) {
				delete(revocationCache, k)
			}
		}
		if len(revocationCache) >= revocationCacheMaxEntries {
			return
		}
	}
	revocationCache[key] = revocationEntry{revoked: revoked, exp: time.Now().Add(revocationCheckCacheTTL)}
}

// invalidateRevocationCache drops a cached revocation status for a
// (issuer DN, serial) so the next handshake re-checks the DB immediately.
// Called on active revocation (API + CLI) to eliminate the TTL stale window.
func invalidateRevocationCache(issuerDN, serial string) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	delete(revocationCache, revocationCacheKey(issuerDN, serial))
}

// invalidateRevocationBySerial drops every cached status whose serial matches.
// Used on single-certificate revocation (serial is globally unique).
func invalidateRevocationBySerial(serial string) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	for k := range revocationCache {
		if strings.HasSuffix(k, "\x00"+serial) {
			delete(revocationCache, k)
		}
	}
}

// clearRevocationCache drops every cached status. Used on bulk revocations
// (by principal UID / sub-CA) where individual serials are not enumerated.
func clearRevocationCache() {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	revocationCache = nil
}

// policySigningOpts builds policy signature verification parameters from config.
// Returns non-nil opts when policy_signing is enabled; nil otherwise (no signature verification).
func policySigningOpts(cfg *internal.Config) (*auth.PolicySignatureOptions, error) {
	ps := cfg.PolicySigning
	if !ps.Enabled {
		return nil, nil
	}
	suffix := ps.SigSuffix
	if suffix == "" {
		suffix = ".sig"
	}
	caFile := ps.CAFile
	if caFile == "" {
		caFile = cfg.Serve.TLSClientCA
	}
	var roots *x509.CertPool
	if caFile != "" {
		var err error
		roots, err = auth.LoadCAFromFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("policy_signing: load CA %s: %w", caFile, err)
		}
	}
	requireAdminOU := true
	if ps.RequireAdminOU != nil {
		requireAdminOU = *ps.RequireAdminOU
	}
	if suffix == ".sig" && cfg.PolicySigning.SigSuffix == "" {
		cfg.PolicySigning.SigSuffix = suffix
	}
	return &auth.PolicySignatureOptions{
		Roots:          roots,
		RequireAdminOU: requireAdminOU,
	}, nil
}

// loadPolicyWithSigning loads authz.json (verifying signature first if enabled).
func loadPolicyWithSigning(cfg *internal.Config, path string) (*auth.Policy, error) {
	opts, err := policySigningOpts(cfg)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		return auth.LoadPolicy(path)
	}
	suffix := cfg.PolicySigning.SigSuffix
	if suffix == "" {
		suffix = ".sig"
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Clean(path + suffix))
	if err != nil {
		if cfg.PolicySigning.Require {
			return nil, fmt.Errorf("policy signature missing: %w", err)
		}
		// Signature missing but Require=false: fall back to loading plaintext policy.
		return auth.LoadPolicy(path)
	}
	if _, err := auth.VerifySignedPolicy(sig, data, opts); err != nil {
		return nil, err
	}
	return auth.LoadPolicy(path)
}

// defaultRoutesPath returns the default route rules file path in the directory
// of configPath. The rules file is always named routes.json regardless of the
// config file name (the historical implementation used strings.Replace to swap
// "pki.json", which only worked for configs literally named pki.json; other
// names caused the config file itself to be parsed as routes, resulting in all 404s).
func defaultRoutesPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "routes.json")
}

// loadRouteRulesWithSigning loads routes.json (verifying signature first if enabled).
func loadRouteRulesWithSigning(cfg *internal.Config, path string) (*routing.RouteRules, error) {
	opts, err := policySigningOpts(cfg)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		return routing.LoadFile(path)
	}
	suffix := cfg.PolicySigning.SigSuffix
	if suffix == "" {
		suffix = ".sig"
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Clean(path + suffix))
	if err != nil {
		if cfg.PolicySigning.Require {
			return nil, fmt.Errorf("route rules signature missing: %w", err)
		}
		return routing.LoadFile(path)
	}
	if _, err := auth.VerifySignedPolicy(sig, data, opts); err != nil {
		return nil, err
	}
	return routing.LoadFile(path)
}

func startServers(cfg *internal.Config, database *db.DB) error {
	// Invalidate the mTLS handshake revocation cache whenever a certificate
	// is revoked (single or bulk) so a freshly revoked client cert fails
	// closed immediately instead of waiting out the cache TTL.
	db.OnCertRevoked = func(serial string) {
		if serial == "" {
			clearRevocationCache()
		} else {
			invalidateRevocationBySerial(serial)
		}
	}

	if cfg.AuthorizationFile != "" {
		if p, err := loadPolicyWithSigning(cfg, cfg.AuthorizationFile); err != nil {
			slog.Warn("serve: authorization_file load failed, using hardcoded RBAC", "path", cfg.AuthorizationFile, "error", err)
		} else {
			auth.SetPolicy(p)
			slog.Info("serve: authorization policy loaded", "path", cfg.AuthorizationFile, "roles", len(p.Roles))
		}
	}

	if err := ca.BackfillAICFields(database); err != nil {
		slog.Warn("serve: backfill AIC fields failed", "error", err)
	}

	tsaHandler, tsaRC, err := loadTSAConfig(cfg)
	if err != nil {
		return err
	}

	ocspHandler, err := loadOCSPConfig(cfg, database)
	if err != nil {
		return err
	}

	fullMux = serve.NewFull(cfg, database, bundle, tsaHandler, ocspHandler)
	fullMux.SetTSAConfig(tsaRC)
	fullMux.Version = "varwof-core/" + version
	fullMux.SetConfigPath(configPath)

	// Enable buffered batch persistence for single-issue API throughput.
	// On failure the server keeps synchronous writes (never blocks startup).
	if err := fullMux.EnableRecordBuffer(cfg); err != nil {
		slog.Warn("serve: record buffer disabled, using synchronous writes", "error", err)
	}
	rbStopFn = fullMux.StopRecordBuffer

	// Enable the resident memory engine (memory-authoritative reads/writes
	// with async batched persistence) only when explicitly configured.
	// nil engine config = DB-only access paths (config-go: "nil=disabled").
	// On failure the server keeps DB-only access paths (never blocks startup).
	if cfg.Engine != nil {
		if err := fullMux.EnableEngine(cfg); err != nil {
			slog.Warn("serve: memory engine disabled, using DB-only access paths", "error", err)
		}
	}
	engineStopFn = fullMux.StopEngine

	// Set up provisioner registry
	reg := provisioner.NewRegistry()
	reg.Register(provisioner.NewMTLSProvisioner())
	reg.Register(provisioner.NewTokenProvisioner())
	provisioner.UserResolver = func(username string) (string, []string, error) {
		user, err := database.GetUserByUsername(username)
		if err != nil {
			return "", nil, err
		}
		if !user.Enabled {
			return "", nil, nil
		}
		perms := getRolePerms(user.Role, database)
		return user.Role, perms, nil
	}
	provisioner.SetTokenResolver(func(token string) (*provisioner.AuthResult, error) {
		if strings.HasPrefix(token, "basic:") {
			return resolveBasicAuth(strings.TrimPrefix(token, "basic:"), database)
		}
		return resolveAPIToken(token, database)
	})
	provisioner.AgentSessionMaxTTL = parseAgentSessionMaxTTL(cfg.Serve.AgentSessionMaxTTL)
	provisioner.TrustedGatewayOUs = append([]string(nil), cfg.Serve.TrustedGatewayOUs...)
	provisioner.CertResolver = func(issuerDN, serial string) (string, string, error) {
		return database.GetPrincipalByCert(issuerDN, serial)
	}
	fullMux.SetProvisioners(reg)

	// Load route rules (JSON-configured per-URL authorization)
	// Always loaded: config file → embedded default fallback
	loadRoutes := func(path string) *routing.RouteRules {
		if path != "" {
			if rr, err := loadRouteRulesWithSigning(cfg, path); err != nil {
				slog.Warn("serve: routes_file load failed", "path", path, "error", err)
				return nil
			} else {
				return rr
			}
		}
		return nil
	}
	var rr *routing.RouteRules
	if cfg.RoutesFile != "" {
		rr = loadRoutes(cfg.RoutesFile)
	} else {
		defaultPath := defaultRoutesPath(configPath)
		if _, err := os.Stat(defaultPath); err == nil {
			rr = loadRoutes(defaultPath)
		}
	}
	if rr == nil {
		rr = serve.LoadDefaultRouteRules()
	}
	fullMux.SetRouteRules(rr)

	// Capability registry (single source of register): validate capabilities are registered when issuing AIC.
	// When capability_schemes is empty, use embedded schemes; when a directory is specified, disk overrides.
	loadCapRegistry := func(m *serve.Server, c *internal.Config) {
		cr := capregistry.New()
		dir := ""
		if c != nil {
			dir = c.CapabilitySchemes
		}
		if err := cr.LoadAndSet(dir); err != nil {
			slog.Warn("serve: capability schemes load failed, registration validation disabled", "error", err)
			return
		}
		m.SetCapRegistry(cr)
	}
	loadCapRegistry(fullMux, cfg)

	publicMux = serve.NewPublic(cfg, database, bundle)
	publicMux.Version = "varwof-core/" + version
	publicMux.SetConfigPath(configPath)
	publicMux.SetRouteRules(rr)

	if internal.BoolOr(cfg.RateLimit.Enabled, false) {
		rl := serve.NewRateLimiter(cfg.RateLimit.Rate, cfg.RateLimit.Burst)
		fullMux.SetRateLimiter(rl)
		publicMux.SetRateLimiter(rl)
	}

	startCRL(database, engineSource(fullMux.Engine()), cfg)
	startExpiryWatcher(cfg, database)
	startTSARenewal(cfg, tsaRC)
	startAuditSaltRetirement(database, cfg)
	startAuditChainVerifier(database, cfg)

	// C7: CA master key rotation monitor — logs a warning when any configured
	// CA's active signing certificate approaches expiry, prompting the operator
	// to rotate via POST /api/v1/ca/{name}/rotate.
	rotationStopFn = fullMux.StartCARotationMonitor(12 * time.Hour)

	wrapFn := serve.WrapHandler
	if internal.BoolOr(cfg.Serve.MetricsEnabled, false) {
		wrapFn = serve.WrapHandlerWithMetrics
	}

	httpServer = &http.Server{
		Addr:    cfg.Serve.Addr,
		Handler: wrapFn(fullMux),
	}
	srv := httpServer
	go func() {
		slog.Info("serve: http (TSA+OCSP+Web+API)", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve: http error", "error", err)
		}
	}()

	if cfg.Serve.TLSAddr != "" && cfg.Serve.TLSCert != "" && cfg.Serve.TLSKey != "" {
		tlsCert, err := tls.LoadX509KeyPair(cfg.Serve.TLSCert, cfg.Serve.TLSKey)
		if err != nil {
			slog.Error("serve: load TLS cert", "error", err)
			return fmt.Errorf("load TLS cert: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
		if cfg.Serve.TLSClientCA != "" {
			caData, err := os.ReadFile(cfg.Serve.TLSClientCA)
			if err != nil {
				slog.Error("serve: read tls_client_ca", "error", err)
			} else {
				caPool := x509.NewCertPool()
				if caPool.AppendCertsFromPEM(caData) {
					tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
					tlsCfg.ClientCAs = caPool
					tlsCfg.VerifyPeerCertificate = verifyClientCertRevocation(database)
					slog.Info("serve: mTLS enabled", "client_ca", cfg.Serve.TLSClientCA)
				} else {
					slog.Error("serve: failed to parse tls_client_ca PEM")
				}
			}
		}
		tlsServer = &http.Server{
			Addr:      cfg.Serve.TLSAddr,
			Handler:   wrapFn(fullMux),
			TLSConfig: tlsCfg,
		}
		tlsSrv := tlsServer
		go func() {
			slog.Info("serve: https (TSA+OCSP+Web+API)", "addr", tlsSrv.Addr)
			if err := tlsSrv.ListenAndServeTLS(cfg.Serve.TLSCert, cfg.Serve.TLSKey); err != nil && err != http.ErrServerClosed {
				slog.Error("serve: https error", "error", err)
			}
		}()
	} else if cfg.Serve.TLSAddr != "" {
		slog.Warn("serve: tls_addr set but tls_cert or tls_key missing; HTTPS not started")
	}

	return nil
}

func reloadConfigNow(cfgPath string) {
	reloadConfigNowWithMuxes(cfgPath, fullMux, publicMux)
}

func reloadConfigNowWithMuxes(cfgPath string, full, public *serve.Server) {
	if cfgPath == "" {
		slog.Warn("reload: no config path known")
		return
	}
	loaded, err := internal.LoadConfig(cfgPath)
	if err != nil {
		slog.Error("reload: load config", "error", err)
		return
	}
	cfg := internal.DefaultConfig()
	merged := internal.MergeConfig(&cfg, loaded)

	if err := applyKeyBackend(merged); err != nil {
		slog.Error("reload: key backend", "error", err)
	}

	if merged.AuthorizationFile != "" {
		if p, err := loadPolicyWithSigning(merged, merged.AuthorizationFile); err != nil {
			slog.Warn("reload: authorization_file load failed, keeping existing policy", "path", merged.AuthorizationFile, "error", err)
		} else {
			auth.SetPolicy(p)
			slog.Info("reload: authorization policy reloaded", "path", merged.AuthorizationFile, "roles", len(p.Roles))
		}
	}

	newDB, err := db.Open(merged.DB)
	if err != nil {
		slog.Error("reload: open db", "error", err)
		return
	}

	tsaHandler, tsaRC, err := loadTSAConfig(merged)
	if err != nil {
		newDB.Close()
		slog.Error("reload: TSA", "error", err)
		return
	}

	ocspHandler, err := loadOCSPConfig(merged, newDB)
	if err != nil {
		newDB.Close()
		slog.Error("reload: OCSP", "error", err)
		return
	}

	// Capture old DB before swapping
	oldDB := currentDB

	// Update provisioner resolvers to use the new DB
	if full != nil {
		provisioner.UserResolver = func(username string) (string, []string, error) {
			u, err := newDB.GetUserByUsername(username)
			if err != nil {
				return "", nil, err
			}
			if !u.Enabled {
				return "", nil, nil
			}
			perms := getRolePerms(u.Role, newDB)
			return u.Role, perms, nil
		}
		provisioner.SetTokenResolver(func(token string) (*provisioner.AuthResult, error) {
			if strings.HasPrefix(token, "basic:") {
				return resolveBasicAuth(strings.TrimPrefix(token, "basic:"), newDB)
			}
			return resolveAPIToken(token, newDB)
		})
		provisioner.AgentSessionMaxTTL = parseAgentSessionMaxTTL(merged.Serve.AgentSessionMaxTTL)
		provisioner.TrustedGatewayOUs = append([]string(nil), merged.Serve.TrustedGatewayOUs...)
		provisioner.CertResolver = func(issuerDN, serial string) (string, string, error) {
			return newDB.GetPrincipalByCert(issuerDN, serial)
		}
	}

	// Atomically swap sub-handlers, config, and db on both muxes
	full.Reload(merged, newDB, tsaHandler, ocspHandler)
	public.Reload(merged, newDB, nil, nil)
	full.SetTSAConfig(tsaRC)

	// Rebuild the memory engine over the new DB connection, or keep the
	// resident engine when the underlying store did not change. The engine
	// holds the previous DB handle, so it must be stopped before the old DB
	// closes and rebuilt over newDB after the swap. Only when engine is
	// configured.
	//
	// E04: a config-only reload (same DB DSN) keeps the resident engine
	// running and merely repoints its write path at newDB. This avoids the
	// multi-second synchronous full-rebuild window during which reads fall
	// back to the DB on large stores.
	keepEngine := full.EngineEnabled() && merged.Engine != nil &&
		oldDB != nil && oldDB != newDB && oldDB.Path() == newDB.Path()
	if !keepEngine {
		stopEngine()
	}
	if merged.Engine != nil {
		if keepEngine {
			full.KeepEngine(newDB)
			slog.Info("reload: keeping resident engine, DB store unchanged", "db", newDB.Path())
		} else {
			full.EnableEngine(merged)
		}
	} else if !merged.RecordBuffer.Disable {
		// Engine removed on reload: re-enable the record buffer so batch
		// throughput and WAL crash-safety are restored instead of silently
		// falling back to synchronous writes. EnableEngine stopped the buffer
		// at startup (engine and record buffer are mutually exclusive).
		if err := full.EnableRecordBuffer(merged); err != nil {
			slog.Warn("reload: record buffer disabled, using synchronous writes", "error", err)
		} else {
			rbStopFn = full.StopRecordBuffer
		}
	}
	engineStopFn = full.StopEngine

	// Reload route rules
	if merged.RoutesFile != "" {
		if rr, err := loadRouteRulesWithSigning(merged, merged.RoutesFile); err != nil {
			slog.Warn("reload: routes_file load failed, keeping existing rules", "path", merged.RoutesFile, "error", err)
		} else {
			full.SetRouteRules(rr)
			public.SetRouteRules(rr)
			slog.Info("reload: route rules reloaded", "path", merged.RoutesFile, "rules", rr.Count())
		}
	}

	// Reload capability schemes (capability registry hot-reload: change capability.json to update policies)
	if merged.CapabilitySchemes != "" {
		cr := capregistry.New()
		if err := cr.LoadAndSet(merged.CapabilitySchemes); err != nil {
			slog.Warn("reload: capability schemes load failed, keeping existing registry", "error", err)
		} else {
			full.SetCapRegistry(cr)
			slog.Info("reload: capability registry reloaded", "dir", merged.CapabilitySchemes)
		}
	}

	// Close old DB connection after new one is active
	if oldDB != nil && oldDB != newDB {
		// Switch mTLS revocation check to the new handle first, then close the old connection,
		// to prevent handshake closures from hitting a closed DB.
		tlsVerifyDB.Store(newDB)
		oldDB.Close()
	}

	// Update currentDB to the new connection
	currentDB = newDB

	// Restart CRL auto-renew with new config
	stopCRL()
	startCRL(newDB, engineSource(full.Engine()), merged)

	// Restart TSA renewal loop with new config
	stopTSARenewal()
	startTSARenewal(merged, tsaRC)

	// Restart CA rotation monitor with new config
	stopCARotationMonitor()
	rotationStopFn = full.StartCARotationMonitor(12 * time.Hour)

	// Restart audit-salt retirement with new config
	stopAuditSaltRetirement()
	startAuditSaltRetirement(newDB, merged)

	// Restart audit chain verifier with new config
	stopAuditChainVerifier()
	startAuditChainVerifier(newDB, merged)

	slog.Info("reload: complete")
}

// ---- Provisioner resolvers ----

func getRolePerms(role string, database *db.DB) []string {
	if p := auth.GetPolicy(); p != nil {
		return p.RoleGrants(role)
	}
	raw := auth.RolePermissions[role]
	perms := make([]string, len(raw))
	for i, r := range raw {
		perms[i] = string(r)
	}
	return perms
}

func resolveAPIToken(token string, database *db.DB) (*provisioner.AuthResult, error) {
	info, err := database.GetToken(token)
	if err != nil {
		return nil, nil
	}
	user, err := database.GetUserByUsername(info.Username)
	var caScopes string
	if err == nil {
		caScopes = user.CAScopes
	}
	perms := getRolePerms(info.Role, database)
	result := &provisioner.AuthResult{
		Username:    info.Username,
		Role:        info.Role,
		Permissions: perms,
	}
	if caScopes != "" {
		result.Permissions = append(result.Permissions, "cas:scope:"+caScopes)
	}
	return result, nil
}

func resolveBasicAuth(authHeader string, database *db.DB) (*provisioner.AuthResult, error) {
	// authHeader is either the raw base64 payload ("dXNlcjpwYXNz") from the
	// M23-fixed extractToken, or a legacy full "Basic <base64>" header.
	payload := strings.TrimSpace(authHeader)
	if len(payload) >= 6 && strings.EqualFold(payload[:6], "Basic ") {
		payload = strings.TrimSpace(payload[6:])
	}
	username, password, ok := parseBasicAuth(payload)
	if !ok {
		return nil, nil
	}
	user, err := database.GetUserByUsername(username)
	if err != nil || !user.Enabled {
		return nil, nil
	}
	// Argon2id verification is expensive (~64MB, tens of ms). Cache the outcome
	// keyed on the stored credential (username+salt+hash) so a password change
	// invalidates automatically; the user is re-read from the DB on every
	// request so a disabled account stays rejected.
	cacheKey := serve.BasicAuthCacheKey(username, user.Salt, user.PasswordHash)
	if !serve.BasicAuthVerified(cacheKey) {
		hash := db.HashPassword(password, user.Salt)
		if subtle.ConstantTimeCompare([]byte(hash), []byte(user.PasswordHash)) != 1 {
			return nil, nil
		}
		serve.RememberBasicAuth(cacheKey)
	}
	perms := getRolePerms(user.Role, database)
	return &provisioner.AuthResult{
		Username:    user.Username,
		Role:        user.Role,
		Permissions: perms,
	}, nil
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", false
	}
	return cs[:s], cs[s+1:], true
}


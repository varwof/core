// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/capregistry"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/routing"
	"github.com/varwof/core/internal/tsa"
	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

type caTreeCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type Server struct {
	cfgPtr     atomic.Pointer[internal.Config]
	dbPtr      atomic.Pointer[db.DB]
	tsaH       atomic.Pointer[http.Handler]
	ocspH      atomic.Pointer[http.Handler]
	tsaRC      atomic.Pointer[tsa.RuntimeConfig]
	publicOnly bool
	rl         *RateLimiter
	asyncQueue *ca.JobQueue
	bundle     *i18n.Bundle
	Version    string
	configPath string
	caTreeMu   sync.Mutex
	caTreeData *caTreeCacheEntry
	provs      *provisioner.Registry
	routeRules atomic.Pointer[routing.RouteRules]

	// capReg is the capability registry (single source of truth for validation).
	// At AIC issuance, declared capabilities are validated against it; nil means disabled (validation skipped).
	capReg *capregistry.CapabilityRegistry

	loginMu       sync.Mutex
	loginAttempts map[string]loginAttempt

	// recordBuffer batch-buffers issued certificate records (single-issue high-throughput mode).
	// Enabled via EnableRecordBuffer; when nil, single-issue writes go directly to the database synchronously.
	recordBuffer *RecordBuffer

	// engine is the in-memory data subsystem (in-memory authority, async batch persistence).
	// Enabled via EnableEngine; when nil, all reads and writes fall back to the database.
	enginePtr atomic.Pointer[engine.Engine]

	// rotationMu maintains a per-CA *ca.RotatingSigner registry (C7 master key hot rotation).
	rotationMu sync.Map

	// identitySrc is the identity-source → certificate automation source
	// (identity-user profile). Rebuilt on reload from cfg.Identity; nil = disabled.
	identitySrc atomic.Value // holds *identitySourceHolder, nil = disabled
}

// identitySourceHolder wraps the active identity source so atomic.Value never
// stores a nil interface (which panics). Load returns nil when disabled.
type identitySourceHolder struct {
	src ca.IdentitySource
}

// loginAttempt tracks consecutive failed password attempts for one account.
// After maxLoginFailures failures the account is locked for lockoutDuration.
type loginAttempt struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

var (
	maxLoginFailures = 5
	lockoutDuration  = 5 * time.Minute
	// loginAttemptTTL bounds how long a stale failure record lives. M19 fix:
	// random-username sprays must not accumulate unbounded entries forever.
	loginAttemptTTL = 24 * time.Hour
	// maxLoginAttemptEntries caps the in-memory map to prevent memory exhaustion.
	maxLoginAttemptEntries = 1 << 16 // 65536
)

// purgeStaleLoginAttempts removes entries older than loginAttemptTTL. Called
// under s.loginMu; cheap sweep bounded by map size.
func (s *Server) purgeStaleLoginAttempts(now time.Time) {
	for user, at := range s.loginAttempts {
		if now.Sub(at.lastSeen) > loginAttemptTTL {
			delete(s.loginAttempts, user)
		}
	}
}

// loginThrottled reports whether the account is currently locked out.
func (s *Server) loginThrottled(username string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	at, ok := s.loginAttempts[username]
	if !ok {
		return false
	}
	if time.Now().Before(at.lockedUntil) {
		return true
	}
	if at.lockedUntil.IsZero() {
		return false
	}
	// Lockout expired: reset the counter.
	delete(s.loginAttempts, username)
	return false
}

// recordLoginFailure counts a failed attempt and locks the account once the
// threshold is crossed.
func (s *Server) recordLoginFailure(username string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginAttempts == nil {
		s.loginAttempts = make(map[string]loginAttempt)
	}
	// Opportunistic TTL sweep to bound growth (M19 fix).
	s.purgeStaleLoginAttempts(time.Now())
	at := s.loginAttempts[username]
	at.failures++
	at.lastSeen = time.Now()
	if at.failures >= maxLoginFailures {
		at.lockedUntil = time.Now().Add(lockoutDuration)
		at.failures = 0
	}
	s.loginAttempts[username] = at
	// Hard cap: if we exceeded the bound, drop arbitrary entries to make room.
	if len(s.loginAttempts) > maxLoginAttemptEntries {
		for user := range s.loginAttempts {
			delete(s.loginAttempts, user)
			if len(s.loginAttempts) <= maxLoginAttemptEntries {
				break
			}
		}
	}
}

// resetLoginThrottle clears the failure counter after a successful login.
func (s *Server) resetLoginThrottle(username string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, username)
}

func (s *Server) SetProvisioners(reg *provisioner.Registry) {
	s.provs = reg
}

func (s *Server) SetRouteRules(rr *routing.RouteRules) {
	s.routeRules.Store(rr)
}

// SetCapRegistry sets the capability registry (single source of truth).
// Passing nil disables capability registration validation.
func (s *Server) SetCapRegistry(cr *capregistry.CapabilityRegistry) {
	s.capReg = cr
}

// CapRegistry returns the current capability registry (may be nil).
func (s *Server) CapRegistry() *capregistry.CapabilityRegistry {
	return s.capReg
}

// validateCapabilities is the capability registration validation hook injected into ca.SignConfig.
// Returns nil if the registry is not enabled or all capabilities are registered.
func (s *Server) validateCapabilities(caps []string) error {
	if s.capReg == nil {
		return nil
	}
	return s.capReg.ValidateCapabilityIDs(caps)
}

// SetTSAConfig stores the TSA RuntimeConfig for management API access.
func (s *Server) SetTSAConfig(rc *tsa.RuntimeConfig) {
	if rc != nil {
		s.tsaRC.Store(rc)
	}
}

// GetTSAConfig returns the TSA RuntimeConfig, or nil if not set.
func (s *Server) GetTSAConfig() *tsa.RuntimeConfig {
	return s.tsaRC.Load()
}

func (s *Server) getRouteRules() *routing.RouteRules {
	return s.routeRules.Load()
}

// NewFull creates a full Server with TSA and OCSP handlers, async job queue,
// and rate limiter support. Used by the main serve command.
func NewFull(cfg *internal.Config, database *db.DB, b *i18n.Bundle, tsaH, ocspH http.Handler) *Server {
	s := &Server{bundle: b}
	s.asyncQueue = ca.NewJobQueue(12, 5*time.Minute, newAsyncJobProcessor(s, 12))
	s.cfgPtr.Store(cfg)
	s.dbPtr.Store(database)
	h := tsaH
	s.tsaH.Store(&h)
	h2 := ocspH
	s.ocspH.Store(&h2)
	s.routeRules.Store(LoadDefaultRouteRules())
	s.rebuildIdentitySource()
	return s
}

// NewPublic creates a Server restricted to public-only routes (health, cert
// distribution, static files). Used by modular serve mode.
func NewPublic(cfg *internal.Config, database *db.DB, b *i18n.Bundle) *Server {
	s := &Server{publicOnly: true, bundle: b}
	s.cfgPtr.Store(cfg)
	s.dbPtr.Store(database)
	s.routeRules.Store(LoadDefaultRouteRules())
	s.rebuildIdentitySource()
	return s
}

// recordWALPath derives the RecordBuffer WAL path from the DB DSN.
// In-memory and remote (postgres/mysql) DSNs get no WAL (crash-unsafe
// buffering is only applied for file-backed SQLite).
func recordWALPath(dbPath string) string {
	switch {
	case dbPath == "":
		return ""
	}
	lower := strings.ToLower(dbPath)
	switch {
	case lower == ":memory:", strings.HasPrefix(lower, "file:"),
		strings.HasPrefix(lower, "postgres"), strings.HasPrefix(lower, "mysql"):
		return ""
	}
	if strings.HasSuffix(lower, ".db") {
		return dbPath[:len(dbPath)-3] + "-records.wal"
	}
	return dbPath + "-records.wal"
}

// onEngineRevoked returns the callback invoked when the memory engine marks a
// certificate revoked. varwof-core uses it to invalidate the OCSP response LRU
// via db.OnCertRevoked (engine revocations go through the same db-level hook
// so every cache layer converges immediately).
func (s *Server) onEngineRevoked() func(serial string) {
	return func(serial string) {
		if db.OnCertRevoked != nil {
			db.OnCertRevoked(serial)
		}
	}
}

// engineFromConfig derives engine options from the serve config. Engine writes
// land in memory first and persist asynchronously with WAL protection; the
// WAL path reuses the record-buffer WAL derivation so cert batches share one
// crash-recovery log.
func engineFromConfig(cfg *internal.Config, onRevoked func(serial string)) engine.EngineOptions {
	opts := engine.EngineOptions{
		WalPath:       recordWALPath(cfg.DB),
		Logger:        slog.Default(),
		OnCertRevoked: onRevoked,
	}
	ec := cfg.Engine
	if ec == nil {
		return opts
	}
	if ec.MaxCerts > 0 {
		opts.MaxCerts = ec.MaxCerts
	}
	if ec.MaxNonces > 0 {
		opts.MaxNonces = ec.MaxNonces
	}
	if ec.MaxDANonces > 0 {
		opts.MaxDANonces = ec.MaxDANonces
	}
	if ec.MaxRevoked > 0 {
		opts.MaxRevoked = ec.MaxRevoked
	}
	if ec.Grace != "" {
		if d, err := time.ParseDuration(ec.Grace); err == nil {
			opts.Grace = d
		}
	}
	if ec.JanitorInterval != "" {
		if d, err := time.ParseDuration(ec.JanitorInterval); err == nil {
			opts.JanitorInterval = d
		}
	}
	if ec.NonceTTL != "" {
		if d, err := time.ParseDuration(ec.NonceTTL); err == nil {
			opts.NonceTTL = d
		}
	}
	if ec.WriteThreshold > 0 {
		opts.WriteThreshold = ec.WriteThreshold
	}
	if ec.WriteMaxPending > 0 {
		opts.WriteMaxPending = ec.WriteMaxPending
	}
	if ec.WriteMaxLatency != "" {
		if d, err := time.ParseDuration(ec.WriteMaxLatency); err == nil {
			opts.WriteMaxLatency = d
		}
	}
	if ec.WriteWorkers > 0 {
		opts.WriteWorkers = ec.WriteWorkers
	}
	return opts
}

// EnableRecordBuffer creates the RecordBuffer for this server from cfg and
// starts its background flusher. Idempotent: a second call replaces the
// existing buffer (flushing it first). Returns the creation error; the
// server keeps working with synchronous writes when this fails.
func (s *Server) EnableRecordBuffer(cfg *internal.Config) error {
	if s.publicOnly {
		return nil
	}
	if cfg.RecordBuffer.Disable {
		s.StopRecordBuffer()
		return nil
	}
	if s.recordBuffer != nil {
		s.recordBuffer.Stop()
	}
	threshold := cfg.RecordBuffer.Threshold
	if threshold <= 0 {
		threshold = defaultFlushBatch
	}
	maxPending := defaultMaxPending
	if cfg.RecordBuffer.MaxPending != nil {
		maxPending = *cfg.RecordBuffer.MaxPending
	}
	maxLatency := defaultMaxLatency
	if cfg.RecordBuffer.MaxLatency != "" {
		if d, err := time.ParseDuration(cfg.RecordBuffer.MaxLatency); err != nil {
			return fmt.Errorf("record_buffer.max_latency: %v", err)
		} else if d > 0 {
			maxLatency = d
		}
	}
	rb, err := NewRecordBuffer(s.getDB, threshold, int32(maxPending), maxLatency, recordWALPath(cfg.DB))
	if err != nil {
		return err
	}
	s.recordBuffer = rb
	slog.Info("record_buffer: enabled", "wal", recordWALPath(cfg.DB), "threshold", threshold, "max_pending", maxPending)
	return nil
}

// StopRecordBuffer flushes buffered records and stops the background flusher.
// No-op when the buffer was never enabled.
func (s *Server) StopRecordBuffer() {
	if s.recordBuffer != nil {
		s.recordBuffer.Stop()
		s.recordBuffer = nil
	}
}

// FlushRecordBuffer synchronously flushes all buffered records to the DB.
// Used before read-modify-write operations (e.g. revocation) so that
// recently issued-but-unflushed certificates are visible to the DB, avoiding
// the ≤500ms visibility window between issue and bulk insert. When the memory
// engine owns the write pipeline its pending writes are flushed instead.
func (s *Server) FlushRecordBuffer() {
	if e := s.getEngine(); e != nil {
		e.FlushAll()
		return
	}
	if s.recordBuffer != nil {
		s.recordBuffer.flushAll()
	}
}

func (s *Server) SetConfigPath(path string) { s.configPath = path }

// WrapHandler wraps the Server with access logging middleware.
func WrapHandler(s *Server) http.Handler {
	return accessLog(s)
}

// WrapHandlerWithMetrics wraps the Server with access logging and Prometheus
// metrics middleware.
func WrapHandlerWithMetrics(s *Server) http.Handler {
	return metricsMiddleware(accessLog(s))
}

func (s *Server) getConfig() *internal.Config { return s.cfgPtr.Load() }
func (s *Server) getDB() *db.DB               { return s.dbPtr.Load() }

// rebuildIdentitySource (re)builds the identity-source automation source from
// the current config. A nil config disables the identity-user profile path.
// An invalid config logs a warning and leaves the previous source in place.
func (s *Server) rebuildIdentitySource() {
	cfg := s.cfgPtr.Load()
	if cfg == nil || cfg.Identity == nil {
		s.identitySrc.Store((*identitySourceHolder)(nil))
		return
	}
	src, err := ca.NewIdentitySource(cfg.Identity)
	if err != nil {
		slog.Warn("identity source build failed; keeping previous", "error", err.Error())
		return
	}
	s.identitySrc.Store(&identitySourceHolder{src: src})
}

// getIdentitySource returns the active identity-source automation source, or nil.
func (s *Server) getIdentitySource() ca.IdentitySource {
	if h, ok := s.identitySrc.Load().(*identitySourceHolder); ok && h != nil {
		return h.src
	}
	return nil
}

// getEngine returns the resident memory engine, or nil when disabled.
func (s *Server) getEngine() *engine.Engine { return s.enginePtr.Load() }

// Engine returns the resident memory engine, or nil when disabled. Exported
// for wiring read-side lookups (OCSP, metrics) outside the package.
func (s *Server) Engine() *engine.Engine { return s.enginePtr.Load() }

// revokedEntriesSource returns the CRL revoked-entries source: the memory
// engine when enabled, else nil (CRL generation falls back to the DB). The
// nil-typed-engine→nil-interface conversion here avoids the typed-nil trap.
func (s *Server) revokedEntriesSource() ca.RevokedEntriesSource {
	if e := s.getEngine(); e != nil {
		return e
	}
	return nil
}

// addCertRecordEnabled reports whether signed records are persisted by the
// engine or record buffer (SkipDB=true in the sign path) rather than written
// synchronously to the DB by ca.Sign.
func (s *Server) addCertRecordEnabled() bool {
	return s.getEngine() != nil || s.recordBuffer != nil
}

// addCertRecord persists a signed certificate record. When the memory engine
// is enabled it lands in memory first (memory-authoritative) and is persisted
// asynchronously; otherwise the record buffer batches it; otherwise the
// caller's SkipDB=false sign path already wrote it. Returns ErrBackpressure
// when the write pipeline is at capacity (HTTP 503), nil on success.
func (s *Server) addCertRecord(rec *db.CertRecord) error {
	if e := s.getEngine(); e != nil {
		return e.IssueCert(rec)
	}
	if s.recordBuffer != nil {
		if !s.recordBuffer.Add(rec) {
			return engine.ErrBackpressure
		}
	}
	return nil
}

// getCertStatus resolves a certificate status preferring the memory engine and
// falling back to the DB on a miss (out-of-band writes stay visible). Returns
// the same error semantics as the underlying store.
func (s *Server) getCertStatus(caName, serial string) (*db.CertStatus, error) {
	if e := s.getEngine(); e != nil {
		st, err := e.GetCertStatus(caName, serial)
		if err == nil {
			return st, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine status lookup failed, falling back to DB", "ca", caName, "serial", serial, "error", err)
		}
	}
	return s.getDB().GetCertStatus(caName, serial)
}

// getCertBySPKIHash resolves certificates by SPKI hash preferring the memory
// engine and falling back to the DB.
func (s *Server) getCertBySPKIHash(hash, caName, status string) ([]*db.CertRecord, error) {
	if e := s.getEngine(); e != nil {
		recs, _, _, err := e.GetCertBySPKIHash(hash, caName, status, 0, nil)
		if err == nil {
			return recs, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine SPKI lookup failed, falling back to DB", "hash", hash, "error", err)
		}
	}
	return s.getDB().GetCertBySPKIHash(hash, caName, status)
}

// storeDANonce persists a DelegationAuthorization nonce (32 bytes) for replay
// protection at AIC issuance. The memory engine is authoritative when enabled;
// otherwise the DB da_nonces table is written directly. Returns
// db.ErrDuplicateNonce when the nonce was already used to mint an AIC (replay
// attempt must be rejected).
// daNonceClockBuffer is the extra retention added to a DA nonce beyond the
// timestamp-freshness window, to absorb clock skew between the agent signing
// the DA and the CA checking its timestamp. 3 minutes is deliberately generous
// vs the default 30s skew.
const daNonceClockBuffer = 3 * time.Minute

// daNonceExpiry returns the deadline after which a DelegationAuthorization
// nonce no longer needs to be retained for replay protection.
//
// The DA timestamp-freshness check (da_max_timestamp_skew) already rejects DAs
// older than skew, so a replayed DA cannot pass that check once |now - ts| >
// skew — the nonce only needs to outlive that window plus a clock-skew buffer.
// When the freshness check is disabled (skew <= 0) the nonce is retained for
// the DA lifetime instead; if the lifetime is also unset it falls back to the
// engine's NonceTTL. The deadline is floored at now+buffer so an entry never
// expires before the request that created it has settled.
func daNonceExpiry(ts int64, lifetimeSec int64, skew time.Duration, ttl time.Duration) time.Time {
	now := time.Now()
	window := skew
	if window <= 0 {
		window = time.Duration(lifetimeSec) * time.Second
		if window <= 0 {
			window = ttl
		}
	}
	exp := time.Unix(ts, 0).Add(window).Add(daNonceClockBuffer)
	if min := now.Add(daNonceClockBuffer); exp.Before(min) {
		exp = min
	}
	return exp
}

// getEngineNonceTTL returns the engine's NonceTTL when the engine is enabled,
// else the 24h default. Used only as the last-resort DA nonce retention when
// both the timestamp-skew window and the DA lifetime are unavailable.
func (s *Server) getEngineNonceTTL() time.Duration {
	if e := s.getEngine(); e != nil {
		return e.NonceTTL()
	}
	return 24 * time.Hour
}

func (s *Server) storeDANonce(nonce []byte, exp time.Time) error {
	if e := s.getEngine(); e != nil {
		return e.StoreDANonce(nonce, exp)
	}
	return s.getDB().StoreDANonce(nonce)
}

// daTimestampSkew returns the DelegationAuthorization.timestamp freshness window
// (da_max_timestamp_skew, default 30s). Returns <=0 to disable this defense.
func (s *Server) daTimestampSkew() time.Duration {
	skew := time.Duration(0)
	cfg := s.getConfig()
	if cfg == nil {
		return internal.DefaultDATimestampSkew
	}
	v := cfg.Serve.DAMaxTimestampSkew
	if v == "" {
		return internal.DefaultDATimestampSkew
	}
	if d, err := time.ParseDuration(v); err == nil {
		skew = d
	}
	return skew
}

// checkDATimestampFreshness validates whether DA.timestamp falls within the freshness window
// (|now - timestamp| ≤ skew; skew<=0 skips the check). Zero-value timestamp is treated as rejected.
// Spec P1-B-13 / dev-docs/aic/06-delegation-auth.md §Validation Flow (CA Issuance Phase) ①.
func (s *Server) checkDATimestampFreshness(ts time.Time) error {
	skew := s.daTimestampSkew()
	if skew <= 0 {
		return nil
	}
	if ts.IsZero() {
		return fmt.Errorf("delegation auth timestamp: missing")
	}
	age := time.Since(ts)
	if age < 0 {
		age = -age
	}
	if age > skew {
		return fmt.Errorf("delegation auth timestamp %v: stale (|now-ts|=%s > %s)", ts.UTC(), age, skew)
	}
	return nil
}

// countActiveAICsByPrincipalUid returns the number of currently active agent-proxy AIC certificates
// for a given principal (status='V', agent_id non-empty, not expired).
// When the engine is enabled, it uses the in-memory index; otherwise falls back to the database.
// Used to enforce the spec's DelegationPolicy.MaxAgents concurrent delegation limit (B2).
func (s *Server) countActiveAICsByPrincipalUid(principalUID string, now time.Time) (int, error) {
	if e := s.getEngine(); e != nil {
		recs, _, _, err := e.ListCertsByPrincipalUid(principalUID, "V", 0, nil)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range recs {
			if r.AgentId == "" {
				continue
			}
			if now.After(r.NotBefore) && now.Before(r.NotAfter) {
				n++
			}
		}
		return n, nil
	}
	if d := s.getDB(); d != nil {
		return d.CountActiveAICByPrincipalUid(principalUID, now)
	}
	return 0, nil
}

// agentProxyMaxValidity returns the agent-proxy certificate validity upper bound
// (agent_proxy_max_validity, default 1h; 0/invalid → default 1h).
// Spec P1-B-09/25, P2-A-04 allows ≤24h.
func (s *Server) agentProxyMaxValidity() time.Duration {
	d := ca.DefaultAgentProxyMaxValidity
	cfg := s.getConfig()
	if cfg == nil {
		return d
	}
	v := cfg.Defaults.AgentProxyMaxValidity
	if v == "" {
		return d
	}
	if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 && parsed <= 24*time.Hour {
		d = parsed
	}
	return d
}

// requirePolicy reports whether issuance must fail when no CN/SAN policy is
// configured (M4 fix: config enforce_policy). It feeds SignConfig.RequirePolicy
// so an unconfigured policy becomes a hard error in enforcement deployments.
func (s *Server) requirePolicy() bool {
	cfg := s.getConfig()
	if cfg == nil || cfg.EnforcePolicy == nil {
		return false
	}
	return *cfg.EnforcePolicy
}

// getAICExtensionByCert resolves the AIC extension for a certificate
// preferring the memory engine and falling back to the DB.
func (s *Server) getAICExtensionByCert(caName, serial string) (*db.AICExtension, error) {
	if e := s.getEngine(); e != nil {
		ext, err := e.GetAICExtensionByCert(caName, serial)
		if err == nil {
			return ext, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine AIC lookup failed, falling back to DB", "ca", caName, "serial", serial, "error", err)
		}
	}
	return s.getDB().GetAICExtensionByCert(caName, serial)
}

// revokeCert marks a certificate revoked. With the memory engine enabled the
// mutation lands in memory first (immediately visible, async persisted, cache
// invalidated via db.OnCertRevoked); otherwise it writes the DB directly.
func (s *Server) revokeCert(caName, serial string, reason int) error {
	if e := s.getEngine(); e != nil {
		if err := e.RevokeCert(caName, serial, reason); err != nil {
			// The cert may have been written out-of-band (CLI, batch while
			// engine stopped) and is not resident in memory. Fall back to the
			// DB so the revocation is not silently lost.
			if errors.Is(err, engine.ErrNotFound) {
				slog.Debug("serve: engine revoke miss, falling back to DB", "ca", caName, "serial", serial)
				return s.getDB().RevokeCert(caName, serial, reason)
			}
			return err
		}
		return nil
	}
	return s.getDB().RevokeCert(caName, serial, reason)
}

// revokeByPrincipalUid revokes every active certificate of a principal.
// Returns the number revoked.
func (s *Server) revokeByPrincipalUid(uid string, reason int) (int, error) {
	if e := s.getEngine(); e != nil {
		return e.RevokeCertsByPrincipalUid(uid, reason)
	}
	return s.getDB().RevokeCertsByPrincipalUid(uid, reason)
}

// revokeBySubCA revokes every active certificate under a sub-CA. Returns the
// number revoked.
func (s *Server) revokeBySubCA(caName string, reason int) (int, error) {
	if e := s.getEngine(); e != nil {
		return e.RevokeCertsBySubCA(caName, reason)
	}
	return s.getDB().RevokeCertsBySubCA(caName, reason)
}

// revokeCertsBatch revokes a large set of certificates. With the memory
// engine enabled the whole batch lands in memory under a single lock
// (immediately visible, async persisted); entries the engine cannot resolve
// (out-of-band writes) are retried against the DB. Without the engine, the DB
// transaction path is used directly. Returns the total count actually revoked.
func (s *Server) revokeCertsBatch(entries []db.RevokeBatchEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	if e := s.getEngine(); e != nil {
		revoked, miss, err := e.RevokeCertsBatch(entries)
		if err != nil {
			return revoked, err
		}
		if len(miss) > 0 {
			n, err := s.getDB().RevokeCertsBatch(miss)
			if err != nil {
				return revoked, err
			}
			revoked += n
		}
		return revoked, nil
	}
	return s.getDB().RevokeCertsBatch(entries)
}

// revokeWithCascade revokes a certificate and cascade-revokes all agent
// certificates with the same PrincipalUid. Mirrors ca.RevokeWithCascade but
// routes writes through the memory engine when enabled.
func (s *Server) revokeWithCascade(caName, serial string, reason int) (int, error) {
	normalized, err := ca.NormalizeSerial(serial)
	if err != nil {
		return 0, fmt.Errorf("normalize serial: %w", err)
	}

	// Look up principal_uid from the record first (fast path), fall back to
	// DER scan for legacy records that predate the principal_uid column.
	rec, lookupErr := s.getCertRecord(caName, normalized)
	var principalUid string
	if lookupErr == nil && rec.PrincipalUid != "" {
		principalUid = rec.PrincipalUid
	} else if lookupErr == nil {
		if uid, extractErr := ca.ExtractPrincipalUID(rec.CertDER); extractErr == nil {
			principalUid = uid
		}
	}

	if err := s.revokeCert(caName, normalized, reason); err != nil {
		return 0, err
	}
	if principalUid == "" {
		return 0, nil // no AIC on revoked cert, no cascade
	}
	cascaded, err := s.revokeByPrincipalUid(principalUid, reason)
	if err != nil {
		return 0, err
	}
	return cascaded, nil
}

// getCertRecord resolves a full certificate record preferring the memory
// engine and falling back to the DB on a miss.
func (s *Server) getCertRecord(caName, serial string) (*db.CertRecord, error) {
	if e := s.getEngine(); e != nil {
		rec, err := e.GetCert(caName, serial)
		if err == nil {
			return rec, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine cert lookup failed, falling back to DB", "ca", caName, "serial", serial, "error", err)
		}
	}
	return s.getDB().GetCert(caName, serial)
}

// getCertStatusByIssuer resolves a certificate status by issuer DN + serial,
// preferring the memory engine and falling back to the DB on a miss.
func (s *Server) getCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error) {
	if e := s.getEngine(); e != nil {
		st, err := e.GetCertStatusByIssuer(issuerDN, serial)
		if err == nil {
			return st, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine issuer status lookup failed, falling back to DB", "issuer", issuerDN, "serial", serial, "error", err)
		}
	}
	return s.getDB().GetCertStatusByIssuer(issuerDN, serial)
}

// EnableEngine builds the resident memory engine over the current DB and
// starts its background janitor. Idempotent: a second call stops the previous
// engine first. Returns the build error; the server keeps working with DB-only
// reads/writes when the engine cannot be rebuilt.
func (s *Server) EnableEngine(cfg *internal.Config) error {
	if s.publicOnly {
		return nil
	}
	if e := s.enginePtr.Load(); e != nil {
		e.Stop()
		s.enginePtr.Store(nil)
	}
	d := s.getDB()
	if d == nil {
		return nil
	}
	e, err := engine.NewEngine(d, engineFromConfig(cfg, s.onEngineRevoked()))
	if err != nil {
		slog.Warn("serve: memory engine disabled, using DB-only reads/writes", "error", err)
		return err
	}
	e.Start()
	s.enginePtr.Store(e)
	// The engine owns its own write pipeline (record buffer + WAL), so the
	// standalone recordBuffer becomes redundant. Stop it to keep exactly one
	// write path for signed certificates.
	s.StopRecordBuffer()
	slog.Info("serve: memory engine enabled",
		"certs", e.Metrics().CertIndexSize,
		"revoked", e.Metrics().RevokedSetSize,
		"nonces", e.Metrics().NonceSetSize,
		"users", e.Metrics().UserIndexSize,
		"tokens", e.Metrics().TokenIndexSize)
	return nil
}

// StopEngine flushes pending engine writes and shuts down the memory engine.
// No-op when the engine was never enabled.
func (s *Server) StopEngine() {
	if e := s.enginePtr.Load(); e != nil {
		e.Stop()
		s.enginePtr.Store(nil)
	}
}

// KeepEngine repoints a running memory engine at a new DB handle without
// rebuilding its in-memory index. It is used on config reload when the
// underlying store has not changed (same DB DSN): reads keep being served from
// the resident index and writes converge through the new handle, avoiding the
// multi-second full-rebuild read cliff on large stores. No-op when the engine
// is not enabled.
func (s *Server) KeepEngine(newDB *db.DB) {
	if e := s.enginePtr.Load(); e != nil {
		e.SetDB(newDB)
	}
}

// EngineEnabled reports whether the resident memory engine is currently active.
func (s *Server) EngineEnabled() bool {
	return s.enginePtr.Load() != nil
}

func (s *Server) tsaHandler() http.Handler {
	if h := s.tsaH.Load(); h != nil {
		return *h
	}
	return http.NotFoundHandler()
}

func (s *Server) ocspHandler() http.Handler {
	if h := s.ocspH.Load(); h != nil {
		return *h
	}
	return http.NotFoundHandler()
}

func (s *Server) SetRateLimiter(rl *RateLimiter) {
	s.rl = rl
}

// requestIP extracts the client IP from a RemoteAddr string, handling both
// IPv4 ("1.2.3.4:5678") and IPv6 ("[::1]:5678" / "fe80::1%eth0:5678") forms.
// On malformed input the whole string is returned unchanged so the rate
// limiter still keys on something.
func requestIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// M20 fix: limit request body size to 10MB to prevent memory exhaustion.
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB
	}

	if s.rl != nil {
		ip := requestIP(r.RemoteAddr)
		if !s.rl.Allow(ip) {
			s.apiErr(w, r, http.StatusTooManyRequests, "api.too_many_requests", "")
			return
		}
	}

	path := r.URL.Path

	// Root POST: TSA/OCSP protocol dispatch by Content-Type (public).
	if path == "/" && r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		switch ct {
		case "application/timestamp-query":
			s.tsaHandler().ServeHTTP(w, r)
			return
		case "application/ocsp-request":
			s.ocspHandler().ServeHTTP(w, r)
			return
		}
		s.apiErr(w, r, http.StatusBadRequest, "api.bad_content_type", "")
		return
	}

	// Public protocol/static/health paths bypass auth entirely.
	if rr := s.getRouteRules(); rr != nil && rr.IsPublic(path) {
		s.serveByPath(w, r, path)
		return
	}

	if s.publicOnly {
		rr := s.getRouteRules()
		if rr != nil {
			if rule, params := rr.MatchWithParams(r.Method, path); rule != nil {
				s.requireRouteAuth(rule, params, s.serveAPI)(w, r)
				return
			}
			if def := rr.DefaultRule(); def != nil {
				s.requireRouteAuth(def, nil, s.serveAPI)(w, r)
				return
			}
		}
		s.apiErr(w, r, http.StatusBadRequest, "api.cert_distribution_only", "")
		return
	}

	// Web pages use dedicated handlers (they are not serveAPI endpoints).
	switch {
	case strings.HasPrefix(path, "/swagger/"):
		s.requirePerm(PermSwaggerView, s.serveSwagger)(w, r)
		return
	case path == "/cas" || path == "/certs" || strings.HasPrefix(path, "/ca/") || strings.HasPrefix(path, "/cert/"):
		s.requirePerm(PermWebView, s.serveWeb)(w, r)
		return
	case path == "/dashboard":
		s.requirePerm(PermWebView, s.serveDashboard)(w, r)
		return
	case path == "/topology":
		s.requirePerm(PermCAList, s.serveTopology)(w, r)
		return
	}

	// Route rules engine: JSON-configured per-URL API authorization.
	// Always populated (embedded default fallback), so the nil path
	// only exists as a safety net.
	rr := s.getRouteRules()
	if rr != nil {
		if rule, params := rr.MatchWithParams(r.Method, path); rule != nil {
			s.requireRouteAuth(rule, params, s.serveAPI)(w, r)
			return
		}
		// M21 fix: honor default_permission as a deny-by-default fallback instead
		// of the dead config it used to be. No match → check for a configured
		// default; if none, deny with 404.
		if def := rr.DefaultRule(); def != nil {
			s.requireRouteAuth(def, nil, s.serveAPI)(w, r)
			return
		}
		s.apiErr(w, r, http.StatusNotFound, "api.not_found", "")
		return
	}
	http.NotFound(w, r)
}

func (s *Server) Reload(cfg *internal.Config, database *db.DB, tsaH, ocspH http.Handler) {
	s.cfgPtr.Store(cfg)
	s.dbPtr.Store(database)
	h := tsaH
	s.tsaH.Store(&h)
	h2 := ocspH
	s.ocspH.Store(&h2)
	if s.getRouteRules() == nil {
		s.routeRules.Store(LoadDefaultRouteRules())
	}
	s.rebuildIdentitySource()
}

// requireRouteAuth checks authorization using a route rule from the JSON config.
// It validates: require_role → permission → CA scope → AIC identity.
func (s *Server) requireRouteAuth(rule *routing.RouteRule, params map[string]string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isWriteMethod(r.Method) && !isSameOrigin(r) {
			s.apiErr(w, r, http.StatusForbidden, "api.forbidden_cors", "")
			return
		}
		user, err := s.authenticate(r)
		if err != nil || user == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="pki"`)
			s.apiErr(w, r, http.StatusUnauthorized, "api.unauthorized", "")
			return
		}

		// 1. require_role check (if specified)
		if len(rule.RequireRole) > 0 {
			allowed := false
			for _, required := range rule.RequireRole {
				if user.Role == required || strings.HasPrefix(user.Role, required+"(") {
					allowed = true
					break
				}
			}
			if !allowed {
				s.apiErr(w, r, http.StatusForbidden, "api.forbidden_role",
					"role "+user.Role+" not in required roles")
				return
			}
		}

		// 2. permission check
		if rule.Permission != "" && !user.HasPerm(Permission(rule.Permission)) {
			s.apiErr(w, r, http.StatusForbidden, "api.forbidden",
				"missing permission: "+rule.Permission)
			return
		}

		// 3. CA scope check (all permission modes; enforced whenever the route
		//    declares ca_scope and the authenticated user carries a scope).
		//    Sub-CA management routes are scope-exempt for superadmin: their
		//    handlers enforce admin-cert scope via verifyAdminCert, and
		//    superadmin is a framework role that may manage any sub-CA.
		if rule.CAScope {
			subCAManage := strings.Contains(r.URL.Path, "/sub-ca/")
			if !(subCAManage && user.Role == "superadmin") {
				if !checkCAScope(user, r, Permission(rule.Permission), s.getConfig()) {
					s.apiErr(w, r, http.StatusForbidden, "api.ca_scope_denied",
						"permission denied for this CA")
					return
				}
			}
		}

		// 4. AIC identity check
		if rule.AllowAIC != nil && !*rule.AllowAIC {
			if strings.HasSuffix(user.Role, "(agent)") {
				s.apiErr(w, r, http.StatusForbidden, "api.forbidden_aic",
					"AIC agent access not allowed for this endpoint")
				return
			}
		}

		ctx := context.WithValue(r.Context(), userCtxKey, user)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// serveByPath dispatches to the appropriate handler based on URL path
// for public routes that bypass authorization.
func (s *Server) serveByPath(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/healthz" || path == "/readyz":
		s.serveHealth(w, r)
	case path == "/":
		s.serveStatic(w, r)
	case path == "/metrics":
		s.metricsHandler().ServeHTTP(w, r)
	case path == "/tsa" || path == "/timestamp":
		s.tsaHandler().ServeHTTP(w, r)
	case path == "/ocsp" || strings.HasPrefix(path, "/ocsp/"):
		s.ocspHandler().ServeHTTP(w, r)
	case strings.HasPrefix(path, "/pki/"):
		s.serveStatic(w, r)
	default:
		s.serveAPI(w, r)
	}
}

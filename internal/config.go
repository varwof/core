package internal

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// Config is the top-level configuration for varwof-core.
// Fields map directly to the JSON config file (see /etc/varwof/core/pki.json).
type Config struct {
	DB                string                   `json:"db,omitempty"`                 // SQLite/MySQL DSN (e.g. "/etc/varwof/core/pki.db")
	Locale            string                   `json:"locale,omitempty"`             // "zh" or "en" (default: auto-detect)
	TSA               TSAConfig                `json:"tsa,omitempty"`                // Time-Stamp Authority config
	OCSP              OCSPConfig               `json:"ocsp,omitempty"`               // OCSP responder config
	CAs               map[string]CAConfig      `json:"cas,omitempty"`                // CA definitions (name → CAConfig)
	Serve             ServeConfig              `json:"serve,omitempty"`              // HTTP server & TLS listener config
	Defaults          DefaultsConfig           `json:"defaults,omitempty"`           // Default values for certificate issuance
	CRL               CRLConfig                `json:"crl,omitempty"`                // CRL generation config
	Webhook           WebhookConfig            `json:"webhook,omitempty"`            // Webhook notification config
	KeyEscrow         KeyEscrowConfig          `json:"key_escrow,omitempty"`         // Key escrow (recovery) config
	CTLog             CTLogConfig              `json:"ct_log,omitempty"`             // Certificate Transparency log config
	LDAP              ca.LDAPConfig            `json:"ldap,omitempty"`               // LDAP directory integration config
	Identity          *ca.IdentitySourceConfig `json:"identity,omitempty"`           // Identity-source → certificate automation (identity-user profile)
	RA                RAConfig                 `json:"ra,omitempty"`                 // Registration Authority workflow config
	RateLimit         RateLimitConfig          `json:"rate_limit,omitempty"`         // Per-IP rate limiting config
	PG                db.PGConfig              `json:"pg,omitempty"`                 // PostgreSQL-specific config (pool size, SSL)
	AutoRenew         AutoRenewConfig          `json:"auto_renew,omitempty"`         // Automatic certificate renewal config
	Archive           ArchiveConfig            `json:"archive,omitempty"`            // Certificate archival config
	TrustBridge       TrustBridgeConfig        `json:"trust_bridge,omitempty"`       // Cross-CA trust bridge config
	SMTP              SMTPConfig               `json:"smtp,omitempty"`               // SMTP notification config
	Policy            string                   `json:"policy,omitempty"`             // Path to policy JSON file (CN/SAN allow/deny)
	// EnforcePolicy, when true, makes an unconfigured issuance policy (policy)
	// a hard error instead of a warn-and-continue (M4 fix). Default false keeps
	// backward-compatible behavior; deployments that rely on policy restrictions
	// should set this to fail closed when policy.json is missing/unloaded.
	EnforcePolicy *bool `json:"enforce_policy,omitempty"`
	RBAC              RBACConfig               `json:"rbac,omitempty"`               // Role-based access control config
	AuthorizationFile string                   `json:"authorization_file,omitempty"` // Path to authz.json policy file
	RoutesFile        string                   `json:"routes_file,omitempty"`        // Path to routes.json per-URL rule file
	CapabilitySchemes string                   `json:"capability_schemes,omitempty"` // Path to capability schemes dir (register; embedded default if empty)
	PolicySigning     PolicySigningConfig      `json:"policy_signing,omitempty"`     // Signed policy-file verification config
	Hierarchy         string                   `json:"hierarchy,omitempty"`          // "simple" | "complex" (CA hierarchy model)
	KeyBackend        KeyBackendConfig         `json:"key_backend,omitempty"`        // Remote signer delegation config
	Persist           PersistConfig            `json:"persist,omitempty"`            // Certificate persistence mode config
	K8sEnabled        *bool                    `json:"k8s_enabled,omitempty"`        // Enable /api/v1/k8s/sign endpoint (default false for security)
	Aggregator        AggregatorConfig         `json:"aggregator,omitempty"`         // Batch certificate issuance aggregator config
	RecordBuffer      RecordBufferConfig       `json:"record_buffer,omitempty"`      // RecordBuffer batch persistence config (threshold/max_pending/max_latency/disable)
	Engine            *EngineConfig            `json:"engine,omitempty"`             // In-memory engine config (nil=disabled, reads/writes fall back to DB)
	SPIFFE            *SPIFFEConfig            `json:"spiffe,omitempty"`             // SPIFFE identity integration config (nil=disabled)
}

// SPIFFEConfig configures optional SPIFFE identity integration for AIC certificates.
// When enabled, AIC agentId is written as a SPIFFE URI and embedded in certificate SAN URIs.
type SPIFFEConfig struct {
	// TrustDomain is the SPIFFE trust domain (e.g. "varwof.com").
	// Used to construct SPIFFE IDs: "spiffe://{trustDomain}/agent/{agentId}".
	TrustDomain string `json:"trust_domain"`
}

// EngineConfig configures the in-memory data engine.
// When enabled, high-frequency reads/writes for certificates, revocations, nonces, etc.
// first hit the in-memory authority, then are persisted asynchronously in batch (WAL crash-safe).
// nil or omitted = engine not enabled, reads/writes fall back to DB.
type EngineConfig struct {
	// MaxCerts is the in-memory certificate upper bound (default 200000). When the limit is
	// reached, eviction only occurs if there are expired certificates (beyond the Grace window);
	// if all existing certificates are unexpired, new signings return ErrBackpressure (HTTP 503)
	// until some certificates expire.
	// Production tuning: set to "peak concurrent valid certificates × 1.5" and monitor
	// the `engine WindowEvictions` metric and issuance 503 rate.
	MaxCerts        int    `json:"max_certs,omitempty"`
	MaxNonces       int    `json:"max_nonces,omitempty"`        // In-memory nonce upper bound (default 100000)
	MaxDANonces     int    `json:"max_da_nonces,omitempty"`     // In-memory DA nonce upper bound (default 100000)
	MaxRevoked      int    `json:"max_revoked,omitempty"`       // Per-CA revocation set upper bound (default 50000)
	Grace           string `json:"grace,omitempty"`             // Retention window for expired certificates in memory (default "24h")
	JanitorInterval string `json:"janitor_interval,omitempty"`  // Janitor sweep interval (default "60s")
	NonceTTL        string `json:"nonce_ttl,omitempty"`         // Unused nonce lifetime (default "24h")
	WriteThreshold  int    `json:"write_threshold,omitempty"`   // Certificate batch persistence threshold (default 100)
	WriteMaxPending int32  `json:"write_max_pending,omitempty"` // Pending persistence upper bound (backpressure, default 20000)
	WriteMaxLatency string `json:"write_max_latency,omitempty"` // Maximum persistence latency (default "500ms")
}

// RecordBufferConfig configures RecordBuffer batch persistence behavior.
// Enabled by default (threshold=500, max_pending=20000, max_latency=500ms).
// Setting max_pending to 0 disables backpressure (Add never returns false, RecordBuffer still batches);
// setting disable to true completely turns off RecordBuffer (issuance writes directly to DB synchronously, no WAL).
type RecordBufferConfig struct {
	Disable    bool   `json:"disable,omitempty"`     // Completely disable RecordBuffer (synchronous persistence)
	Threshold  int    `json:"threshold,omitempty"`   // Batch threshold (default 500)
	MaxPending *int   `json:"max_pending,omitempty"` // Pending upper bound pointer; nil=default 20000, 0=disable backpressure (unlimited)
	MaxLatency string `json:"max_latency,omitempty"` // Maximum batch delay (default "500ms", Go duration format)
}

// AggregatorConfig configures batch certificate issuance aggregation.
type AggregatorConfig struct {
	WindowMs   int `json:"window_ms,omitempty"`   // Time window in milliseconds (default 200)
	BatchMax   int `json:"batch_max,omitempty"`   // Maximum batch size (default 1000)
	Threshold  int `json:"threshold,omitempty"`   // Auto-switch threshold (default 50)
	BufferSize int `json:"buffer_size,omitempty"` // Queue capacity (default 10000)
}

// PersistConfig controls certificate persistence mode.
type PersistConfig struct {
	Mode          string `json:"mode,omitempty"`           // "realtime" | "batch" | "async"
	BatchSize     int    `json:"batch_size,omitempty"`     // Accumulate N records before batch flush
	BatchInterval string `json:"batch_interval,omitempty"` // Max wait before batch flush (e.g. "5s")
	QueueSize     int    `json:"queue_size,omitempty"`     // Async queue capacity (default 10000)
	BufferDB      string `json:"buffer_db,omitempty"`      // Buffer database DSN for async mode
}

// RateLimitConfig defines per-IP request rate limiting.
type RateLimitConfig struct {
	Enabled *bool   `json:"enabled,omitempty"` // Enable per-IP rate limiting (*bool so hot reload can disable)
	Rate    float64 `json:"rate,omitempty"`    // Requests per second allowed
	Burst   int     `json:"burst,omitempty"`   // Burst size (default 200)
}

// RAConfig configures the Registration Authority approval workflow.
type RAConfig struct {
	RequiredApprovals int    `json:"required_approvals,omitempty"` // Number of approvals required (default 1)
	DefaultCA         string `json:"default_ca,omitempty"`         // Default CA for RA-issued certificates
	DefaultProfile    string `json:"default_profile,omitempty"`    // Default profile for RA-issued certificates
}

// KeyEscrowConfig defines the admin public key for key recovery.
type KeyEscrowConfig struct {
	AdminPublicKey string `json:"admin_public_key,omitempty"` // PEM-encoded admin public key for key recovery
}

// CTLogConfig configures Certificate Transparency log submission.
type CTLogConfig struct {
	URL       string       `json:"url,omitempty"`     // CT log server URL
	APIKey    string       `json:"api_key,omitempty"` // CT log API key (optional)
	PublicKey string       `json:"public_key,omitempty"` // CT log public key (base64 DER SPKI or PEM). Required for real SCT signature verification (H11); without it verification degrades to structural checks with a warning.
	Logs      []CTLogEntry `json:"logs,omitempty"`    // Additional CT log entries
}

// CTLogEntry defines a single CT log server endpoint.
type CTLogEntry struct {
	URL       string `json:"url"`               // CT log server URL
	APIKey    string `json:"api_key,omitempty"` // CT log API key (optional)
	PublicKey string `json:"public_key,omitempty"` // CT log public key (base64 DER SPKI or PEM). Required for real SCT signature verification (H11).
}

// WebhookConfig configures HTTP webhook notifications for PKI events.
type WebhookConfig struct {
	URL                 string `json:"url,omitempty"`                   // Webhook callback URL
	Timeout             string `json:"timeout,omitempty"`               // HTTP request timeout (e.g. "10s")
	ExpiryCheckInterval string `json:"expiry_check_interval,omitempty"` // Expiry check interval (e.g. "24h")
	ExpiryThresholds    []int  `json:"expiry_thresholds,omitempty"`     // Days before expiry to trigger (e.g. [30,7,1])
}

// RBACConfig defines role-based access control settings.
type RBACConfig struct {
	Enabled        *bool               `json:"enabled,omitempty"`         // Master RBAC switch (*bool so hot reload can disable)
	PermissionMode string              `json:"permission_mode,omitempty"` // "simple" | "enterprise"
	CAScopes       map[string][]string `json:"ca_scopes,omitempty"`
}

// PolicySigningConfig configures PKCS#7 signature verification for authz.json / routes.json.
// When enabled, the policy file's detached signature (<file>.sig) is verified before loading;
// the signer must be an admin-role certificate issued by this PKI, and the CA chain must be
// verifiable. Verification failure rejects loading (fail-closed).
// Example:
//
//	"policy_signing": {
//	  "enabled": true,
//	  "ca_file": "/etc/varwof/core/keys/issuing-ca.pem",
//	  "require_admin_ou": true,
//	  "require": true,
//	  "sig_suffix": ".sig"
//	}
type PolicySigningConfig struct {
	Enabled        bool   `json:"enabled,omitempty"`          // Enable policy file signature verification
	CAFile         string `json:"ca_file,omitempty"`          // Trusted CA chain PEM (default tls_client_ca)
	RequireAdminOU *bool  `json:"require_admin_ou,omitempty"` // Require signer to have admin OU (default true, nil=unset)
	Require        bool   `json:"require,omitempty"`          // true=reject when signature missing; false=degrade with warning
	SigSuffix      string `json:"sig_suffix,omitempty"`       // Signature file suffix (default ".sig")
}

// DefaultDATimestampSkew is the default DelegationAuthorization.timestamp freshness window
// (spec P1-B-13 / dev-docs/aic/06-delegation-auth.md §Validation Flow (CA Issuance Phase) ①:
// |now - timestamp| ≤ 30s). Override with da_max_timestamp_skew; "0" disables this defense.
const DefaultDATimestampSkew = 30 * time.Second

// ServeConfig configures the HTTP server, TLS listeners, and admin auth.
type ServeConfig struct {
	Addr               string            `json:"addr,omitempty"`                  // HTTP listen address (e.g. ":8443")
	TLSAddr            string            `json:"tls_addr,omitempty"`              // HTTPS mTLS listen address (e.g. ":4433")
	APIAddr            string            `json:"api_addr,omitempty"`              // Internal API listen address (e.g. "127.0.0.1:9090")
	TLSCert            string            `json:"tls_cert,omitempty"`              // TLS certificate file path
	TLSKey             string            `json:"tls_key,omitempty"`               // TLS private key file path
	Static             string            `json:"static,omitempty"`                // Static file directory (Web UI, CRL distribution)
	TLSClientCA        string            `json:"tls_client_ca,omitempty"`         // Client CA cert for mTLS authentication
	AuthUsername       string            `json:"auth_username,omitempty"`         // Basic auth username (fallback when mTLS unavailable)
	AuthPassword       string            `json:"auth_password,omitempty"`         // Basic auth password
	ReloadPollInterval string            `json:"reload_poll_interval,omitempty"`  // Config file poll interval (e.g. "10s")
	ShutdownTimeout    string            `json:"shutdown_timeout,omitempty"`      // Graceful shutdown timeout (e.g. "10s")
	MetricsEnabled     *bool             `json:"metrics_enabled,omitempty"`       // Enable Prometheus /metrics endpoint (*bool so hot reload can disable)
	LogFormat          string            `json:"log_format,omitempty"`            // "text" or "json" for structured logging
	LogDest            string            `json:"log_dest,omitempty"`              // Log output target: "stderr" (default), "file:/path/to/pki.log", or "syslog" (local /dev/log or UDP localhost:514)
	AgentSessionMaxTTL string            `json:"agent_session_max_ttl,omitempty"` // Max X-Agent-TTL window for delegated sessions (e.g. "24h"; "0" rejects them entirely)
	TrustedGatewayOUs  []string          `json:"trusted_gateway_ous,omitempty"`   // OUs of trusted gateway service certs that may assert delegated identity via X-Client-Cert-DER (B2, recommended) or legacy X-Agent-User (Deprecated, B1); empty = reject gateway-asserted delegation
	AuditSalt          AuditSaltConfig   `json:"audit_salt,omitempty"`            // Per-day salt masking of PII in the audit log (privacy / data minimization)
	AuditVerify        AuditVerifyConfig `json:"audit_verify,omitempty"`          // Periodic Merkle chain integrity verification of the audit log (AUTH-016)
	DAMaxTimestampSkew string            `json:"da_max_timestamp_skew,omitempty"` // Max |now - DelegationAuthorization.timestamp| accepted at issuance (e.g. "30s"; default 30s, "0" disables the freshness check). Second line of the DA nonce/timestamp replay defense (P1-B-13).
}

// AuditSaltConfig configures per-day salt masking of personally identifiable
// audit fields (username, remote IP). Each calendar day uses a fresh random
// salt to HMAC these fields before they are stored and chained; the salt is
// kept for retention_days and then purged, after which masked identities are
// permanently irrecoverable while the Merkle chain over the masked values
// stays verifiable.
type AuditSaltConfig struct {
	Enabled         *bool  `json:"enabled,omitempty"`          // Enable salt masking (default true). When false, audit fields stay plaintext.
	RetentionDays   int    `json:"retention_days,omitempty"`   // Days to keep each daily salt (default 365). After this, the day's salt row is deleted → masked identities become irreversible.
	CleanupInterval string `json:"cleanup_interval,omitempty"` // How often to scan and purge expired salts (e.g. "24h"; default 24h).
}

// AuditVerifyConfig configures automatic integrity verification of the audit
// Merkle hash chain (AUTH-016). When enabled, the server periodically recomputes
// the chain and logs a warning (with the offending entry ID) on any break —
// e.g. a row deleted or altered out-of-band. Verification reads the whole
// audit_log, so the interval should be relaxed for very large logs.
type AuditVerifyConfig struct {
	Enabled  *bool  `json:"enabled,omitempty"`  // Enable periodic chain verification (default true).
	Interval string `json:"interval,omitempty"` // How often to verify (e.g. "1h"; default 24h).
}

// TSAConfig configures the RFC 3161 Time-Stamp Authority service.
type TSAConfig struct {
	Addr            string `json:"addr,omitempty"`             // TSA listen address (e.g. ":3180")
	SignerCert      string `json:"signer_cert,omitempty"`      // TSA signer certificate PEM file
	SignerKey       string `json:"signer_key,omitempty"`       // TSA signer private key PEM file
	Chain           string `json:"chain,omitempty"`            // TSA certificate chain (intermediate + root)
	TSAPolicy       string `json:"tsa_policy,omitempty"`       // TSA policy OID (default: 2.16.840.1.101.3.4.2.1)
	Ordering        *bool  `json:"ordering,omitempty"`         // Enforce strict timestamp ordering (*bool so hot reload can toggle)
	AccuracySeconds int    `json:"accuracy_seconds,omitempty"` // Time accuracy in seconds
	AccuracyMillis  int    `json:"accuracy_millis,omitempty"`  // Time accuracy in milliseconds
	AccuracyMicros  int    `json:"accuracy_micros,omitempty"`  // Time accuracy in microseconds
	// Auto-renewal fields
	CoreURL       string `json:"core_url,omitempty"`        // varwof-core API URL for automatic signer renewal
	CAName        string `json:"ca_name,omitempty"`         // CA name to use for signer certificate renewal
	ValidityDays  int    `json:"validity_days,omitempty"`   // Renewed signer cert validity in days
	RenewalWindow string `json:"renewal_window,omitempty"`  // How far before expiry to trigger renewal (e.g. "720h")
	CheckInterval string `json:"check_interval,omitempty"`  // How often to check cert expiry (e.g. "1h")
	TLSClientCert string `json:"tls_client_cert,omitempty"` // mTLS client cert for varwof-core API calls
	TLSClientKey  string `json:"tls_client_key,omitempty"`  // mTLS client key for varwof-core API calls
	TLSCACert     string `json:"tls_ca_cert,omitempty"`     // CA cert to verify varwof-core API TLS
}

// OCSPConfig configures the RFC 6960 OCSP responder.
type OCSPConfig struct {
	Addr       string `json:"addr,omitempty"`        // OCSP responder listen address (e.g. ":9080")
	SignerCert string `json:"signer_cert,omitempty"` // OCSP signer certificate PEM file
	SignerKey  string `json:"signer_key,omitempty"`  // OCSP signer private key PEM file
	NextUpdate string `json:"next_update,omitempty"` // Next update interval (e.g. "4h")
	CacheSize  int    `json:"cache_size,omitempty"`  // OCSP response cache size (entries)
	CacheTTL   string `json:"cache_ttl,omitempty"`   // OCSP cache TTL (e.g. "1h")
	CacheFile  string `json:"cache_file,omitempty"`  // persisted cache file; when set, the in-memory cache is replaced by a disk-backed cache loaded at startup and re-saved after each response (stateless OCSP node support)
}

// CAConfig defines a single CA's certificate and key paths.
type CAConfig struct {
	Cert     string `json:"cert,omitempty"`     // CA certificate PEM file path
	Key      string `json:"key,omitempty"`      // CA private key PEM file path
	Chain    string `json:"chain,omitempty"`    // CA chain file (intermediates + root)
	Password string `json:"password,omitempty"` // CA private key password (from env if empty)
}

// KeyBackendConfig configures remote signer delegation.
type KeyBackendConfig struct {
	Type     string `json:"type,omitempty"`      // "software" (default) or "remote_hsm"
	URL      string `json:"url,omitempty"`       // Remote signer URL (e.g. "https://127.0.0.1:9443")
	KeyAlias string `json:"key_alias,omitempty"` // Key alias on remote signer (default: auto-detect from cert filename)
	TLS      struct {
		Cert   string `json:"cert,omitempty"`    // Client TLS cert for mTLS
		Key    string `json:"key,omitempty"`     // Client TLS key for mTLS
		CACert string `json:"ca_cert,omitempty"` // CA cert to verify remote signer
	} `json:"tls,omitempty"`
	Token string `json:"token,omitempty"` // Bearer token
}

// DefaultsConfig defines default values applied to every certificate issuance.
type DefaultsConfig struct {
	CA             string `json:"ca,omitempty"`              // Default CA name for issuance
	Profile        string `json:"profile,omitempty"`         // Default certificate profile (e.g. "tls-server")
	KeyType        string `json:"key_type,omitempty"`        // Default key type (e.g. "ecdsa-p256")
	Hash           string `json:"hash,omitempty"`            // Default hash algorithm (e.g. "sha256")
	DefaultCountry string `json:"default_country,omitempty"` // Default subject country (C)
	DefaultOrg     string `json:"default_org,omitempty"`     // Default subject organization (O)
	// Org is the legacy alias for DefaultOrg (config key "org"). When both
	// are present, Org wins so that init-full's generated "defaults.org"
	// keeps working. Deprecated: use default_org in new configs.
	Org               string   `json:"org,omitempty"`
	// Realm is the namespace identifier for PrincipalUid (e.g. "example.com").
	// When empty, defaults to "example.com" (RFC 2606 reserved domain).
	// Used as the Realm field in PrincipalUid when no explicit principal_uid is provided.
	Realm             string   `json:"realm,omitempty"`
	CertValidity      string   `json:"cert_validity,omitempty"`       // Default certificate validity duration (e.g. "2160h")
	OCSPURL           string   `json:"ocsp_url,omitempty"`            // OCSP responder URL (injected into AIA)
	IssuerURL         string   `json:"issuer_url,omitempty"`          // Issuer certificate URL (injected into AIA)
	IssuerAltNames    []string `json:"issuer_alt_names,omitempty"`    // Additional AIA issuer URLs
	SubjectInfoAccess []string `json:"subject_info_access,omitempty"` // Subject Info Access extensions
	PolicyOIDs        []string `json:"policy_oids,omitempty"`         // Certificate policy OIDs to include
	// PolicyMappings is an RFC 5280 §4.2.1.5 Policy Mappings extension list,
	// each item in format "issuerDomainPolicy:subjectDomainPolicy", written only
	// into CA certificates (enterprise bridge / cross-domain trust scenarios,
	// e.g. ["1.2.3.4.1:1.2.3.4.2"]).
	PolicyMappings []string `json:"policy_mappings,omitempty"`
	// RequireExplicitPolicy is the RFC 5280 §4.2.1.11 Policy Constraints
	// requireExplicitPolicy skipCerts count (CA certificates). Not generated by default.
	RequireExplicitPolicy *int `json:"require_explicit_policy,omitempty"`
	// InhibitPolicyMapping is the RFC 5280 §4.2.1.11 Policy Constraints
	// inhibitPolicyMapping skipCerts count (CA certificates). Not generated by default.
	InhibitPolicyMapping *int `json:"inhibit_policy_mapping,omitempty"`
	// InhibitAnyPolicy is the RFC 5280 §4.2.1.14 Inhibit anyPolicy extension's
	// skipCerts count (CA certificates). Not generated by default.
	InhibitAnyPolicy *int `json:"inhibit_any_policy,omitempty"`
	ReportMaxRows    int  `json:"report_max_rows,omitempty"` // Max rows in CSV/PDF reports (default 5000)
	// AgentProxyMaxValidity is the hard upper bound for agent-proxy (authorized mode)
	// certificate validity (Go duration, default "1h", can be relaxed up to ≤24h;
	// spec P1-B-09/25, P2-A-04).
	AgentProxyMaxValidity string `json:"agent_proxy_max_validity,omitempty"`
}

// CRLConfig configures Certificate Revocation List generation.
type CRLConfig struct {
	Addr          string `json:"addr,omitempty"`           // CRL distribution HTTP listen address
	ValidityDays  int    `json:"validity_days,omitempty"`  // CRL validity period in days (default 30)
	OutputDir     string `json:"output_dir,omitempty"`     // CRL file output directory
	CRLBaseURL    string `json:"crl_base_url,omitempty"`   // Base URL for CRL distribution points
	AutoRenew     string `json:"auto_renew,omitempty"`     // Deprecated: use RenewInterval
	RenewInterval string `json:"renew_interval,omitempty"` // CRL auto-regeneration interval (e.g. "24h")
	Partitions    int    `json:"partitions,omitempty"`     // 0 or 1 = no partitioning
}

// AutoRenewConfig configures automatic certificate renewal.
type AutoRenewConfig struct {
	Enabled         *bool    `json:"enabled,omitempty"`               // Enable automatic renewal (*bool so hot reload can disable)
	Interval        string   `json:"interval,omitempty"`              // Renewal check interval (e.g. "24h")
	WindowDays      int      `json:"window_days,omitempty"`           // Days before expiry to renew
	DefaultValidity int      `json:"default_validity_days,omitempty"` // Validity days for renewed certificates
	Profiles        []string `json:"profiles,omitempty"`              // Profiles eligible for auto-renewal
	ExcludeCAs      []string `json:"exclude_cas,omitempty"`           // CAs excluded from auto-renewal
	NotifyOnly      *bool    `json:"notify_only,omitempty"`           // Only notify, don't auto-renew (*bool so hot reload can toggle)
	MaxRenewals     int      `json:"max_renewals,omitempty"`          // Max renewals per certificate (0 = unlimited)
}

// ArchiveConfig configures certificate archival (soft-delete) behavior.
type ArchiveConfig struct {
	Enabled        *bool    `json:"enabled,omitempty"`         // Enable certificate archival (*bool so hot reload can disable)
	RetentionDays  int      `json:"retention_days,omitempty"`  // Days to keep archived certificates
	ExcludeCAs     []string `json:"exclude_cas,omitempty"`     // CAs excluded from archival
	ArchiveExpired *bool    `json:"archive_expired,omitempty"` // Archive expired certificates (*bool so hot reload can toggle)
	ArchiveRevoked *bool    `json:"archive_revoked,omitempty"` // Archive revoked certificates (*bool so hot reload can toggle)
}

// TrustBridgeConfig defines cross-CA trust bridge policies.
type TrustBridgeConfig struct {
	Bridges []TrustBridgePolicy `json:"bridges,omitempty"`
}

// TrustBridgePolicy defines a single trust bridge between two CAs.
type TrustBridgePolicy struct {
	Enabled   bool   `json:"enabled"`                 // Enable this trust bridge
	IssuerCA  string `json:"issuer_ca"`               // Issuer CA name (the trust anchor)
	SubjectCA string `json:"subject_ca"`              // Subject CA name (the bridge target)
	Validity  int    `json:"validity_days,omitempty"` // Cross-cert validity in days
}

// SMTPConfig configures email notifications via SMTP.
type SMTPConfig struct {
	Host               string `json:"host,omitempty"`                 // SMTP server hostname
	Port               int    `json:"port,omitempty"`                 // SMTP server port (e.g. 587)
	Username           string `json:"username,omitempty"`             // SMTP auth username
	Password           string `json:"password,omitempty"`             // SMTP auth password
	From               string `json:"from,omitempty"`                 // Sender email address
	To                 string `json:"to,omitempty"`                   // Recipient email address (comma-separated)
	TLS                *bool  `json:"tls,omitempty"`                  // Require TLS for SMTP connection (*bool so hot reload can toggle)
	InsecureSkipVerify *bool  `json:"insecure_skip_verify,omitempty"` // Skip TLS cert verification (*bool so hot reload can toggle)
	Events             string `json:"events,omitempty"`               // Comma-separated event types to notify on
}

func (ct *CTLogConfig) AllLogs() []CTLogEntry {
	var entries []CTLogEntry
	if ct.URL != "" {
		entries = append(entries, CTLogEntry{URL: ct.URL, APIKey: ct.APIKey, PublicKey: ct.PublicKey})
	}
	entries = append(entries, ct.Logs...)
	return entries
}

// BoolOr returns the value pointed to by b, or def when b is nil.
func BoolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// BoolPtr returns a pointer to b.
func BoolPtr(b bool) *bool { return &b }

var validKeyTypes = map[string]bool{
	"ecdsa-p256": true,
	"ecdsa-p384": true,
	"ed25519":    true,
	"ecdsa-p521": true,
	"rsa-2048":   true,
	"rsa-4096":   true,
	"rsa-8192":   true,
}

var validHashes = map[string]bool{
	"sha256": true,
	"sha384": true,
	"sha512": true,
}

var validPGSSLMode = map[string]bool{
	"disable":     true,
	"allow":       true,
	"prefer":      true,
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

func Validate(cfg *Config) error {
	if cfg.Defaults.KeyType != "" && !validKeyTypes[cfg.Defaults.KeyType] {
		return fmt.Errorf("config: invalid defaults.key_type %q", cfg.Defaults.KeyType)
	}
	if cfg.Defaults.Hash != "" && !validHashes[cfg.Defaults.Hash] {
		return fmt.Errorf("config: invalid defaults.hash %q", cfg.Defaults.Hash)
	}

	durFields := map[string]string{
		"defaults.cert_validity":        cfg.Defaults.CertValidity,
		"webhook.timeout":               cfg.Webhook.Timeout,
		"webhook.expiry_check_interval": cfg.Webhook.ExpiryCheckInterval,
		"serve.reload_poll_interval":    cfg.Serve.ReloadPollInterval,
		"serve.shutdown_timeout":        cfg.Serve.ShutdownTimeout,
		"auto_renew.interval":           cfg.AutoRenew.Interval,
		"crl.auto_renew":                cfg.CRL.AutoRenew,
		"crl.renew_interval":            cfg.CRL.RenewInterval,
		"ocsp.next_update":              cfg.OCSP.NextUpdate,
		"ocsp.cache_ttl":                cfg.OCSP.CacheTTL,
		"tsa.renewal_window":            cfg.TSA.RenewalWindow,
		"tsa.check_interval":            cfg.TSA.CheckInterval,
		"persist.batch_interval":        cfg.Persist.BatchInterval,
	}
	for name, val := range durFields {
		if val == "" {
			continue
		}
		if _, err := time.ParseDuration(val); err != nil {
			return fmt.Errorf("config: invalid duration %s=%q: %w", name, val, err)
		}
	}

	portFields := map[string]string{
		"serve.addr":     cfg.Serve.Addr,
		"serve.tls_addr": cfg.Serve.TLSAddr,
		"tsa.addr":       cfg.TSA.Addr,
		"crl.addr":       cfg.CRL.Addr,
		"ocsp.addr":      cfg.OCSP.Addr,
		"api.addr":       cfg.Serve.APIAddr,
	}
	for name, val := range portFields {
		if val == "" {
			continue
		}
		colon := strings.LastIndex(val, ":")
		if colon < 0 {
			return fmt.Errorf("config: %s=%q missing port", name, val)
		}
		portStr := val[colon+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("config: %s=%q invalid port %q", name, val, portStr)
		}
	}

	// ── Enum checks ──
	enumFields := map[string]struct {
		val  string
		vals []string
	}{
		"hierarchy":            {cfg.Hierarchy, []string{"simple", "complex"}},
		"locale":               {cfg.Locale, []string{"zh", "en"}},
		"serve.log_format":     {cfg.Serve.LogFormat, []string{"text", "json"}},
		"rbac.permission_mode": {cfg.RBAC.PermissionMode, []string{"simple", "enterprise"}},
		"key_backend.type":     {cfg.KeyBackend.Type, []string{"software", "remote_hsm"}},
	}
	for name, f := range enumFields {
		if f.val == "" {
			continue
		}
		valid := false
		for _, v := range f.vals {
			if f.val == v {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("config: invalid %s=%q (must be one of %v)", name, f.val, f.vals)
		}
	}

	// ── serve.log_dest ──
	// Accepts "stderr", "syslog", or "file:/path/to/pki.log" (any path).
	if ld := cfg.Serve.LogDest; ld != "" && ld != "stderr" && ld != "syslog" && !strings.HasPrefix(ld, "file:") {
		return fmt.Errorf("config: invalid serve.log_dest=%q (must be \"stderr\", \"syslog\", or \"file:/path\")", ld)
	}
	if cfg.Persist.Mode != "" && cfg.Persist.Mode != "realtime" && cfg.Persist.Mode != "batch" && cfg.Persist.Mode != "async" {
		return fmt.Errorf("config: invalid persist.mode=%q (must be 'realtime', 'batch', or 'async')", cfg.Persist.Mode)
	}

	// ── URL validation ──
	urlFields := map[string]string{
		"ct_log.url":          cfg.CTLog.URL,
		"webhook.url":         cfg.Webhook.URL,
		"tsa.core_url":        cfg.TSA.CoreURL,
		"key_backend.url":     cfg.KeyBackend.URL,
		"defaults.ocsp_url":   cfg.Defaults.OCSPURL,
		"defaults.issuer_url": cfg.Defaults.IssuerURL,
		"crl.crl_base_url":    cfg.CRL.CRLBaseURL,
	}
	for name, val := range urlFields {
		if val == "" {
			continue
		}
		if _, err := url.Parse(val); err != nil {
			return fmt.Errorf("config: invalid URL %s=%q: %w", name, val, err)
		}
	}
	for i, entry := range cfg.CTLog.Logs {
		if entry.URL != "" {
			if _, err := url.Parse(entry.URL); err != nil {
				return fmt.Errorf("config: ct_log.logs[%d].url=%q: %w", i, entry.URL, err)
			}
		}
	}

	// ── Numeric range checks ──
	if cfg.SMTP.Port != 0 && (cfg.SMTP.Port < 1 || cfg.SMTP.Port > 65535) {
		return fmt.Errorf("config: invalid smtp.port=%d (must be 1-65535)", cfg.SMTP.Port)
	}
	if BoolOr(cfg.RateLimit.Enabled, false) {
		if cfg.RateLimit.Rate <= 0 {
			return fmt.Errorf("config: rate_limit.rate must be > 0 when enabled (got %f)", cfg.RateLimit.Rate)
		}
		if cfg.RateLimit.Burst <= 0 {
			return fmt.Errorf("config: rate_limit.burst must be > 0 when enabled (got %d)", cfg.RateLimit.Burst)
		}
	}
	// Numeric fields: 0 means "use default elsewhere" so only validate
	// explicit non-zero values.
	if cfg.RA.RequiredApprovals < 0 {
		return fmt.Errorf("config: ra.required_approvals=%d must be >= 0", cfg.RA.RequiredApprovals)
	}
	if cfg.CRL.ValidityDays < 0 {
		return fmt.Errorf("config: crl.validity_days=%d must be >= 0", cfg.CRL.ValidityDays)
	}
	if cfg.Defaults.ReportMaxRows < 0 {
		return fmt.Errorf("config: defaults.report_max_rows=%d must be >= 0", cfg.Defaults.ReportMaxRows)
	}
	if BoolOr(cfg.AutoRenew.Enabled, false) {
		if cfg.AutoRenew.WindowDays < 0 {
			return fmt.Errorf("config: auto_renew.window_days=%d must be >= 0", cfg.AutoRenew.WindowDays)
		}
		if cfg.AutoRenew.DefaultValidity < 1 {
			return fmt.Errorf("config: auto_renew.default_validity_days=%d must be >= 1", cfg.AutoRenew.DefaultValidity)
		}
	}
	if BoolOr(cfg.Archive.Enabled, false) && cfg.Archive.RetentionDays < 1 {
		return fmt.Errorf("config: archive.retention_days=%d must be >= 1", cfg.Archive.RetentionDays)
	}

	// ── Nested struct validation (PG / LDAP / Persist / Aggregator) ──
	if cfg.PG.Port != 0 && (cfg.PG.Port < 1 || cfg.PG.Port > 65535) {
		return fmt.Errorf("config: invalid pg.port=%d (must be 1-65535)", cfg.PG.Port)
	}
	if cfg.PG.SSLMode != "" && !validPGSSLMode[cfg.PG.SSLMode] {
		return fmt.Errorf("config: invalid pg.sslmode=%q (must be one of disable, allow, prefer, require, verify-ca, verify-full)", cfg.PG.SSLMode)
	}
	if cfg.LDAP.URL != "" {
		u, err := url.Parse(cfg.LDAP.URL)
		if err != nil {
			return fmt.Errorf("config: invalid ldap.url=%q: %w", cfg.LDAP.URL, err)
		}
		if u.Scheme != "ldap" && u.Scheme != "ldaps" {
			return fmt.Errorf("config: ldap.url=%q must use ldap:// or ldaps:// scheme", cfg.LDAP.URL)
		}
	}
	if cfg.Identity != nil {
		if strings.TrimSpace(cfg.Identity.SourceURL) == "" {
			return fmt.Errorf("config: identity.source_url is required when identity is configured")
		}
		switch cfg.Identity.Type {
		case "", ca.IdentitySourceLDAP, ca.IdentitySourceOAuth:
		default:
			return fmt.Errorf("config: invalid identity.type=%q (must be ldap or oauth)", cfg.Identity.Type)
		}
		if cfg.Identity.Type == ca.IdentitySourceOAuth && (cfg.Identity.Username == "" || cfg.Identity.Password == "") {
			return fmt.Errorf("config: identity.username/password required for identity.type=oauth")
		}
		if cfg.Identity.TimeoutSec < 0 {
			return fmt.Errorf("config: identity.timeout_sec=%d must be >= 0", cfg.Identity.TimeoutSec)
		}
	}
	if cfg.Persist.BatchSize < 0 {
		return fmt.Errorf("config: persist.batch_size=%d must be >= 0", cfg.Persist.BatchSize)
	}
	if cfg.Persist.QueueSize < 0 {
		return fmt.Errorf("config: persist.queue_size=%d must be >= 0", cfg.Persist.QueueSize)
	}
	for name, val := range map[string]int{
		"aggregator.window_ms":   cfg.Aggregator.WindowMs,
		"aggregator.batch_max":   cfg.Aggregator.BatchMax,
		"aggregator.threshold":   cfg.Aggregator.Threshold,
		"aggregator.buffer_size": cfg.Aggregator.BufferSize,
	} {
		if val < 0 {
			return fmt.Errorf("config: %s=%d must be >= 0", name, val)
		}
	}

	// ── Listener conflict detection ──
	if cfg.Serve.Addr != "" && cfg.Serve.TLSAddr != "" && cfg.Serve.Addr == cfg.Serve.TLSAddr {
		return fmt.Errorf("config: serve.addr and serve.tls_addr both %q; same-process listeners must be distinct", cfg.Serve.Addr)
	}
	// Standalone modular listeners (pki serve tsa/ocsp/crl/api): flag a
	// collision only for user-explicit (non-default) addresses, since the
	// default config intentionally shares :8443 across services.
	def := DefaultConfig()
	seen := map[string]string{}
	for _, s := range []struct{ name, addr, def string }{
		{"tsa.addr", cfg.TSA.Addr, def.TSA.Addr},
		{"ocsp.addr", cfg.OCSP.Addr, def.OCSP.Addr},
		{"crl.addr", cfg.CRL.Addr, ""},
		{"serve.api_addr", cfg.Serve.APIAddr, ""},
	} {
		if s.addr == "" || s.addr == s.def {
			continue
		}
		if prev, ok := seen[s.addr]; ok {
			return fmt.Errorf("config: %s and %s both listen on %q (modular services must use distinct ports)", prev, s.name, s.addr)
		}
		seen[s.addr] = s.name
	}

	// ── File path existence (user-explicit, non-default paths only) ──
	checkFile := func(section, path string) error {
		if path == "" {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("config: %s=%q: %w", section, path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("config: %s=%q is a directory, expected a file", section, path)
		}
		return nil
	}
	checkDir := func(section, path string) error {
		if path == "" {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("config: %s=%q: %w", section, path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("config: %s=%q is not a directory", section, path)
		}
		return nil
	}
	// Only validate a field when the user explicitly set it (non-empty and
	// different from the compiled-in default), so that an un-deployed default
	// layout on a dev machine is not rejected.
	paths := []struct {
		section, val, dflt string
		dir                bool
	}{
		{"serve.tls_cert", cfg.Serve.TLSCert, def.Serve.TLSCert, false},
		{"serve.tls_key", cfg.Serve.TLSKey, def.Serve.TLSKey, false},
		{"serve.tls_client_ca", cfg.Serve.TLSClientCA, def.Serve.TLSClientCA, false},
		{"serve.static", cfg.Serve.Static, def.Serve.Static, true},
		{"tsa.signer_cert", cfg.TSA.SignerCert, def.TSA.SignerCert, false},
		{"tsa.signer_key", cfg.TSA.SignerKey, def.TSA.SignerKey, false},
		{"tsa.chain", cfg.TSA.Chain, def.TSA.Chain, false},
		{"tsa.tls_client_cert", cfg.TSA.TLSClientCert, def.TSA.TLSClientCert, false},
		{"tsa.tls_client_key", cfg.TSA.TLSClientKey, def.TSA.TLSClientKey, false},
		{"tsa.tls_ca_cert", cfg.TSA.TLSCACert, def.TSA.TLSCACert, false},
		{"ocsp.signer_cert", cfg.OCSP.SignerCert, def.OCSP.SignerCert, false},
		{"ocsp.signer_key", cfg.OCSP.SignerKey, def.OCSP.SignerKey, false},
		{"policy", cfg.Policy, def.Policy, false},
		{"authorization_file", cfg.AuthorizationFile, def.AuthorizationFile, false},
		{"routes_file", cfg.RoutesFile, def.RoutesFile, false},
		{"capability_schemes", cfg.CapabilitySchemes, def.CapabilitySchemes, true},
		{"crl.output_dir", cfg.CRL.OutputDir, def.CRL.OutputDir, true},
		{"key_backend.tls.cert", cfg.KeyBackend.TLS.Cert, def.KeyBackend.TLS.Cert, false},
		{"key_backend.tls.key", cfg.KeyBackend.TLS.Key, def.KeyBackend.TLS.Key, false},
		{"key_backend.tls.ca_cert", cfg.KeyBackend.TLS.CACert, def.KeyBackend.TLS.CACert, false},
	}
	for _, p := range paths {
		if p.val == "" || p.val == p.dflt {
			continue
		}
		var err error
		if p.dir {
			err = checkDir(p.section, p.val)
		} else {
			err = checkFile(p.section, p.val)
		}
		if err != nil {
			return err
		}
	}
	// Per-CA certificate/key/chain files. When delegating to a remote HSM
	// signer the private keys live on the remote side and are not checked.
	for name, caCfg := range cfg.CAs {
		defCA := def.CAs[name]
		for _, f := range []struct{ field, path string }{
			{"cert", caCfg.Cert},
			{"key", caCfg.Key},
			{"chain", caCfg.Chain},
		} {
			if f.path == "" {
				continue
			}
			switch f.field {
			case "cert":
				if f.path == defCA.Cert {
					continue
				}
			case "key":
				if cfg.KeyBackend.Type == "remote_hsm" || f.path == defCA.Key {
					continue
				}
			case "chain":
				if f.path == defCA.Chain {
					continue
				}
			}
			if err := checkFile("cas."+name+"."+f.field, f.path); err != nil {
				return err
			}
		}
	}

	return nil
}

// ParseOID parses a dot-separated OID string into an asn1.ObjectIdentifier.
// Each component must be in range 0-255 and the OID must have at least 2 components.
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %q: %w", p, err)
		}
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("OID component %d out of range", v)
		}
		oid[i] = v
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("OID must have at least 2 components")
	}
	return oid, nil
}

func DefaultConfig() Config {
	return Config{
		DB: "/etc/varwof/core/pki.db",
		TSA: TSAConfig{
			Addr:       ":8443",
			SignerCert: "/etc/varwof/core/keys/tsa-signer.pem",
			SignerKey:  "/etc/varwof/core/keys/tsa-signer.key",
			Chain:      "/etc/varwof/core/keys/tsa-ca.pem",
		},
		OCSP: OCSPConfig{
			Addr:       ":8443",
			SignerCert: "/etc/varwof/core/keys/ocsp-signer.pem",
			SignerKey:  "/etc/varwof/core/keys/ocsp-signer.key",
			CacheTTL:   "1h",
		},
		CAs: map[string]CAConfig{
			"root":    {Cert: "/etc/varwof/core/keys/root-ca.pem", Key: "/etc/varwof/core/keys/root-ca.key"},
			"issuing": {Cert: "/etc/varwof/core/keys/issuing-ca.pem", Key: "/etc/varwof/core/keys/issuing-ca.key"},
			"tsa":     {Cert: "/etc/varwof/core/keys/tsa-ca.pem", Key: "/etc/varwof/core/keys/tsa-ca.key"},
		},
		RBAC: RBACConfig{
			PermissionMode: "simple",
		},
		Hierarchy: "simple",
		Serve: ServeConfig{
			Addr:               ":8443",
			Static:             "/etc/varwof/core/www",
			ReloadPollInterval: "10s",
			ShutdownTimeout:    "10s",
			AgentSessionMaxTTL: "24h",
			DAMaxTimestampSkew: "30s",
			AuditSalt: AuditSaltConfig{
				Enabled:         BoolPtr(true),
				RetentionDays:   365,
				CleanupInterval: "24h",
			},
			AuditVerify: AuditVerifyConfig{
				Enabled:  BoolPtr(true),
				Interval: "24h",
			},
		},
		Defaults: DefaultsConfig{
			CA:                    "issuing",
			Profile:               "tls-server",
			KeyType:               "ecdsa-p256",
			Hash:                  "sha256",
			DefaultCountry:        "CN",
			DefaultOrg:            "example.com",
			Realm:                 "example.com",
			CertValidity:          "2160h",
			ReportMaxRows:         5000,
			AgentProxyMaxValidity: "1h",
		},
		CRL: CRLConfig{
			ValidityDays: 30,
		},
		RA: RAConfig{
			RequiredApprovals: 1,
			DefaultCA:         "issuing",
			DefaultProfile:    "tls-server",
		},
		RateLimit: RateLimitConfig{
			Enabled: BoolPtr(true),
			Rate:    100,
			Burst:   200,
		},
		Webhook: WebhookConfig{
			Timeout:             "10s",
			ExpiryCheckInterval: "24h",
			ExpiryThresholds:    []int{30, 7, 1},
		},
		AutoRenew: AutoRenewConfig{
			Enabled:         BoolPtr(false),
			Interval:        "24h",
			WindowDays:      30,
			DefaultValidity: 365,
		},
		Archive: ArchiveConfig{
			Enabled:        BoolPtr(false),
			RetentionDays:  365,
			ArchiveExpired: BoolPtr(true),
			ArchiveRevoked: BoolPtr(false),
		},
		LDAP: ca.LDAPConfig{
			Filter:  "(uid=%s)",
			UIDAttr: "uid",
			MapCN:   "cn",
		},
	}
}

func DefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		if pg := os.Getenv("PROGRAMDATA"); pg != "" {
			return filepath.Join(pg, "varwof", "core", "pki.json")
		}
		return filepath.Join(os.Getenv("APPDATA"), "varwof", "core", "pki.json")
	default:
		return "/etc/varwof/core/pki.json"
	}
}

func SearchConfigPath() string {
	home := os.Getenv("HOME")
	candidates := []string{
		"pki.json",
		filepath.Join(home, ".config", "pki", "pki.json"),
		"/etc/varwof/core/pki.json", // priority
		DefaultConfigPath(),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.normalizeDefaults()
	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &cfg, nil
}

// normalizeDefaults synchronizes the legacy defaults.org alias to DefaultOrg
// and fills in missing Realm with a safe default.
func (c *Config) normalizeDefaults() {
	if c.Defaults.Org != "" {
		c.Defaults.DefaultOrg = c.Defaults.Org
	}
	if c.Defaults.Realm == "" {
		c.Defaults.Realm = "example.com"
	}
}

func MergeConfig(base, override *Config) *Config {
	if override == nil {
		return base
	}
	c := *base
	if override.DB != "" {
		c.DB = override.DB
	}
	if override.Locale != "" {
		c.Locale = override.Locale
	}
	if override.TSA.Addr != "" {
		c.TSA.Addr = override.TSA.Addr
	}
	if override.TSA.SignerCert != "" {
		c.TSA.SignerCert = override.TSA.SignerCert
	}
	if override.TSA.SignerKey != "" {
		c.TSA.SignerKey = override.TSA.SignerKey
	}
	if override.TSA.Chain != "" {
		c.TSA.Chain = override.TSA.Chain
	}
	if override.TSA.TSAPolicy != "" {
		c.TSA.TSAPolicy = override.TSA.TSAPolicy
	}
	if override.TSA.Ordering != nil {
		c.TSA.Ordering = override.TSA.Ordering
	}
	if override.TSA.AccuracySeconds != 0 {
		c.TSA.AccuracySeconds = override.TSA.AccuracySeconds
	}
	if override.TSA.AccuracyMillis != 0 {
		c.TSA.AccuracyMillis = override.TSA.AccuracyMillis
	}
	if override.TSA.AccuracyMicros != 0 {
		c.TSA.AccuracyMicros = override.TSA.AccuracyMicros
	}
	if override.TSA.CoreURL != "" {
		c.TSA.CoreURL = override.TSA.CoreURL
	}
	if override.TSA.CAName != "" {
		c.TSA.CAName = override.TSA.CAName
	}
	if override.TSA.ValidityDays != 0 {
		c.TSA.ValidityDays = override.TSA.ValidityDays
	}
	if override.TSA.RenewalWindow != "" {
		c.TSA.RenewalWindow = override.TSA.RenewalWindow
	}
	if override.TSA.CheckInterval != "" {
		c.TSA.CheckInterval = override.TSA.CheckInterval
	}
	if override.TSA.TLSClientCert != "" {
		c.TSA.TLSClientCert = override.TSA.TLSClientCert
	}
	if override.TSA.TLSClientKey != "" {
		c.TSA.TLSClientKey = override.TSA.TLSClientKey
	}
	if override.TSA.TLSCACert != "" {
		c.TSA.TLSCACert = override.TSA.TLSCACert
	}
	if override.OCSP.Addr != "" {
		c.OCSP.Addr = override.OCSP.Addr
	}
	if override.OCSP.SignerCert != "" {
		c.OCSP.SignerCert = override.OCSP.SignerCert
	}
	if override.OCSP.SignerKey != "" {
		c.OCSP.SignerKey = override.OCSP.SignerKey
	}
	if override.OCSP.NextUpdate != "" {
		c.OCSP.NextUpdate = override.OCSP.NextUpdate
	}
	if override.OCSP.CacheSize != 0 {
		c.OCSP.CacheSize = override.OCSP.CacheSize
	}
	if override.OCSP.CacheTTL != "" {
		c.OCSP.CacheTTL = override.OCSP.CacheTTL
	}
	if override.OCSP.CacheFile != "" {
		c.OCSP.CacheFile = override.OCSP.CacheFile
	}
	if override.Defaults.CA != "" {
		c.Defaults.CA = override.Defaults.CA
	}
	if override.Defaults.Profile != "" {
		c.Defaults.Profile = override.Defaults.Profile
	}
	if override.Defaults.KeyType != "" {
		c.Defaults.KeyType = override.Defaults.KeyType
	}
	if override.Defaults.Hash != "" {
		c.Defaults.Hash = override.Defaults.Hash
	}
	if override.Defaults.DefaultCountry != "" {
		c.Defaults.DefaultCountry = override.Defaults.DefaultCountry
	}
	if override.Defaults.DefaultOrg != "" {
		c.Defaults.DefaultOrg = override.Defaults.DefaultOrg
	}
	if override.Defaults.Org != "" {
		c.Defaults.DefaultOrg = override.Defaults.Org
	}
	if override.Defaults.Realm != "" {
		c.Defaults.Realm = override.Defaults.Realm
	}
	if override.Defaults.CertValidity != "" {
		c.Defaults.CertValidity = override.Defaults.CertValidity
	}
	if override.Defaults.OCSPURL != "" {
		c.Defaults.OCSPURL = override.Defaults.OCSPURL
	}
	if override.Defaults.IssuerURL != "" {
		c.Defaults.IssuerURL = override.Defaults.IssuerURL
	}
	if len(override.Defaults.IssuerAltNames) > 0 {
		c.Defaults.IssuerAltNames = override.Defaults.IssuerAltNames
	}
	if len(override.Defaults.SubjectInfoAccess) > 0 {
		c.Defaults.SubjectInfoAccess = override.Defaults.SubjectInfoAccess
	}
	if len(override.Defaults.PolicyOIDs) > 0 {
		c.Defaults.PolicyOIDs = override.Defaults.PolicyOIDs
	}
	if len(override.Defaults.PolicyMappings) > 0 {
		c.Defaults.PolicyMappings = override.Defaults.PolicyMappings
	}
	if override.Defaults.RequireExplicitPolicy != nil {
		c.Defaults.RequireExplicitPolicy = override.Defaults.RequireExplicitPolicy
	}
	if override.Defaults.InhibitPolicyMapping != nil {
		c.Defaults.InhibitPolicyMapping = override.Defaults.InhibitPolicyMapping
	}
	if override.Defaults.InhibitAnyPolicy != nil {
		c.Defaults.InhibitAnyPolicy = override.Defaults.InhibitAnyPolicy
	}
	if override.Defaults.ReportMaxRows != 0 {
		c.Defaults.ReportMaxRows = override.Defaults.ReportMaxRows
	}
	if override.Defaults.AgentProxyMaxValidity != "" {
		c.Defaults.AgentProxyMaxValidity = override.Defaults.AgentProxyMaxValidity
	}
	if override.Serve.Addr != "" {
		c.Serve.Addr = override.Serve.Addr
	}
	if override.Serve.APIAddr != "" {
		c.Serve.APIAddr = override.Serve.APIAddr
	}
	if override.Serve.TLSAddr != "" {
		c.Serve.TLSAddr = override.Serve.TLSAddr
	}
	if override.Serve.TLSCert != "" {
		c.Serve.TLSCert = override.Serve.TLSCert
	}
	if override.Serve.TLSKey != "" {
		c.Serve.TLSKey = override.Serve.TLSKey
	}
	if override.Serve.TLSClientCA != "" {
		c.Serve.TLSClientCA = override.Serve.TLSClientCA
	}
	if override.Serve.AuthUsername != "" {
		c.Serve.AuthUsername = override.Serve.AuthUsername
	}
	if override.Serve.AuthPassword != "" {
		c.Serve.AuthPassword = override.Serve.AuthPassword
	}
	if override.Serve.Static != "" {
		c.Serve.Static = override.Serve.Static
	}
	if override.Serve.ReloadPollInterval != "" {
		c.Serve.ReloadPollInterval = override.Serve.ReloadPollInterval
	}
	if override.Serve.ShutdownTimeout != "" {
		c.Serve.ShutdownTimeout = override.Serve.ShutdownTimeout
	}
	if override.Serve.MetricsEnabled != nil {
		c.Serve.MetricsEnabled = override.Serve.MetricsEnabled
	}
	if override.Serve.LogFormat != "" {
		c.Serve.LogFormat = override.Serve.LogFormat
	}
	if override.Serve.LogDest != "" {
		c.Serve.LogDest = override.Serve.LogDest
	}
	if override.Serve.AgentSessionMaxTTL != "" {
		c.Serve.AgentSessionMaxTTL = override.Serve.AgentSessionMaxTTL
	}
	if override.Serve.DAMaxTimestampSkew != "" {
		c.Serve.DAMaxTimestampSkew = override.Serve.DAMaxTimestampSkew
	}
	if len(override.Serve.TrustedGatewayOUs) > 0 {
		c.Serve.TrustedGatewayOUs = append([]string(nil), override.Serve.TrustedGatewayOUs...)
	}
	if override.Serve.AuditSalt.Enabled != nil {
		c.Serve.AuditSalt.Enabled = override.Serve.AuditSalt.Enabled
	}
	if override.Serve.AuditSalt.RetentionDays > 0 {
		c.Serve.AuditSalt.RetentionDays = override.Serve.AuditSalt.RetentionDays
	}
	if override.Serve.AuditSalt.CleanupInterval != "" {
		c.Serve.AuditSalt.CleanupInterval = override.Serve.AuditSalt.CleanupInterval
	}
	if override.Serve.AuditVerify.Enabled != nil {
		c.Serve.AuditVerify.Enabled = override.Serve.AuditVerify.Enabled
	}
	if override.Serve.AuditVerify.Interval != "" {
		c.Serve.AuditVerify.Interval = override.Serve.AuditVerify.Interval
	}
	if override.CRL.Addr != "" {
		c.CRL.Addr = override.CRL.Addr
	}
	if override.CRL.ValidityDays > 0 {
		c.CRL.ValidityDays = override.CRL.ValidityDays
	}
	if override.CRL.RenewInterval != "" {
		c.CRL.RenewInterval = override.CRL.RenewInterval
	}
	if override.CRL.Partitions > 0 {
		c.CRL.Partitions = override.CRL.Partitions
	}
	if override.CRL.OutputDir != "" {
		c.CRL.OutputDir = override.CRL.OutputDir
	}
	if override.CRL.CRLBaseURL != "" {
		c.CRL.CRLBaseURL = override.CRL.CRLBaseURL
	}
	if override.CRL.AutoRenew != "" {
		c.CRL.AutoRenew = override.CRL.AutoRenew
	}
	if override.Webhook.URL != "" {
		c.Webhook.URL = override.Webhook.URL
	}
	if override.Webhook.Timeout != "" {
		c.Webhook.Timeout = override.Webhook.Timeout
	}
	if override.Webhook.ExpiryCheckInterval != "" {
		c.Webhook.ExpiryCheckInterval = override.Webhook.ExpiryCheckInterval
	}
	if len(override.Webhook.ExpiryThresholds) > 0 {
		c.Webhook.ExpiryThresholds = override.Webhook.ExpiryThresholds
	}
	for name, ca := range override.CAs {
		if c.CAs == nil {
			c.CAs = make(map[string]CAConfig)
		}
		existing := c.CAs[name]
		if ca.Cert != "" {
			existing.Cert = ca.Cert
		}
		if ca.Key != "" {
			existing.Key = ca.Key
		}
		if ca.Chain != "" {
			existing.Chain = ca.Chain
		}
		if ca.Password != "" {
			existing.Password = ca.Password
		}
		c.CAs[name] = existing
	}
	if override.RA.RequiredApprovals != 0 {
		c.RA.RequiredApprovals = override.RA.RequiredApprovals
	}
	if override.RA.DefaultCA != "" {
		c.RA.DefaultCA = override.RA.DefaultCA
	}
	if override.RA.DefaultProfile != "" {
		c.RA.DefaultProfile = override.RA.DefaultProfile
	}
	if override.KeyBackend.Type != "" {
		c.KeyBackend.Type = override.KeyBackend.Type
	}
	if override.KeyBackend.URL != "" {
		c.KeyBackend.URL = override.KeyBackend.URL
	}
	if override.KeyBackend.KeyAlias != "" {
		c.KeyBackend.KeyAlias = override.KeyBackend.KeyAlias
	}
	if override.KeyBackend.TLS.Cert != "" {
		c.KeyBackend.TLS.Cert = override.KeyBackend.TLS.Cert
	}
	if override.KeyBackend.TLS.Key != "" {
		c.KeyBackend.TLS.Key = override.KeyBackend.TLS.Key
	}
	if override.KeyBackend.TLS.CACert != "" {
		c.KeyBackend.TLS.CACert = override.KeyBackend.TLS.CACert
	}
	if override.KeyBackend.Token != "" {
		c.KeyBackend.Token = override.KeyBackend.Token
	}
	if override.RateLimit.Enabled != nil {
		c.RateLimit.Enabled = override.RateLimit.Enabled
	}
	if override.RateLimit.Rate != 0 {
		c.RateLimit.Rate = override.RateLimit.Rate
	}
	if override.RateLimit.Burst != 0 {
		c.RateLimit.Burst = override.RateLimit.Burst
	}
	if override.LDAP.URL != "" {
		c.LDAP.URL = override.LDAP.URL
	}
	if override.LDAP.BindDN != "" {
		c.LDAP.BindDN = override.LDAP.BindDN
	}
	if override.LDAP.BindPassword != "" {
		c.LDAP.BindPassword = override.LDAP.BindPassword
	}
	if override.LDAP.BaseDN != "" {
		c.LDAP.BaseDN = override.LDAP.BaseDN
	}
	if override.LDAP.Filter != "" {
		c.LDAP.Filter = override.LDAP.Filter
	}
	if override.LDAP.UIDAttr != "" {
		c.LDAP.UIDAttr = override.LDAP.UIDAttr
	}
	if override.LDAP.MapCN != "" {
		c.LDAP.MapCN = override.LDAP.MapCN
	}
	if override.LDAP.MapOrg != "" {
		c.LDAP.MapOrg = override.LDAP.MapOrg
	}
	if override.LDAP.MapOU != "" {
		c.LDAP.MapOU = override.LDAP.MapOU
	}
	if override.LDAP.MapL != "" {
		c.LDAP.MapL = override.LDAP.MapL
	}
	if override.LDAP.MapST != "" {
		c.LDAP.MapST = override.LDAP.MapST
	}
	if override.LDAP.MapC != "" {
		c.LDAP.MapC = override.LDAP.MapC
	}
	if override.LDAP.MapEmail != "" {
		c.LDAP.MapEmail = override.LDAP.MapEmail
	}
	if override.Identity != nil {
		if c.Identity == nil {
			c.Identity = &ca.IdentitySourceConfig{}
		}
		if override.Identity.Type != "" {
			c.Identity.Type = override.Identity.Type
		}
		if override.Identity.SourceURL != "" {
			c.Identity.SourceURL = override.Identity.SourceURL
		}
		if override.Identity.Token != "" {
			c.Identity.Token = override.Identity.Token
		}
		if override.Identity.Source != "" {
			c.Identity.Source = override.Identity.Source
		}
		if override.Identity.Username != "" {
			c.Identity.Username = override.Identity.Username
		}
		if override.Identity.Password != "" {
			c.Identity.Password = override.Identity.Password
		}
		if override.Identity.TimeoutSec != 0 {
			c.Identity.TimeoutSec = override.Identity.TimeoutSec
		}
		if override.Identity.DefaultOU != "" {
			c.Identity.DefaultOU = override.Identity.DefaultOU
		}
		if override.Identity.DisabledOK {
			c.Identity.DisabledOK = true
		}
		if len(override.Identity.OUFromGroups) > 0 {
			if c.Identity.OUFromGroups == nil {
				c.Identity.OUFromGroups = make(map[string]string)
			}
			for k, v := range override.Identity.OUFromGroups {
				c.Identity.OUFromGroups[k] = v
			}
		}
	}
	if override.KeyEscrow.AdminPublicKey != "" {
		c.KeyEscrow.AdminPublicKey = override.KeyEscrow.AdminPublicKey
	}
	if override.CTLog.URL != "" {
		c.CTLog.URL = override.CTLog.URL
	}
	if override.CTLog.APIKey != "" {
		c.CTLog.APIKey = override.CTLog.APIKey
	}
	if override.CTLog.PublicKey != "" {
		c.CTLog.PublicKey = override.CTLog.PublicKey
	}
	if len(override.CTLog.Logs) > 0 {
		c.CTLog.Logs = override.CTLog.Logs
	}
	if override.AutoRenew.Enabled != nil {
		c.AutoRenew.Enabled = override.AutoRenew.Enabled
	}
	if override.AutoRenew.Interval != "" {
		c.AutoRenew.Interval = override.AutoRenew.Interval
	}
	if override.AutoRenew.WindowDays != 0 {
		c.AutoRenew.WindowDays = override.AutoRenew.WindowDays
	}
	if override.AutoRenew.DefaultValidity != 0 {
		c.AutoRenew.DefaultValidity = override.AutoRenew.DefaultValidity
	}
	if len(override.AutoRenew.Profiles) > 0 {
		c.AutoRenew.Profiles = override.AutoRenew.Profiles
	}
	if len(override.AutoRenew.ExcludeCAs) > 0 {
		c.AutoRenew.ExcludeCAs = override.AutoRenew.ExcludeCAs
	}
	if override.AutoRenew.NotifyOnly != nil {
		c.AutoRenew.NotifyOnly = override.AutoRenew.NotifyOnly
	}
	if override.AutoRenew.MaxRenewals != 0 {
		c.AutoRenew.MaxRenewals = override.AutoRenew.MaxRenewals
	}
	if override.Archive.Enabled != nil {
		c.Archive.Enabled = override.Archive.Enabled
	}
	if override.Archive.RetentionDays != 0 {
		c.Archive.RetentionDays = override.Archive.RetentionDays
	}
	if len(override.Archive.ExcludeCAs) > 0 {
		c.Archive.ExcludeCAs = override.Archive.ExcludeCAs
	}
	if override.Archive.ArchiveExpired != nil {
		c.Archive.ArchiveExpired = override.Archive.ArchiveExpired
	}
	if override.Archive.ArchiveRevoked != nil {
		c.Archive.ArchiveRevoked = override.Archive.ArchiveRevoked
	}
	if len(override.TrustBridge.Bridges) > 0 {
		c.TrustBridge.Bridges = override.TrustBridge.Bridges
	}
	if override.SMTP.Host != "" {
		c.SMTP.Host = override.SMTP.Host
	}
	if override.SMTP.Port != 0 {
		c.SMTP.Port = override.SMTP.Port
	}
	if override.SMTP.Username != "" {
		c.SMTP.Username = override.SMTP.Username
	}
	if override.SMTP.Password != "" {
		c.SMTP.Password = override.SMTP.Password
	}
	if override.SMTP.From != "" {
		c.SMTP.From = override.SMTP.From
	}
	if override.SMTP.To != "" {
		c.SMTP.To = override.SMTP.To
	}
	if override.SMTP.TLS != nil {
		c.SMTP.TLS = override.SMTP.TLS
	}
	if override.SMTP.InsecureSkipVerify != nil {
		c.SMTP.InsecureSkipVerify = override.SMTP.InsecureSkipVerify
	}
	if override.SMTP.Events != "" {
		c.SMTP.Events = override.SMTP.Events
	}
	if override.Policy != "" {
		c.Policy = override.Policy
	}
	if override.EnforcePolicy != nil {
		c.EnforcePolicy = override.EnforcePolicy
	}
	if override.AuthorizationFile != "" {
		c.AuthorizationFile = override.AuthorizationFile
	}
	if override.RoutesFile != "" {
		c.RoutesFile = override.RoutesFile
	}
	if override.CapabilitySchemes != "" {
		c.CapabilitySchemes = override.CapabilitySchemes
	}
	if override.PolicySigning.Enabled {
		c.PolicySigning = override.PolicySigning
	} else if override.PolicySigning.CAFile != "" || override.PolicySigning.SigSuffix != "" {
		c.PolicySigning.Enabled = override.PolicySigning.Enabled
		c.PolicySigning.CAFile = override.PolicySigning.CAFile
		c.PolicySigning.RequireAdminOU = override.PolicySigning.RequireAdminOU
		c.PolicySigning.Require = override.PolicySigning.Require
		c.PolicySigning.SigSuffix = override.PolicySigning.SigSuffix
	}
	if override.Hierarchy != "" {
		c.Hierarchy = override.Hierarchy
	}
	if override.PG.Host != "" {
		c.PG.Host = override.PG.Host
	}
	if override.PG.Port != 0 {
		c.PG.Port = override.PG.Port
	}
	if override.PG.User != "" {
		c.PG.User = override.PG.User
	}
	if override.PG.Password != "" {
		c.PG.Password = override.PG.Password
	}
	if override.PG.DBName != "" {
		c.PG.DBName = override.PG.DBName
	}
	if override.PG.SSLMode != "" {
		c.PG.SSLMode = override.PG.SSLMode
	}
	if override.PG.DSN != "" {
		c.PG.DSN = override.PG.DSN
	}
	if override.RBAC.Enabled != nil {
		c.RBAC.Enabled = override.RBAC.Enabled
	}
	if override.RBAC.PermissionMode != "" {
		c.RBAC.PermissionMode = override.RBAC.PermissionMode
	}
	if len(override.RBAC.CAScopes) > 0 {
		c.RBAC.CAScopes = override.RBAC.CAScopes
	}
	if override.Persist.Mode != "" {
		c.Persist.Mode = override.Persist.Mode
	}
	if override.Persist.BatchSize != 0 {
		c.Persist.BatchSize = override.Persist.BatchSize
	}
	if override.Persist.BatchInterval != "" {
		c.Persist.BatchInterval = override.Persist.BatchInterval
	}
	if override.Persist.QueueSize != 0 {
		c.Persist.QueueSize = override.Persist.QueueSize
	}
	if override.Persist.BufferDB != "" {
		c.Persist.BufferDB = override.Persist.BufferDB
	}
	if override.Aggregator.WindowMs != 0 {
		c.Aggregator.WindowMs = override.Aggregator.WindowMs
	}
	if override.Aggregator.BatchMax != 0 {
		c.Aggregator.BatchMax = override.Aggregator.BatchMax
	}
	if override.Aggregator.Threshold != 0 {
		c.Aggregator.Threshold = override.Aggregator.Threshold
	}
	if override.Aggregator.BufferSize != 0 {
		c.Aggregator.BufferSize = override.Aggregator.BufferSize
	}
	if override.RecordBuffer.Disable {
		c.RecordBuffer.Disable = override.RecordBuffer.Disable
	}
	if override.RecordBuffer.Threshold != 0 {
		c.RecordBuffer.Threshold = override.RecordBuffer.Threshold
	}
	if override.RecordBuffer.MaxPending != nil {
		c.RecordBuffer.MaxPending = override.RecordBuffer.MaxPending
	}
	if override.RecordBuffer.MaxLatency != "" {
		c.RecordBuffer.MaxLatency = override.RecordBuffer.MaxLatency
	}
	if override.Engine != nil {
		c.Engine = override.Engine
	}
	if override.SPIFFE != nil {
		c.SPIFFE = override.SPIFFE
	}
	return &c
}

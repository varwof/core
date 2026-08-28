// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal/remotesigner"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/varwof/engine/db"
	pki "github.com/varwof/types"
)

type Profile string

const (
	ProfileRootCA      Profile = "root-ca"
	ProfileSubCA       Profile = "sub-ca"
	ProfilePolicyCA    Profile = "policy-ca"
	ProfileTLSServer   Profile = "tls-server"
	ProfileTLSClient   Profile = "tls-client"
	ProfileOCSPSigner  Profile = "ocsp-signer"
	ProfileTimestamp   Profile = "timestamp"
	ProfileCodeSigning Profile = "codesigning"
	ProfileEmail       Profile = "email"
	ProfileDocument    Profile = "document"
	ProfileAgentProxy  Profile = "agent-proxy"
	ProfileCMP         Profile = "cmp"

	// ProfileIdentityUser is a person's base identity certificate issued
	// automatically from a directory/identity source (bridge-ldap lookup or
	// bridge-oauth userinfo). CN/OU/email are filled from the identity source;
	// used by the serve layer with IdentitySourceConfig.
	ProfileIdentityUser Profile = "identity-user"

	// VPN certificate templates: used for mTLS-based VPN channels such as WireGuard/OpenVPN.
	// vpn-client is ClientAuth only (client certificate); vpn-server includes ServerAuth+ClientAuth
	// (server certificate, also allows client-side verification for mutual authentication).
	ProfileVPNClient Profile = "vpn-client"
	ProfileVPNServer Profile = "vpn-server"

	// Management certificate templates (m-*): built-in PKI management role certificate presets.
	// Automatically sets OU + ClientAuth EKU + DigitalSignature KU;
	// at issuance, only profile and CN need to be specified, no need to manually pass OU.
	ProfileMSuperAdmin Profile = "m-superadmin"
	ProfileMAdmin      Profile = "m-admin"
	ProfileMOperator   Profile = "m-operator"
	ProfileMRevoker    Profile = "m-revoker"
	ProfileMAuditor    Profile = "m-auditor"
	ProfileMReadonly   Profile = "m-readonly"
	ProfileMConsole    Profile = "m-console"
	ProfileMAutoRenew  Profile = "m-auto-renew"
	ProfileMReporter   Profile = "m-reporter"
)

type SignConfig struct {
	DB                *db.DB
	SkipDB            bool // true = issue only, no DB write (high-throughput batch mode, caller responsible for persistence)
	CAKey             crypto.Signer
	CACert            *x509.Certificate
	CAName            string
	SubjectPubKey     any
	Profile           Profile
	CommonName        string
	Subject           *pkix.Name
	SANs              []string
	CAScope           []string
	KeyType           string
	Hash              string
	CRLBaseURL        string
	OCSPURL           string
	IssuerURL         string
	Validity          time.Duration
	DefaultCountry    string
	DefaultOrg        string
	IssuerAltNames    []string
	SubjectInfoAccess []string
	PolicyOIDs        []string
	// PolicyMappings is the RFC 5280 §4.2.1.5 Policy Mappings extension,
	// each item maps issuerDomainPolicy to subjectDomainPolicy, allowed only in CA certificates
	// (enterprise bridge / cross-domain trust scenarios).
	PolicyMappings []PolicyMapping
	// RequireExplicitPolicy is the RFC 5280 §4.2.1.11 Policy Constraints
	// requireExplicitPolicy (skipCerts count). nil means this field is not generated.
	RequireExplicitPolicy *int
	// InhibitPolicyMapping is the RFC 5280 §4.2.1.11 Policy Constraints
	// inhibitPolicyMapping (skipCerts count). nil means this field is not generated.
	InhibitPolicyMapping *int
	// InhibitAnyPolicy is the RFC 5280 §4.2.1.14 Inhibit anyPolicy extension's skipCerts
	// count (0 means anyPolicy is prohibited on this certificate chain). nil means this extension is not generated.
	InhibitAnyPolicy  *int
	DedupCN           bool
	MaxPathLen        int
	ExtraEKUOIDs      []string
	MustStaple        bool
	CRLPartitions     int
	NotBefore         *time.Time
	NotAfter          *time.Time
	PermittedDomains  []string
	ExcludedDomains   []string
	PermittedEmails   []string
	ExcludedEmails    []string
	PermittedURIs     []string
	ExcludedURIs      []string
	PermittedIPRanges []string
	ExcludedIPRanges  []string
	Policy            *Policy
	PolicyFile        string
	// RequirePolicy (M4 fix): when true and no issuance policy is loaded, Sign()
	// rejects issuance instead of warn-and-continue. The serve layer derives it
	// from config enforce_policy. Library consumers may set it explicitly.
	RequirePolicy          bool
	AIC                    *AICConfig                    // Agent Identity Certificate configuration
	PrincipalAuthorization *PrincipalAuthorizationConfig // user authorization
	Scope                  string                        // admin scope: which CAs this admin can manage (comma-separated)
	// MaxAgentProxyValidity is the hard upper bound for agent-proxy (authorized mode)
	// certificate validity. 0 uses DefaultAgentProxyMaxValidity (1h); spec P1-B-09/25 and
	// P2-A-04's "authorized certificate validity ≤24h" semantics — default 1h, can be relaxed
	// up to ≤24h via configuration.
	MaxAgentProxyValidity time.Duration

	// ValidateCapabilities is an optional AIC capability registration validation hook.
	// Injected by the upper layer (serve layer): passes the full identifiers of capabilities
	// declared in the AIC ("scheme:capability_id" list) to the register capability registry
	// for validation; returns an error if issuance should fail. nil means skip this validation
	// (capability registration validation not enabled, backward compatible).
	ValidateCapabilities func(caps []string) error

	// UserCert is the DA signer (user) certificate whose SPKI hash must match
	// AIC.PrincipalUid.KeyHash. When set (and AIC is non-nil), Sign() verifies
	// the DelegationAuthorization signature at the library layer (M5 fix) — so
	// library consumers cannot mint AIC certificates carrying unverified DA
	// evidence. nil skips the check (serve-layer callers that verified already
	// may leave it unset; supplying it is always safe — verification is idempotent).
	UserCert *x509.Certificate

	// ConsumeDANonce is an optional anti-replay hook called once with the DA nonce
	// after DA signature verification passes. Injected by the serve layer (engine or
	// DB store); library consumers that need replay protection may supply their own.
	// nil skips nonce consumption (no persistence → replayable).
	ConsumeDANonce func(nonce []byte) error
}

// DefaultAgentProxyMaxValidity is the default hard upper bound for agent-proxy certificate validity (1 hour).
const DefaultAgentProxyMaxValidity = 1 * time.Hour

// MaxAgentProxyValidity is the spec-mandated hard ceiling for agent-proxy
// (authorized mode) certificate validity. Per AIC spec §3.4, agent sessions must
// not exceed 24 hours. M2 fix: this bound is enforced at the CA library layer so
// it cannot be silently bypassed by any caller-supplied configuration.
const MaxAgentProxyValidity = 24 * time.Hour

// MaxAgentProxyValidityLimit returns the effective agent-proxy validity upper bound.
// M2 fix: any positive configured value is capped at the spec ceiling (24h);
// 0/negative falls back to the 1h default.
func (sc *SignConfig) MaxAgentProxyValidityLimit() time.Duration {
	if sc == nil || sc.MaxAgentProxyValidity <= 0 {
		return DefaultAgentProxyMaxValidity
	}
	if sc.MaxAgentProxyValidity > MaxAgentProxyValidity {
		return MaxAgentProxyValidity
	}
	return sc.MaxAgentProxyValidity
}

type SignResult struct {
	Cert       *x509.Certificate
	CertDER    []byte
	SerialHex  string
	PrivateKey crypto.Signer
	// Record is the DB record for this certificate. In SkipDB mode, the database is not
	// written; the caller is responsible for persistence (e.g. via RecordBuffer batch
	// persistence); also populated in synchronous write mode.
	Record *db.CertRecord
}

func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case "sm2":
		if sm2Supported {
			return generateSM2Key()
		}
		return nil, fmt.Errorf("SM2 not supported: build with -tags gmsm")
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// MinRSAKeySize is the minimum RSA key length (bits) allowed for signing.
// Issuance is rejected below this value to prevent weak keys (NIST SP 800-57 / MLPS 2.0).
const MinRSAKeySize = 2048

// forbiddenECCurves are weak elliptic curves not allowed in issued certificates (not recommended by NIST).
var forbiddenECCurves = map[elliptic.Curve]string{
	elliptic.P224(): "P-224",
	// Weaker curves like P-192 / sect163k1 cannot be constructed via Go stdlib,
	// but to prevent bypass: explicitly verify the curve OID is not in the allowed list.
}

// allowedECCurves is the whitelist of allowed elliptic curves (NIST P-256/P-384/P-521).
var allowedECCurves = map[elliptic.Curve]string{
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

// CheckPublicKeyStrength validates the strength of the public key to be signed, rejecting weak keys.
// Rules:
//   - RSA < MinRSAKeySize: reject
//   - EC curve not in NIST P-256/P-384/P-521 whitelist: reject
//   - Ed25519: always accept
//   - Unknown type: return warning (non-blocking, to prevent compatibility regression)
func CheckPublicKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSAKeySize {
			return fmt.Errorf("weak RSA key: %d bits < minimum %d bits (NIST SP 800-57)", k.N.BitLen(), MinRSAKeySize)
		}
		return nil
	case *ecdsa.PublicKey:
		if _, ok := allowedECCurves[k.Curve]; ok {
			return nil
		}
		if name, forbidden := forbiddenECCurves[k.Curve]; forbidden {
			return fmt.Errorf("weak EC curve: %s not allowed (NIST rejects legacy curves)", name)
		}
		return fmt.Errorf("EC curve not in allowed set (P-256/P-384/P-521)")
	case ed25519.PublicKey:
		return nil
	default:
		return nil
	}
}

func randomSerial() (*big.Int, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("rand read: %w", err)
	}
	// Ensure positive number (RFC 5280 §4.1.2.2)
	buf[0] &= 0x7f
	return new(big.Int).SetBytes(buf), nil
}

func buildCertTemplate(sc *SignConfig, serial *big.Int) *x509.Certificate {
	now := time.Now()
	country := sc.DefaultCountry
	if country == "" {
		country = "CN"
	}
	org := sc.DefaultOrg
	if org == "" {
		org = "example.com"
	}
	subject := pkix.Name{
		CommonName:   sc.CommonName,
		Country:      []string{country},
		Organization: []string{org},
	}
	if sc.Subject != nil {
		subject = *sc.Subject
		if subject.CommonName == "" {
			subject.CommonName = sc.CommonName
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.Add(sc.Validity),
	}

	if sc.NotBefore != nil {
		tmpl.NotBefore = *sc.NotBefore
	}
	if sc.NotAfter != nil {
		tmpl.NotAfter = *sc.NotAfter
	}

	// M1 fix: clip NotAfter to the CA cert's own validity. Certificates/sub-CAs
	// must not outlive their issuer — otherwise CA rotation silently breaks chains.
	if sc.CACert != nil && tmpl.NotAfter.After(sc.CACert.NotAfter) {
		tmpl.NotAfter = sc.CACert.NotAfter
	}
	// Also ensure NotBefore >= CA NotBefore and NotBefore < NotAfter.
	if sc.CACert != nil && tmpl.NotBefore.Before(sc.CACert.NotBefore) {
		tmpl.NotBefore = sc.CACert.NotBefore
	}
	if !tmpl.NotBefore.Before(tmpl.NotAfter) {
		// Fallback: clamp to a sane window (NotBefore + 1h) instead of producing an invalid cert.
		tmpl.NotAfter = tmpl.NotBefore.Add(time.Hour)
	}

	tmpl.SubjectKeyId = []byte{}
	tmpl.AuthorityKeyId = []byte{}
	return tmpl
}

func Sign(sc *SignConfig) (*SignResult, error) {
	// Work on a local shallow copy: Sign must never mutate the caller's shared
	// *SignConfig (Policy / PrincipalAuthorization are set lazily below), which
	// would be a cross-goroutine data race and non-idempotent when the same
	// config is reused.
	scCopy := *sc
	sc = &scCopy

	// Serial-independent validation runs once, outside the retry loop.
	if sc.PolicyFile != "" && sc.Policy == nil {
		p, err := LoadPolicy(sc.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("policy load: %w", err)
		}
		sc.Policy = p
	}
	if sc.Policy == nil {
		if sc.RequirePolicy {
			// M4 fix: enforcement mode — unconfigured issuance policy is a hard
			// error (fail-closed) so CN/SAN restrictions cannot silently lapse.
			return nil, fmt.Errorf("policy: no issuance policy configured but enforce_policy=true; " +
				"set policy (policy.json) or disable enforce_policy")
		}
		// G-13: no issuance policy configured — CN/SAN restrictions are
		// NOT enforced. Surface the gap so operators enable one explicitly
		// (e.g. via policy.json referenced by SignConfig.PolicyFile).
		slog.Warn("ca/sign: no issuance policy configured; CN/SAN restrictions are NOT enforced",
			"ca", sc.CAName, "profile", sc.Profile)
	}
	if err := CheckPolicy(sc); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	// Key strength validation: reject weak RSA / weak EC curves (NIST SP 800-57).
	// One-time check before retry loop (does not depend on serial).
	subjKey := sc.SubjectPubKey
	if subjKey == nil {
		subjKey = sc.CAKey.Public()
	}
	if err := CheckPublicKeyStrength(subjKey); err != nil {
		return nil, fmt.Errorf("subject key strength: %w", err)
	}

	// Spec §3.4 Rule 2: Pre-issuance PrincipalAuthorization validation.
	// Only validated here when PA has explicit grants; empty grants are derived by applyProfile
	// and validated a second time.
	if sc.AIC != nil && sc.PrincipalAuthorization != nil && len(sc.PrincipalAuthorization.Grants) > 0 {
		if err := validatePrincipalAuthForAIC(sc.AIC, sc.PrincipalAuthorization); err != nil {
			return nil, fmt.Errorf("principal authorization validation: %w", err)
		}
	}

	// M5 fix: DA signature verification at the library layer. When the DA signer
	// certificate is supplied, the DelegationAuthorization evidence is verified
	// here — regardless of caller (server API or library consumer). Anti-replay
	// (nonce consumption) runs after verification when a hook is configured.
	if sc.AIC != nil && sc.UserCert != nil {
		if err := VerifyDelegationAuthorization(sc.UserCert, sc.AIC); err != nil {
			return nil, fmt.Errorf("delegation authorization validation: %w", err)
		}
		if sc.ConsumeDANonce != nil && sc.AIC.DelegationAuthorization != nil {
			if err := sc.ConsumeDANonce(sc.AIC.DelegationAuthorization.Nonce); err != nil {
				return nil, fmt.Errorf("delegation authorization nonce: %w", err)
			}
		}
	}
	// Capability registration validation (single source of truth from register):
	// AIC-declared capabilities must be registered.
	// Hook is injected by the serve layer; nil means not enabled (backward compatible).
	if sc.AIC != nil && sc.ValidateCapabilities != nil {
		ids := make([]string, 0, len(sc.AIC.Capabilities))
		for _, c := range sc.AIC.Capabilities {
			ids = append(ids, c.FullID())
		}
		if err := sc.ValidateCapabilities(ids); err != nil {
			return nil, fmt.Errorf("capability registration validation: %w", err)
		}
	}

	// Retry loop: serial is embedded in the TBS and (for partitioned CRL DPs)
	// in the CRL URL, so the template + signing must be rebuilt per attempt.
	// Only the serial → sign → insert sequence repeats on ErrDuplicateSerial.
	for attempt := 0; attempt < 10; attempt++ {
		serial, err := randomSerial()
		if err != nil {
			return nil, fmt.Errorf("random serial: %w", err)
		}
		serialHex := fmt.Sprintf("%040X", serial)

		tmpl := buildCertTemplate(sc, serial)

		if err := applyProfile(tmpl, sc); err != nil {
			return nil, fmt.Errorf("apply profile: %w", err)
		}

		// Spec §3.4 Rule 2 (second validation): applyProfile may auto-derive PA from authz.json;
		// here we re-validate that auto-derived PA covers the AIC capabilities.
		if sc.AIC != nil && sc.PrincipalAuthorization != nil {
			if err := validatePrincipalAuthForAIC(sc.AIC, sc.PrincipalAuthorization); err != nil {
				return nil, fmt.Errorf("principal authorization validation (post-derive): %w", err)
			}
		}

		// Spec §3.4 Rule 1: AIC certificates MUST be end-entity (explicitly reject IsCA=true)
		if (sc.AIC != nil || sc.Profile == ProfileAgentProxy) && tmpl.IsCA {
			return nil, fmt.Errorf("aic: agent certificates MUST NOT have IsCA=true")
		}

		if err := addIssuerAltName(tmpl, sc.IssuerAltNames); err != nil {
			return nil, fmt.Errorf("issuer alt name: %w", err)
		}
		if err := addSubjectInfoAccess(tmpl, sc.SubjectInfoAccess); err != nil {
			return nil, fmt.Errorf("subject info access: %w", err)
		}
		if err := addCertificatePolicies(tmpl, sc.PolicyOIDs); err != nil {
			return nil, fmt.Errorf("cert policies: %w", err)
		}
		if err := addPolicyExtensions(tmpl, sc); err != nil {
			return nil, fmt.Errorf("policy extensions: %w", err)
		}

		// CAScope URIs must be set before parseSANs: when a DirName SAN is
		// present parseSANs folds tmpl.URIs into its manually built SAN
		// extension and clears tmpl.URIs — adding them afterwards would let Go
		// drop the scope URIs (duplicate SAN OID) and lose the scope.
		for _, scope := range sc.CAScope {
			tmpl.URIs = append(tmpl.URIs, &url.URL{Scheme: "urn", Opaque: "pki:ca:" + scope})
		}
		if len(sc.SANs) > 0 {
			if err := parseSANs(tmpl, sc.SANs); err != nil {
				return nil, fmt.Errorf("parse SANs: %w", err)
			}
		}

		pubBytes, err := x509.MarshalPKIXPublicKey(sc.CAKey.Public())
		if err != nil {
			return nil, fmt.Errorf("marshal public key for SKI: %w", err)
		}
		tmpl.SubjectKeyId = sha256hash(pubBytes)[:20]
		if sc.CACert != nil {
			// AKI must equal the issuer's SubjectKeyId (RFC 5280 §4.2.1.1).
			// Prefer the CA cert's authoritative SKI; fall back to SHA-256 of the
			// CA public key for issuers without a SKI extension.
			if len(sc.CACert.SubjectKeyId) > 0 {
				tmpl.AuthorityKeyId = sc.CACert.SubjectKeyId
			} else {
				caPubBytes, err := x509.MarshalPKIXPublicKey(sc.CACert.PublicKey)
				if err != nil {
					return nil, fmt.Errorf("marshal CA public key for AKI: %w", err)
				}
				tmpl.AuthorityKeyId = sha256hash(caPubBytes)[:20]
			}
		}

		// Spec §3.4 Rule 3: AKI boundary check. M7 fix: this ran before AKI was
		// populated (dead code) — now it runs after AKI/SKI derivation and actually
		// verifies AKI matches the issuer's SubjectKeyId.
		if sc.CACert != nil && len(tmpl.AuthorityKeyId) > 0 && len(sc.CACert.SubjectKeyId) > 0 {
			if !bytesEqual(tmpl.AuthorityKeyId, sc.CACert.SubjectKeyId) {
				return nil, fmt.Errorf("aic: AuthorityKeyId mismatch with issuer SubjectKeyId")
			}
		}

		subjPubKey := sc.SubjectPubKey
		if subjPubKey == nil {
			subjPubKey = sc.CAKey.Public()
		}

		var certDER []byte
		if isSM2Key(sc.CAKey) {
			// Pure SM2 path: gmsm/x509 produces a cert with the SM2-with-SM3
			// signature algorithm OID (1.2.156.10197.1.501) instead of ECDSA.
			certDER, err = createSM2Certificate(tmpl, sc.CACert, subjPubKey, sc.CAKey)
		} else {
			certDER, err = x509.CreateCertificate(rand.Reader, tmpl, sc.CACert, subjPubKey, sc.CAKey)
		}
		if err != nil {
			return nil, fmt.Errorf("create certificate: %w", err)
		}
		if len(certDER) > pki.MaxHardCertDERSize {
			return nil, fmt.Errorf("certificate DER exceeds %dKB limit (%d bytes)", pki.MaxHardCertDERSize/1024, len(certDER))
		}

		var cert *x509.Certificate
		if isSM2Key(sc.CAKey) {
			cert, err = parseSM2Certificate(certDER)
		} else {
			cert, err = x509.ParseCertificate(certDER)
		}
		if err != nil {
			return nil, fmt.Errorf("parse signed cert: %w", err)
		}

		caName := sc.CAName
		if caName == "" {
			caName = sc.CACert.Subject.CommonName
		}
		subjO, subjC, issuerDN, keyAlgo, keySize, sigAlgo, ski, aki, san := ExtractCertFields(cert)
		spkiHash := ExtractSPKIHash(cert)
		profile := string(sc.Profile)
		var principalUid, agentId string
		if sc.AIC != nil {
			principalUid = sc.AIC.PrincipalUid.String()
			if principalUid == ":" {
				principalUid = ""
			}
			agentId = sc.AIC.AgentId
		}
		record := &db.CertRecord{
			SerialNumber: serialHex,
			CAName:       caName,
			Status:       "V",
			Subject:      cert.Subject.String(),
			CommonName:   sc.CommonName,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			CertDER:      certDER,
			Fingerprint:  db.Fingerprint(certDER),
			SubjectO:     subjO,
			SubjectC:     subjC,
			IssuerDN:     issuerDN,
			KeyAlgo:      keyAlgo,
			KeySize:      keySize,
			SigAlgo:      sigAlgo,
			SKI:          ski,
			AKI:          aki,
			SAN:          san,
			Profile:      profile,
			SPKIHash:     spkiHash,
			PrincipalUid: principalUid,
			AgentId:      agentId,
		}
		var insErr error
		if sc.SkipDB {
			insErr = nil
		} else if sc.DedupCN {
			insErr = sc.DB.InsertCertWithDedup(record)
		} else {
			insErr = sc.DB.InsertCert(record)
		}
		if insErr != nil {
			if errors.Is(insErr, db.ErrDuplicateSerial) {
				slog.Debug("ca/sign: serial collision, retrying", "serial", serialHex)
				continue
			}
			return nil, fmt.Errorf("insert cert to db: %w", insErr)
		}

		// Debug level: At high throughput, this log at Info level competes with accessLog
		// for the slog mutex, forming a lock convoy (measured w32+ throughput collapse).
		// Issuance auditing is handled by a separate AuditLogger; only operational
		// observability is retained here.
		slog.Debug("ca/sign: issued", "ca", caName, "serial", serialHex, "profile", sc.Profile, "cn", sc.CommonName, "validity", sc.Validity)
		return &SignResult{
			Cert:      cert,
			CertDER:   certDER,
			SerialHex: serialHex,
			Record:    record,
		}, nil
	}

	return nil, fmt.Errorf("failed to generate unique serial after 10 attempts")
}

func setHash(tmpl *x509.Certificate, hash string, signer crypto.Signer) {
	var algo x509.SignatureAlgorithm
	if isEd25519Key(signer) {
		// Ed25519 is always PureEd25519 — the hash selector is ignored and a
		// wrong value would otherwise make CreateCertificate fail.
		algo = x509.PureEd25519
		tmpl.SignatureAlgorithm = algo
		return
	}
	_, isRSA := signer.Public().(*rsa.PublicKey)
	switch {
	case isRSA && hash == "sha384":
		algo = x509.SHA384WithRSA
	case isRSA && hash == "sha512":
		algo = x509.SHA512WithRSA
	case isRSA && hash == "pss":
		// RSA-PSS signing (RFC 4055). When a specific PSS hash is requested,
		// it is carried in the hash value (e.g. "pss-sha384").
		algo = x509.SHA256WithRSAPSS
	case !isRSA && hash == "sha384":
		algo = x509.ECDSAWithSHA384
	case !isRSA && hash == "sha512":
		algo = x509.ECDSAWithSHA512
	case !isRSA:
		algo = x509.ECDSAWithSHA256
	default:
		algo = x509.SHA256WithRSA
	}
	tmpl.SignatureAlgorithm = algo
}

// isEd25519Key reports whether the signer's public key is an Ed25519 key.
// Ed25519 signatures are always PureEd25519 — the hash selector is ignored.
func isEd25519Key(key crypto.Signer) bool {
	_, ok := key.Public().(ed25519.PublicKey)
	return ok
}

func addMustStaple(tmpl *x509.Certificate) {
	features := []int{5}
	b, err := asn1.Marshal(features)
	if err != nil {
		return
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    oidTLSFeature,
		Value: b,
	})
}

type NameConstraints struct {
	PermittedDomains  []string
	ExcludedDomains   []string
	PermittedEmails   []string
	ExcludedEmails    []string
	PermittedURIs     []string
	ExcludedURIs      []string
	PermittedIPRanges []string
	ExcludedIPRanges  []string
}

// PolicyMapping represents a single mapping in the RFC 5280 §4.2.1.5 Policy Mappings extension:
// issuerDomainPolicy maps to subjectDomainPolicy. Allowed only in CA certificates.
type PolicyMapping struct {
	IssuerDomainPolicy  string // Issuer domain policy OID (e.g. "2.5.29.32.0")
	SubjectDomainPolicy string // Subject domain policy OID
}

func applyNameConstraints(tmpl *x509.Certificate, nc *NameConstraints) {
	if nc == nil {
		return
	}
	if len(nc.PermittedDomains) > 0 {
		tmpl.PermittedDNSDomains = nc.PermittedDomains
		tmpl.PermittedDNSDomainsCritical = true
	}
	if len(nc.ExcludedDomains) > 0 {
		tmpl.ExcludedDNSDomains = nc.ExcludedDomains
	}
	if len(nc.PermittedEmails) > 0 {
		tmpl.PermittedEmailAddresses = nc.PermittedEmails
	}
	if len(nc.ExcludedEmails) > 0 {
		tmpl.ExcludedEmailAddresses = nc.ExcludedEmails
	}
	if len(nc.PermittedURIs) > 0 {
		tmpl.PermittedURIDomains = nc.PermittedURIs
	}
	if len(nc.ExcludedURIs) > 0 {
		tmpl.ExcludedURIDomains = nc.ExcludedURIs
	}
	for _, cidr := range nc.PermittedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, ipnet)
		}
	}
	for _, cidr := range nc.ExcludedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, ipnet)
		}
	}
}

func applyProfile(tmpl *x509.Certificate, sc *SignConfig) error {
	setHash(tmpl, sc.Hash, sc.CAKey)

	switch sc.Profile {
	case ProfileRootCA:
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		if sc.MaxPathLen > 0 {
			tmpl.MaxPathLen = sc.MaxPathLen
		}
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.ExtKeyUsage = nil

	case ProfilePolicyCA:
		tmpl.IsCA = true
		// M6 fix: MaxPathLen=1 + MaxPathLenZero=true used to encode pathlen=1
		// (Go only honors MaxPathLenZero when MaxPathLen==0). Policy CA must be
		// pathlen=0 — it cannot issue further sub-CAs.
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
	case ProfileSubCA:
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		if sc.MaxPathLen > 0 {
			tmpl.MaxPathLen = sc.MaxPathLen
		} else {
			tmpl.MaxPathLen = 1
			tmpl.MaxPathLenZero = true
		}
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		applyNameConstraints(tmpl, &NameConstraints{
			PermittedDomains:  sc.PermittedDomains,
			ExcludedDomains:   sc.ExcludedDomains,
			PermittedEmails:   sc.PermittedEmails,
			ExcludedEmails:    sc.ExcludedEmails,
			PermittedURIs:     sc.PermittedURIs,
			ExcludedURIs:      sc.ExcludedURIs,
			PermittedIPRanges: sc.PermittedIPRanges,
			ExcludedIPRanges:  sc.ExcludedIPRanges,
		})

	case ProfileTLSServer:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileTLSClient:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileOCSPSigner:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		tmpl.UnknownExtKeyUsage = nil
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileTimestamp:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		// RFC 3161 mandates EKU critical. Go's ExtKeyUsage always encodes as
		// non-critical, so we use ExtraExtensions with Critical=true instead.
		tmpl.ExtKeyUsage = nil
		tmpl.UnknownExtKeyUsage = nil
		ekuOIDs := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}
		if b, err := asn1.Marshal(ekuOIDs); err == nil {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    b,
			})
		}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileCodeSigning:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileEmail:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileDocument:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		tmpl.ExtKeyUsage = nil
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileIdentityUser:
		// A person's base identity certificate. The serve layer resolves
		// CN/OU/email from an identity source and fills them into the subject;
		// this profile only pins the template (identity + email + client auth).
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)
		if sc.PrincipalAuthorization != nil {
			ext, err := BuildPrincipalAuthorizationExtension(*sc.PrincipalAuthorization)
			if err != nil {
				return fmt.Errorf("build PA extension: %w", err)
			}
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}

	case ProfileCMP:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileVPNClient:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileVPNServer:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)

	case ProfileAgentProxy:
		if sc.Subject == nil || len(sc.Subject.OrganizationalUnit) == 0 {
			return fmt.Errorf("agent-proxy profile requires at least one OU " +
				"(OrganizationalUnit) for gateway RBAC; use --subject \"/CN=<name>/OU=gateway:<role>\"")
		}
		// M24 fix: reject wildcard OUs ("*", "gateway:*") that would map to any
		// RBAC role at the gateway — a privilege elevation channel.
		if err := auth.ValidateOUS(sc.Subject.OrganizationalUnit); err != nil {
			return fmt.Errorf("agent-proxy OU: %w", err)
		}
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		// authorized mode certificate validity ≤ MaxAgentProxyValidity (default 1h, spec
		// P1-B-09/25 and P2-A-04 allow relaxing to ≤24h, controlled by agent_proxy_max_validity config).
		maxValidity := sc.MaxAgentProxyValidityLimit()
		if tmpl.NotAfter.After(tmpl.NotBefore.Add(maxValidity)) {
			tmpl.NotAfter = tmpl.NotBefore.Add(maxValidity)
		}
		addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
		addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)
		if sc.AIC != nil {
			ext, err := BuildAIC(*sc.AIC)
			if err != nil {
				return fmt.Errorf("build AIC extension: %w", err)
			}
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			// SPIFFE identity: if agentId is in SPIFFE format, add it as a SAN URI.
			if pki.IsSPIFFEAgentID(sc.AIC.AgentId) {
				if err := pki.AddSPIFFESANToCert(tmpl, sc.AIC.AgentId); err != nil {
					return fmt.Errorf("add SPIFFE SAN: %w", err)
				}
			}
		}
		// Auto-derive PrincipalAuthorization from authorization policy if not explicit
		if sc.PrincipalAuthorization == nil || len(sc.PrincipalAuthorization.Grants) == 0 {
			if p := auth.GetPolicy(); p != nil && sc.Subject != nil {
				for _, ou := range sc.Subject.OrganizationalUnit {
					role := p.RoleByOU(ou)
					if role == "" {
						continue
					}
					grants := p.RoleGrants(role)
					if len(grants) > 0 {
						caps := make([]Capability, len(grants))
						for i, g := range grants {
							scheme, capId := parseGrant(g)
							caps[i] = Capability{
								SchemeId:     scheme,
								CapabilityId: capId,
							}
						}
						sc.PrincipalAuthorization = &PrincipalAuthorizationConfig{Grants: caps}
						break
					}
				}
			}
		}
		if sc.PrincipalAuthorization != nil {
			ext, err := BuildPrincipalAuthorizationExtension(*sc.PrincipalAuthorization)
			if err != nil {
				return fmt.Errorf("build PA extension: %w", err)
			}
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}

	// ── Management certificate templates (m-*) ──────────────────────────────────────
	// Each template automatically sets OU + ClientAuth EKU; at issuance, only CN needs to be specified.
	// 8 profiles differ only in OU (RBAC role), KU/EKU are identical, merged into a common branch.

	case ProfileMSuperAdmin, ProfileMAdmin, ProfileMOperator, ProfileMAuditor,
		ProfileMRevoker, ProfileMReadonly, ProfileMConsole, ProfileMAutoRenew, ProfileMReporter:
		applyManagementProfile(tmpl, sc)
		// OID scope: specifies which CAs this management certificate can operate on
		// (consistent with dual-write SAN URI; any m-* profile carrying scope is written,
		// merged and deduplicated at authentication time).
		if sc.Scope != "" {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1},
				Value: []byte(sc.Scope),
			})
		}
		// Cert-first permission declaration: automatically generates PrincipalAuthorization
		// grants based on the role template and writes them to the certificate, making permissions
		// self-contained with the certificate (no need to query DB roles at runtime).
		if sc.PrincipalAuthorization == nil {
			if pa := managementPAGrants(sc); pa != nil {
				ext, err := BuildPrincipalAuthorizationExtension(*pa)
				if err != nil {
					return fmt.Errorf("build m-* PA extension: %w", err)
				}
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			}
		} else if err := validateManagementPAGrants(sc); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown profile: %s", sc.Profile)
	}

	// Direct authorization (no AIC) human certificates: embed PrincipalAuthorization
	// extension when explicitly carrying PA grants. agent-proxy (AIC) and m-* management
	// profiles have already built PA within their branches; remaining end-entity profiles
	// (tls-client/server etc.) are supplemented here — PA is independent of AIC, human
	// certificates can directly carry authorization declarations (gateway PA-only determination:
	// without AIC, capability checks are based on PA grants).
	if sc.PrincipalAuthorization != nil && !tmpl.IsCA && !hasPAExtension(tmpl.ExtraExtensions) {
		ext, err := BuildPrincipalAuthorizationExtension(*sc.PrincipalAuthorization)
		if err != nil {
			return fmt.Errorf("build PA extension: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}

	if sc.MustStaple {
		addMustStaple(tmpl)
	}

	for _, oidStr := range sc.ExtraEKUOIDs {
		oid, err := parseOID(oidStr)
		if err != nil {
			return fmt.Errorf("extra EKU OID: %w", err)
		}
		tmpl.UnknownExtKeyUsage = append(tmpl.UnknownExtKeyUsage, oid)
	}

	return nil
}

// managementProfileOU maps the m-* certificate profiles to their RBAC role OU.
// The OU is what the gateway/lib RBAC layer extracts to determine roles.
var managementProfileOU = map[Profile]string{
	ProfileMSuperAdmin: "SuperAdmin",
	ProfileMAdmin:      "admin",
	ProfileMOperator:   "operator",
	ProfileMRevoker:    "revoker",
	ProfileMAuditor:    "auditor",
	ProfileMReadonly:   "readonly",
	ProfileMConsole:    "console",
	ProfileMAutoRenew:  "auto-renew",
	ProfileMReporter:   "reporter",
}

// hasPAExtension checks if the extension list already contains a PrincipalAuthorization extension,
// avoiding duplicate additions from the common PA build section and profile branches (agent-proxy/m-*).
func hasPAExtension(exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(OIDPrincipalAuthorization) {
			return true
		}
	}
	return false
}

// applyManagementProfile applies the shared management-certificate profile:
// an entity certificate (IsCA=false) with DigitalSignature KU, ClientAuth EKU,
// and a role-specific OrganizationalUnit used for gateway RBAC.
func applyManagementProfile(tmpl *x509.Certificate, sc *SignConfig) {
	tmpl.Subject.OrganizationalUnit = []string{managementProfileOU[sc.Profile]}
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	addCRLDP(tmpl, sc.CRLBaseURL, sc.CACert.Subject.CommonName, sc.CRLPartitions, tmpl.SerialNumber)
	addAIA(tmpl, sc.OCSPURL, sc.IssuerURL)
}

// managementPAGrants derives PrincipalAuthorization grants for an m-*
// management certificate from the authorization policy (role → grants).
// The role is resolved from the profile's RBAC OU. Returns nil when no
// policy is configured (certificates carry OU only for backward compat).
func managementPAGrants(sc *SignConfig) *PrincipalAuthorizationConfig {
	p := auth.GetPolicy()
	if p == nil {
		return nil
	}
	ou := managementProfileOU[sc.Profile]
	role := p.RoleByOU(ou)
	if role == "" {
		return nil
	}
	grants := p.RoleGrants(role)
	if len(grants) == 0 {
		return nil
	}
	caps := make([]Capability, len(grants))
	for i, g := range grants {
		scheme, capId := parseGrant(g)
		caps[i] = Capability{SchemeId: scheme, CapabilityId: capId}
	}
	return &PrincipalAuthorizationConfig{Grants: caps}
}

// validateManagementPAGrants enforces cert-first authorization: an explicit
// PrincipalAuthorization on an m-* profile must not grant more than the
// role's policy grants (least privilege, fail-closed).
func validateManagementPAGrants(sc *SignConfig) error {
	p := auth.GetPolicy()
	if p == nil {
		return nil
	}
	ou := managementProfileOU[sc.Profile]
	role := p.RoleByOU(ou)
	if role == "" {
		return fmt.Errorf("m-* profile %q: OU %q maps to no role", sc.Profile, ou)
	}
	allowed := p.RoleGrants(role)
	for _, cap := range sc.PrincipalAuthorization.Grants {
		if !grantCovered(cap.CapabilityId, allowed) {
			return fmt.Errorf("m-* profile %q: grant %q not covered by role %q policy grants (fail-closed)",
				sc.Profile, cap.CapabilityId, role)
		}
	}
	return nil
}

// grantCovered reports whether a capability id matches any of the allowed
// grant patterns (exact or wildcard).
func grantCovered(capID string, allowed []string) bool {
	if capID == "" {
		return false
	}
	for _, a := range allowed {
		if auth.MatchCapability(capID, a) {
			return true
		}
	}
	return false
}

func addCRLDP(tmpl *x509.Certificate, baseURL, caName string, partitions int, serial *big.Int) {
	if baseURL == "" {
		return
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if partitions > 1 && serial != nil {
		serialHex := fmt.Sprintf("%040X", serial)
		p := partitionOfSerial(serialHex, partitions)
		filename := CRLFilename(caName, p, partitions)
		crlURL := fmt.Sprintf("%s/%s", baseURL, filename)
		u, err := url.Parse(crlURL)
		if err != nil {
			return
		}
		tmpl.CRLDistributionPoints = []string{u.String()}
		return
	}
	crlURL := fmt.Sprintf("%s/%s.crl", baseURL, SanitizeCAName(caName))
	u, err := url.Parse(crlURL)
	if err != nil {
		return
	}
	tmpl.CRLDistributionPoints = []string{u.String()}
}

func addAIA(tmpl *x509.Certificate, ocspURL, issuerURL string) {
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	if issuerURL != "" {
		tmpl.IssuingCertificateURL = []string{issuerURL}
	}
}

func addIssuerAltName(tmpl *x509.Certificate, names []string) error {
	if len(names) == 0 {
		return nil
	}
	var gns []asn1.RawValue
	for _, name := range names {
		switch {
		case strings.HasPrefix(name, "DNS:"):
			gns = append(gns, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(strings.TrimPrefix(name, "DNS:"))})
		case strings.HasPrefix(name, "URI:"):
			gns = append(gns, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(strings.TrimPrefix(name, "URI:"))})
		default:
			return fmt.Errorf("unsupported IssuerAltName format: %s (use DNS: or URI: prefix)", name)
		}
	}
	b, err := asn1.Marshal(struct {
		Names []asn1.RawValue `asn1:"sequence"`
	}{Names: gns})
	if err != nil {
		return fmt.Errorf("marshal IssuerAltName: %w", err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 18},
		Value: b,
	})
	return nil
}

func addSubjectInfoAccess(tmpl *x509.Certificate, accessList []string) error {
	if len(accessList) == 0 {
		return nil
	}
	type AccessDescription struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue `asn1:"explicit,tag:0"`
	}
	methodMap := map[string]asn1.ObjectIdentifier{
		"ocsp":          {1, 3, 6, 1, 5, 5, 7, 48, 1},
		"ca_repository": {1, 3, 6, 1, 5, 5, 7, 48, 5},
		"time_stamping": {1, 3, 6, 1, 5, 5, 7, 48, 2},
	}
	var descs []AccessDescription
	for _, entry := range accessList {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid SubjectInfoAccess entry: %s (format: method:location)", entry)
		}
		methodOID, ok := methodMap[parts[0]]
		if !ok {
			return fmt.Errorf("unknown SIA method: %s (use ocsp, ca_repository, time_stamping)", parts[0])
		}
		loc := parts[1]
		var locRaw asn1.RawValue
		switch {
		case strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://"):
			locRaw = asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(loc)}
		case strings.HasPrefix(loc, "DNS:"):
			locRaw = asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(strings.TrimPrefix(loc, "DNS:"))}
		default:
			locRaw = asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(loc)}
		}
		descs = append(descs, AccessDescription{Method: methodOID, Location: locRaw})
	}
	b, err := asn1.Marshal(descs)
	if err != nil {
		return fmt.Errorf("marshal SubjectInfoAccess: %w", err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11},
		Value: b,
	})
	return nil
}

func addCertificatePolicies(tmpl *x509.Certificate, oids []string) error {
	if len(oids) == 0 {
		return nil
	}
	type PolicyInformation struct {
		Policy asn1.ObjectIdentifier
	}
	var policies []PolicyInformation
	for _, oidStr := range oids {
		oid, err := parseOID(oidStr)
		if err != nil {
			return fmt.Errorf("invalid policy OID %q: %w", oidStr, err)
		}
		policies = append(policies, PolicyInformation{Policy: oid})
	}
	b, err := asn1.Marshal(policies)
	if err != nil {
		return fmt.Errorf("marshal CertificatePolicies: %w", err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 32},
		Value: b,
	})
	return nil
}

var (
	oidPolicyMappings    = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidPolicyConstraints = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidInhibitAnyPolicy  = asn1.ObjectIdentifier{2, 5, 29, 54}
)

// addPolicyExtensions injects RFC 5280 certificate policy system extensions (CA certificates only):
// Policy Mappings (2.5.29.33), Policy Constraints (2.5.29.36),
// Inhibit anyPolicy (2.5.29.54). End-entity certificates are not allowed to carry these extensions.
func addPolicyExtensions(tmpl *x509.Certificate, sc *SignConfig) error {
	if len(sc.PolicyMappings) == 0 && sc.RequireExplicitPolicy == nil &&
		sc.InhibitPolicyMapping == nil && sc.InhibitAnyPolicy == nil {
		return nil
	}
	if !tmpl.IsCA {
		return fmt.Errorf("policy extensions: Policy Mappings / Policy Constraints / Inhibit anyPolicy are only allowed in CA certificates")
	}
	if len(sc.PolicyMappings) > 0 {
		type Mapping struct {
			IssuerDomainPolicy  asn1.ObjectIdentifier
			SubjectDomainPolicy asn1.ObjectIdentifier
		}
		mappings := make([]Mapping, 0, len(sc.PolicyMappings))
		for _, m := range sc.PolicyMappings {
			issuer, err := parseOID(m.IssuerDomainPolicy)
			if err != nil {
				return fmt.Errorf("invalid issuerDomainPolicy OID %q: %w", m.IssuerDomainPolicy, err)
			}
			subject, err := parseOID(m.SubjectDomainPolicy)
			if err != nil {
				return fmt.Errorf("invalid subjectDomainPolicy OID %q: %w", m.SubjectDomainPolicy, err)
			}
			mappings = append(mappings, Mapping{IssuerDomainPolicy: issuer, SubjectDomainPolicy: subject})
		}
		b, err := asn1.Marshal(mappings)
		if err != nil {
			return fmt.Errorf("marshal PolicyMappings: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    oidPolicyMappings,
			Value: b,
		})
	}

	if sc.RequireExplicitPolicy != nil || sc.InhibitPolicyMapping != nil {
		type PolicyConstraints struct {
			RequireExplicitPolicy int `asn1:"optional,explicit,tag:0"`
			InhibitPolicyMapping  int `asn1:"optional,explicit,tag:1"`
		}
		var pc PolicyConstraints
		if sc.RequireExplicitPolicy != nil {
			pc.RequireExplicitPolicy = *sc.RequireExplicitPolicy
		}
		if sc.InhibitPolicyMapping != nil {
			pc.InhibitPolicyMapping = *sc.InhibitPolicyMapping
		}
		b, err := asn1.Marshal(pc)
		if err != nil {
			return fmt.Errorf("marshal PolicyConstraints: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    oidPolicyConstraints,
			Value: b,
		})
	}

	if sc.InhibitAnyPolicy != nil {
		b, err := asn1.Marshal(*sc.InhibitAnyPolicy)
		if err != nil {
			return fmt.Errorf("marshal Inhibit anyPolicy: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    oidInhibitAnyPolicy,
			Value: b,
		})
	}
	return nil
}

// ParsePolicyMapping parses an "issuerDomainPolicy:subjectDomainPolicy" string into a
// PolicyMapping (for reuse by API/CLI layers).
func ParsePolicyMapping(s string) (PolicyMapping, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return PolicyMapping{}, fmt.Errorf("invalid policy mapping %q (want issuer:subject)", s)
	}
	if _, err := parseOID(parts[0]); err != nil {
		return PolicyMapping{}, fmt.Errorf("invalid issuerDomainPolicy: %w", err)
	}
	if _, err := parseOID(parts[1]); err != nil {
		return PolicyMapping{}, fmt.Errorf("invalid subjectDomainPolicy: %w", err)
	}
	return PolicyMapping{IssuerDomainPolicy: parts[0], SubjectDomainPolicy: parts[1]}, nil
}

// ParsePolicyMappings batch-parses a list of strings ("issuer:subject" format) into
// []PolicyMapping; any invalid item causes the entire operation to fail.
func ParsePolicyMappings(strs []string) ([]PolicyMapping, error) {
	if len(strs) == 0 {
		return nil, nil
	}
	out := make([]PolicyMapping, 0, len(strs))
	for _, s := range strs {
		m, err := ParsePolicyMapping(s)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID: %s", s)
		}
		oid[i] = v
	}
	return oid, nil
}

var (
	oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	validDNS      = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	return validDNS.MatchString(name)
}

type sanEntry struct {
	tag  int
	data []byte
}

func buildGeneralName(tag int, data []byte) []byte {
	cls := 0x80 // context-specific
	if tag == 4 {
		cls |= 0x20 // constructed
	}
	// Proper TLV: [tag] [length] [value]. (Previously the length octet was
	// omitted, producing malformed GeneralNames that Go could not re-parse.)
	out := []byte{byte(cls | tag)}
	switch {
	case len(data) < 128:
		out = append(out, byte(len(data)))
	default:
		l := len(data)
		var lenBytes []byte
		for l > 0 {
			lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
			l >>= 8
		}
		out = append(out, byte(0x80|len(lenBytes)))
		out = append(out, lenBytes...)
	}
	return append(out, data...)
}

func asn1DERSequence(content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{0x30, byte(len(content))}, content...)
	}
	// Long-form length encoding (for sequences > 127 bytes)
	lenBytes := make([]byte, 8)
	n := len(content)
	i := len(lenBytes) - 1
	for n > 0 {
		lenBytes[i] = byte(n & 0xff)
		n >>= 8
		i--
	}
	lenBytes = lenBytes[i+1:]
	tl := []byte{0x30, byte(0x80 | len(lenBytes))}
	tl = append(tl, lenBytes...)
	return append(tl, content...)
}

func parseSANs(tmpl *x509.Certificate, sans []string) error {
	var dirNames []string
	var entries []sanEntry

	for _, s := range sans {
		s = strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(s, "DNS:"):
			dns := strings.TrimPrefix(s, "DNS:")
			if !validDNSName(dns) {
				return fmt.Errorf("invalid DNS SAN: %s", s)
			}
			tmpl.DNSNames = append(tmpl.DNSNames, dns)
		case strings.HasPrefix(s, "IP:"):
			ip := net.ParseIP(strings.TrimPrefix(s, "IP:"))
			if ip == nil {
				return fmt.Errorf("invalid IP SAN: %s", s)
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		case strings.HasPrefix(s, "URI:"):
			u, err := url.Parse(strings.TrimPrefix(s, "URI:"))
			if err != nil {
				return fmt.Errorf("invalid URI SAN: %w", err)
			}
			tmpl.URIs = append(tmpl.URIs, u)
		case strings.HasPrefix(s, "email:"):
			addr := strings.TrimPrefix(s, "email:")
			if _, err := mail.ParseAddress(addr); err != nil {
				return fmt.Errorf("invalid email SAN: %s", s)
			}
			tmpl.EmailAddresses = append(tmpl.EmailAddresses, addr)
		case strings.HasPrefix(s, "DirName:"):
			dirNames = append(dirNames, s)
		default:
			return fmt.Errorf("unsupported SAN type: %s", s)
		}
	}

	if len(dirNames) == 0 {
		return nil
	}

	for _, s := range dirNames {
		name := strings.TrimPrefix(s, "DirName:")
		parts := strings.Split(name, ",")
		dirName := &pkix.Name{}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("invalid DirName SAN format: %s", s)
			}
			switch strings.ToUpper(strings.TrimSpace(kv[0])) {
			case "CN":
				dirName.CommonName = strings.TrimSpace(kv[1])
			case "O":
				dirName.Organization = []string{strings.TrimSpace(kv[1])}
			case "OU":
				dirName.OrganizationalUnit = []string{strings.TrimSpace(kv[1])}
			case "C":
				dirName.Country = []string{strings.TrimSpace(kv[1])}
			case "L":
				dirName.Locality = []string{strings.TrimSpace(kv[1])}
			case "ST":
				dirName.Province = []string{strings.TrimSpace(kv[1])}
			default:
				return fmt.Errorf("unsupported DirName attribute: %s", kv[0])
			}
		}
		dirDER, err := asn1.Marshal(*dirName)
		if err != nil {
			return fmt.Errorf("marshal DirName: %w", err)
		}
		entries = append(entries, sanEntry{tag: 4, data: dirDER})
	}

	// Append other SAN types if mixing with DirName
	hasOther := len(tmpl.DNSNames) > 0 || len(tmpl.IPAddresses) > 0 ||
		len(tmpl.URIs) > 0 || len(tmpl.EmailAddresses) > 0
	if hasOther {
		for _, dns := range tmpl.DNSNames {
			entries = append(entries, sanEntry{tag: 2, data: []byte(dns)})
		}
		for _, ip := range tmpl.IPAddresses {
			ip4 := ip.To4()
			if ip4 != nil {
				entries = append(entries, sanEntry{tag: 7, data: ip4})
			} else {
				entries = append(entries, sanEntry{tag: 7, data: ip.To16()})
			}
		}
		for _, u := range tmpl.URIs {
			entries = append(entries, sanEntry{tag: 6, data: []byte(u.String())})
		}
		for _, email := range tmpl.EmailAddresses {
			entries = append(entries, sanEntry{tag: 1, data: []byte(email)})
		}
	}

	var seq []byte
	for _, e := range entries {
		gn := buildGeneralName(e.tag, e.data)
		seq = append(seq, gn...)
	}
	seqDER := asn1DERSequence(seq)
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: seqDER,
	})

	if hasOther {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = nil
		tmpl.URIs = nil
		tmpl.EmailAddresses = nil
	}
	return nil
}

func sha256hash(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

type OfflineSignConfig struct {
	CACert   *x509.Certificate
	CAKey    crypto.Signer
	CSR      *x509.CertificateRequest
	Validity time.Duration
	Hash     string // sha256, sha384, sha512
	PathLen  int    // 0 = sub-ca, 1+ = intermediate, -1 = no constraint
}

func SignCACSR(cfg *OfflineSignConfig) ([]byte, *big.Int, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("random serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      cfg.CSR.Subject,
		NotBefore:    now,
		NotAfter:     now.Add(cfg.Validity),

		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// M1 fix: clip sub-CA NotAfter to the parent CA's validity.
	if cfg.CACert != nil && tmpl.NotAfter.After(cfg.CACert.NotAfter) {
		tmpl.NotAfter = cfg.CACert.NotAfter
	}
	if !tmpl.NotBefore.Before(tmpl.NotAfter) {
		tmpl.NotAfter = tmpl.NotBefore.Add(time.Hour)
	}

	if cfg.PathLen >= 0 {
		tmpl.MaxPathLen = cfg.PathLen
		if cfg.PathLen == 0 {
			tmpl.MaxPathLenZero = true
		}
	}

	setHash(tmpl, cfg.Hash, cfg.CAKey)

	// Subject Key Identifier
	pubBytes, _ := x509.MarshalPKIXPublicKey(cfg.CSR.PublicKey)
	tmpl.SubjectKeyId = sha256hash(pubBytes)[:20]

	// Authority Key Identifier
	caPubBytes, _ := x509.MarshalPKIXPublicKey(cfg.CACert.PublicKey)
	tmpl.AuthorityKeyId = sha256hash(caPubBytes)[:20]

	// Include extensions from CSR if present
	tmpl.ExtraExtensions = cfg.CSR.Extensions

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, cfg.CACert, cfg.CSR.PublicKey, cfg.CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	return certDER, serial, nil
}

func LoadPrivateKey(keyPath string, keyPassword ...string) (crypto.Signer, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return ParsePrivateKey(keyPEM, keyPassword...)
}

func ParsePrivateKey(keyPEM []byte, keyPassword ...string) (crypto.Signer, error) {
	rest := keyPEM
	var keyBlock *pem.Block
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			password := ""
			if len(keyPassword) > 0 {
				password = keyPassword[0]
			}
			return DecryptKeyPKCS8(block.Bytes, password)
		case "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
			keyBlock = block
			break
		}
		rest = remaining
		if keyBlock != nil {
			break
		}
	}
	if keyBlock == nil {
		return nil, fmt.Errorf("no private key block found in PEM")
	}

	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		if err := CheckPublicKeyStrength(k.Public()); err != nil {
			return nil, fmt.Errorf("weak key: %w", err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// SM2 keys cannot be decoded by stdlib PKCS8; try gmsm.
			if sm2Supported {
				var pwd []byte
				if len(keyPassword) > 0 && keyPassword[0] != "" {
					pwd = []byte(keyPassword[0])
				}
				if s, e2 := parseSM2PrivateKeyPEM(pem.EncodeToMemory(keyBlock), pwd); e2 == nil {
					return s, nil
				} else {
					return nil, fmt.Errorf("parse sm2 key: %w", e2)
				}
			}
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key is not a signer")
		}
		if err := CheckPublicKeyStrength(s.Public()); err != nil {
			return nil, fmt.Errorf("weak key: %w", err)
		}
		return s, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		if err := CheckPublicKeyStrength(k.Public()); err != nil {
			return nil, fmt.Errorf("weak key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
}

// RemoteSigner globals
var (
	globalRemoteConfig   *remotesigner.Config
	globalRemoteConfigMu sync.Mutex
)

// SetRemoteSignerConfig enables remote HSM signing for all LoadSigner calls.
func SetRemoteSignerConfig(cfg *remotesigner.Config) {
	globalRemoteConfigMu.Lock()
	globalRemoteConfig = cfg
	globalRemoteConfigMu.Unlock()
}

// RemoteSignerConfig returns the current remote signer config.
func RemoteSignerConfig() *remotesigner.Config {
	globalRemoteConfigMu.Lock()
	defer globalRemoteConfigMu.Unlock()
	return globalRemoteConfig
}

var signerCache sync.Map

type signerCacheEntry struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

func FlushSignerCache(keyPath ...string) {
	if len(keyPath) > 0 && keyPath[0] != "" {
		signerCache.Delete(keyPath[0])
	} else {
		signerCache = sync.Map{}
	}
}

func LoadSigner(certPath, keyPath string, keyPassword ...string) (*x509.Certificate, crypto.Signer, error) {
	if cached, ok := signerCache.Load(keyPath); ok {
		entry := cached.(*signerCacheEntry)
		return entry.cert, entry.signer, nil
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}

	// Wrap with remote signer if configured
	if rc := RemoteSignerConfig(); rc != nil {
		alias := rc.KeyAlias
		if alias == "" {
			alias = extractCAName(certPath)
		}
		remoteCfg := *rc
		remoteCfg.KeyAlias = alias
		rs, rErr := remotesigner.New(remoteCfg)
		if rErr != nil {
			return nil, nil, fmt.Errorf("remote signer: %w", rErr)
		}
		signerCache.Store(keyPath, &signerCacheEntry{cert, rs})
		return cert, rs, nil
	}

	signer, err := LoadPrivateKey(keyPath, keyPassword...)
	if err != nil {
		return nil, nil, err
	}

	signerCache.Store(keyPath, &signerCacheEntry{cert, signer})
	return cert, signer, nil
}

// extractCAName extracts a key alias from the cert filename (e.g. "ca" from "/etc/varwof/core/keys/ca.pem")
func extractCAName(certPath string) string {
	base := certPath
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := strings.LastIndex(base, "\\"); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[:idx]
	}
	return base
}

func CertToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func KeyToPEM(key crypto.Signer) ([]byte, error) {
	if isSM2Key(key) {
		// stdlib PKCS8 cannot encode the SM2 curve; use gmsm's PEM writer.
		der, err := marshalSM2PrivateKey(exportSM2Key(key))
		if err != nil {
			return nil, fmt.Errorf("marshal sm2 key: %w", err)
		}
		return der, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(exportSM2Key(key))
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseGrant parses a grant string like "varwof/demo-mysql-v1:SELECT:*" into scheme
// and capability parts. Format: "scheme:capability" where the scheme may contain
// "/" but not ":". We split on the first ":" which separates scheme from capability.
// The capability part may itself contain ":" (e.g. "SELECT:*").
func parseGrant(g string) (scheme, capId string) {
	if i := strings.Index(g, ":"); i > 0 {
		return g[:i], g[i+1:]
	}
	return "generic", g
}

// validatePrincipalAuthForAIC validates that PrincipalAuthorization's grants cover the AIC's capabilities.
// Spec §3.4 Rule 2: Pre-issuance PrincipalAuthorization validation — all AIC capability IDs
// MUST appear in PrincipalAuthorization's grants (superset is allowed).
// A6 (spec P2-B-05): When a grant matches an AIC capability's scheme, additionally verify
// parameters do not exceed grant parameter bounds (declared ≤ granted), reject if exceeded.
// H10 fix: subset matching is scheme-aware — a grant only covers a capability when their
// schemes match (or either is the generic empty scheme). Previously a bare CapabilityId match
// let a grant in one scheme (e.g. "mysql-v1") cover a capability in a completely different
// scheme ("redis-v1") — a cross-scheme escalation.
func validatePrincipalAuthForAIC(aic *AICConfig, pa *PrincipalAuthorizationConfig) error {
	if aic == nil || pa == nil {
		return nil
	}
	for _, cap := range aic.Capabilities {
		matchedCapID := false
		for i := range pa.Grants {
			g := &pa.Grants[i]
			// H10: exact-scheme match, or generic (empty scheme on either side) falls
			// back to CapabilityId matching for backward compatibility.
			if !sameScheme(g.SchemeId, cap.SchemeId) {
				continue
			}
			if g.CapabilityId != cap.CapabilityId {
				continue
			}
			matchedCapID = true
			if g.SchemeId == cap.SchemeId {
				if err := ValidateParameterSubset(*g, cap); err != nil {
					return err
				}
			}
			break
		}
		if !matchedCapID {
			return fmt.Errorf("aic capability %q (scheme %q) not covered by principal authorization grants",
				cap.CapabilityId, cap.SchemeId)
		}
	}
	return nil
}

// sameScheme reports whether a grant scheme covers an AIC capability scheme.
// An empty scheme on either side is the generic/legacy namespace and matches
// anything (historical capabilities were issued without a scheme). Otherwise
// the schemes must belong to the same semantic family — exact equality, or
// versioned/namespaced variants of the same family (e.g. "gateway",
// "varwof-gateway", "varwof-gateway-v1"). Genuinely different families (e.g.
// "mysql-v1" vs "redis-v1") never match (H10).
func sameScheme(grant, capScheme string) bool {
	if grant == "" || capScheme == "" {
		return true
	}
	if grant == capScheme {
		return true
	}
	return hasSchemePrefix(capScheme, grant) || hasSchemePrefix(grant, capScheme)
}

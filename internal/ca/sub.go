package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

var (
	ErrSubCAAlreadyExists = errors.New("sub-CA already exists")
	ErrSubCANotFound      = errors.New("sub-CA not found")
	ErrSubCARevoked       = errors.New("sub-CA is revoked")
	ErrSubCAExpired       = errors.New("sub-CA is expired")
	ErrAdminCertRequired  = errors.New("admin certificate with keyCertSign usage required")
	ErrInvalidAdminCert   = errors.New("invalid admin certificate")
)

// SubCAConfig holds configuration for creating a new sub-CA.
type SubCAConfig struct {
	Name           string        // Unique name for the sub-CA
	ParentCA       string        // Parent CA name (issuing CA)
	KeyType        string        // Key type (ecdsa-p256, ecdsa-p384, rsa-2048, etc.)
	Validity       time.Duration // Certificate validity period
	MaxPathLen     int           // Path length constraint (0 for end-entity only)
	KeyUsage       []string      // Key usage extensions
	Protocol       string        // Protocol identifier (scep, cmp, acme, est)
	PermittedDomains []string    // Name constraints: permitted domains
	ExcludedDomains  []string    // Name constraints: excluded domains
	CRLBaseURL     string        // Base URL for the CRL Distribution Point extension
}

// SubCAResult holds the result of sub-CA creation.
type SubCAResult struct {
	Name        string
	Cert        *x509.Certificate
	CertDER     []byte
	CertPEM     []byte
	Key         crypto.Signer
	KeyPEM      []byte
	SerialHex   string
	Fingerprint string
}

// SubCAMeta holds metadata for an existing sub-CA.
type SubCAMeta struct {
	ID            int64
	Name          string
	ParentCA      string
	Cert          *x509.Certificate
	CertDER       []byte
	KeyEncrypted  []byte
	Subject       string
	NotBefore     time.Time
	NotAfter      time.Time
	KeyAlgorithm  string
	Fingerprint   string
	Status        string
	Protocol      string
	KeyUsage      string
	MaxPathLen    int
	CreatedAt     time.Time
	RevokedAt     *time.Time
	RevokeReason  *int
}

// IssueSubCA creates a new sub-CA certificate signed by the parent CA.
func IssueSubCA(database *db.DB, cfg *SubCAConfig, parentCert *x509.Certificate, parentKey crypto.Signer) (*SubCAResult, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("sub-CA name is required")
	}
	if cfg.ParentCA == "" {
		return nil, fmt.Errorf("parent CA name is required")
	}
	if cfg.Validity == 0 {
		cfg.Validity = 10 * 365 * 24 * time.Hour // Default 10 years
	}
	if cfg.KeyType == "" {
		cfg.KeyType = "ecdsa-p256"
	}

	now := time.Now()

	// M14 fix: validate the parent CA before issuing — it must be a CA, must
	// not be expired (RFC 5280 §4.8.5: sub-CA cannot outlive its issuer), must
	// not be revoked, and must have remaining path-length budget.
	if parentCert == nil {
		return nil, errors.New("parent CA certificate is required")
	}
	if !parentCert.IsCA || parentCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("parent CA is not a valid CA certificate (missing IsCA/CertSign)")
	}
	if !parentCert.NotBefore.Before(now) {
		return nil, errors.New("parent CA is not yet valid")
	}
	if parentCert.NotAfter.Before(now.Add(24 * time.Hour)) {
		return nil, errors.New("parent CA expires within 24h; cannot issue a sub-CA from it")
	}
	// Path-length budget: a parent with pathLenConstraint=0 may not have
	// subordinate CAs; a parent without the extension is unbounded.
	if parentCert.MaxPathLen == 0 && parentCert.MaxPathLenZero {
		return nil, errors.New("parent CA has path length 0 and cannot issue sub-CAs")
	}
	if parentCert.MaxPathLen > 0 && cfg.MaxPathLen >= parentCert.MaxPathLen {
		return nil, fmt.Errorf("sub-CA path length %d exceeds parent budget %d", cfg.MaxPathLen, parentCert.MaxPathLen)
	}
	// Revocation check: if the parent is itself a managed sub-CA, it must be active.
	if parentMeta, err := database.GetSubCA(cfg.ParentCA); err == nil && parentMeta != nil {
		if parentMeta.Status == "revoked" {
			return nil, ErrSubCARevoked
		}
	} else if err != nil && !errors.Is(err, ErrSubCANotFound) {
		// Non-fatal: parent may be a root/imported CA without a sub_ca record.
		_ = err
	}

	// Check if sub-CA already exists
	existing, _ := database.GetSubCA(cfg.Name)
	if existing != nil {
		return nil, ErrSubCAAlreadyExists
	}

	// Generate key pair
	signer, err := GenerateKey(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Generate serial number
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}

	// Build certificate template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.Name,
			Country:      []string{"CN"},
			Organization: []string{"PKI Sub-CA"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(cfg.Validity),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            cfg.MaxPathLen,
		MaxPathLenZero:        cfg.MaxPathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{},
		AuthorityKeyId:        []byte{},
	}

	// M1 fix: clip sub-CA NotAfter to the parent CA's validity.
	if parentCert != nil && tmpl.NotAfter.After(parentCert.NotAfter) {
		tmpl.NotAfter = parentCert.NotAfter
	}
	if !tmpl.NotBefore.Before(tmpl.NotAfter) {
		tmpl.NotAfter = tmpl.NotBefore.Add(time.Hour)
	}

	// Apply key usage extensions
	if err := applySubCAKeyUsage(tmpl, cfg.KeyUsage); err != nil {
		return nil, err
	}

	// Apply name constraints
	if len(cfg.PermittedDomains) > 0 || len(cfg.ExcludedDomains) > 0 {
		applyNameConstraints(tmpl, &NameConstraints{
			PermittedDomains: cfg.PermittedDomains,
			ExcludedDomains:  cfg.ExcludedDomains,
		})
	}

	// Add CRL Distribution Point (low-fix: empty baseURL no longer silently
	// skips the extension — it is set from cfg.CRLBaseURL when provided).
	if parentCert != nil {
		addCRLDP(tmpl, cfg.CRLBaseURL, cfg.Name, 0, serial)
	}

	// Compute SubjectKeyId
	pubBytes, _ := x509.MarshalPKIXPublicKey(signer.Public())
	ski := sha256hash(pubBytes)[:20]
	tmpl.SubjectKeyId = ski

	// Set AuthorityKeyId from parent
	if parentCert != nil {
		caPubBytes, _ := x509.MarshalPKIXPublicKey(parentCert.PublicKey)
		tmpl.AuthorityKeyId = sha256hash(caPubBytes)[:20]
	} else {
		tmpl.AuthorityKeyId = ski
	}

	// Sign certificate
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, signer.Public(), parentKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	// Store in database
	record := &db.SubCAMeta{
		Name:         cfg.Name,
		ParentCA:     cfg.ParentCA,
		CertDER:      certDER,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		KeyAlgorithm: cfg.KeyType,
		Fingerprint:  db.Fingerprint(certDER),
		Status:       "active",
		Protocol:     cfg.Protocol,
		KeyUsage:     joinKeyUsage(cfg.KeyUsage),
		MaxPathLen:   cfg.MaxPathLen,
	}

	if err := database.InsertSubCA(record); err != nil {
		return nil, fmt.Errorf("insert sub_ca: %w", err)
	}

	slog.Info("ca/sub: issued sub-CA",
		"name", cfg.Name,
		"parent", cfg.ParentCA,
		"protocol", cfg.Protocol,
		"validity", cfg.Validity,
		"key_type", cfg.KeyType,
	)

	return &SubCAResult{
		Name:        cfg.Name,
		Cert:        cert,
		CertDER:     certDER,
		CertPEM:     certPEM,
		Key:         signer,
		KeyPEM:      keyPEM,
		SerialHex:   fmt.Sprintf("%040X", serial),
		Fingerprint: db.Fingerprint(certDER),
	}, nil
}

// GetSubCA retrieves a sub-CA by name.
func GetSubCA(database *db.DB, name string) (*SubCAMeta, error) {
	record, err := database.GetSubCA(name)
	if err != nil {
		return nil, ErrSubCANotFound
	}

	cert, err := x509.ParseCertificate(record.CertDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	notBefore, _ := time.Parse(time.RFC3339, record.NotBefore)
	notAfter, _ := time.Parse(time.RFC3339, record.NotAfter)

	meta := &SubCAMeta{
		ID:           record.ID,
		Name:         record.Name,
		ParentCA:     record.ParentCA,
		Cert:         cert,
		CertDER:      record.CertDER,
		KeyEncrypted: record.KeyEncrypted,
		Subject:      record.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyAlgorithm: record.KeyAlgorithm,
		Fingerprint:  record.Fingerprint,
		Status:       record.Status,
		Protocol:     record.Protocol,
		KeyUsage:     record.KeyUsage,
		MaxPathLen:   record.MaxPathLen,
	}

	if record.RevokedAt != nil {
		t, _ := time.Parse(time.RFC3339, *record.RevokedAt)
		meta.RevokedAt = &t
	}
	if record.RevokeReason != nil {
		meta.RevokeReason = record.RevokeReason
	}

	return meta, nil
}

// ListSubCAs returns all sub-CAs, optionally filtered by protocol.
func ListSubCAs(database *db.DB, protocol string) ([]*SubCAMeta, error) {
	records, err := database.ListSubCAs(protocol)
	if err != nil {
		return nil, err
	}

	var result []*SubCAMeta
	for _, record := range records {
		cert, err := x509.ParseCertificate(record.CertDER)
		if err != nil {
			slog.Warn("ca/sub: failed to parse sub-CA certificate",
				"name", record.Name,
				"error", err,
			)
			continue
		}

		notBefore, _ := time.Parse(time.RFC3339, record.NotBefore)
		notAfter, _ := time.Parse(time.RFC3339, record.NotAfter)

		meta := &SubCAMeta{
			ID:           record.ID,
			Name:         record.Name,
			ParentCA:     record.ParentCA,
			Cert:         cert,
			CertDER:      record.CertDER,
			KeyEncrypted: record.KeyEncrypted,
			Subject:      record.Subject,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyAlgorithm: record.KeyAlgorithm,
			Fingerprint:  record.Fingerprint,
			Status:       record.Status,
			Protocol:     record.Protocol,
			KeyUsage:     record.KeyUsage,
			MaxPathLen:   record.MaxPathLen,
		}

		if record.RevokedAt != nil {
			t, _ := time.Parse(time.RFC3339, *record.RevokedAt)
			meta.RevokedAt = &t
		}
		if record.RevokeReason != nil {
			meta.RevokeReason = record.RevokeReason
		}

		result = append(result, meta)
	}

	return result, nil
}

// RevokeSubCA revokes a sub-CA by name.
func RevokeSubCA(database *db.DB, name string, reason int) error {
	record, err := database.GetSubCA(name)
	if err != nil {
		return ErrSubCANotFound
	}

	if record.Status == "revoked" {
		return fmt.Errorf("sub-CA %q is already revoked", name)
	}

	now := time.Now().Format(time.RFC3339)
	if err := database.RevokeSubCA(name, reason, now); err != nil {
		return fmt.Errorf("revoke sub_ca: %w", err)
	}

	slog.Info("ca/sub: revoked sub-CA",
		"name", name,
		"reason", reason,
	)

	return nil
}

// VerifySubCA checks if a sub-CA is valid (exists, active, and not expired).
func VerifySubCA(database *db.DB, name string) (*SubCAMeta, error) {
	meta, err := GetSubCA(database, name)
	if err != nil {
		return nil, err
	}

	if meta.Status == "revoked" {
		return nil, ErrSubCARevoked
	}

	// M14 fix: a sub-CA whose NotBefore is in the future is not yet valid.
	if time.Now().Before(meta.NotBefore) {
		return nil, errors.New("sub-CA is not yet valid")
	}

	if time.Now().After(meta.NotAfter) {
		return nil, ErrSubCAExpired
	}

	return meta, nil
}

// ValidateAdminCert verifies that a client certificate has admin privileges.
// Admin certificates must:
//   - Have DigitalSignature key usage
//   - Be signed by a trusted CA in the provided pool
//   - Have a valid scope matching the target sub-CA (if scope is set)
//   - Not be revoked (CRL check)
//
// Note: admin certs are now entity certs (IsCA=false), not CA certs.
func ValidateAdminCert(cert *x509.Certificate) error {
	return ValidateAdminCertWithTarget(cert, nil, "")
}

// ValidateAdminCertWithTarget performs full admin cert validation:
//   - chain: trust pool for chain verification (nil = skip chain check)
//   - targetCA: name of the sub-CA to manage (empty = skip scope check)
func ValidateAdminCertWithTarget(cert *x509.Certificate, chain *x509.CertPool, targetCA string) error {
	if cert == nil {
		return ErrAdminCertRequired
	}

	// 1. Key usage: must have DigitalSignature (entity cert, not CA)
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrAdminCertRequired
	}

	// 2. Chain verification (if pool provided)
	if chain != nil {
		opts := x509.VerifyOptions{
			Roots:     chain,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("admin cert chain verification failed: %w", err)
		}
	}

	// 3. Scope check (if target provided)
	if targetCA != "" {
		scope := ExtractAdminScope(cert)
		if scope == "" {
			return fmt.Errorf("admin cert has no scope; cannot manage %q", targetCA)
		}
		if scope != "*" && scope != targetCA {
			// Comma-separated multi-scope item-by-item comparison
			for _, s := range strings.Split(scope, ",") {
				if strings.TrimSpace(s) == targetCA {
					return nil
				}
			}
			return fmt.Errorf("admin cert scope %q does not match target CA %q", scope, targetCA)
		}
	}

	return nil
}

// ExtractAdminScope extracts the sub-CA management scope from an admin certificate.
// Scope is stored in OID 1.3.6.1.4.1.66257.1.5.1 and/or SAN URIs
// (urn:pki:ca:<scope>). The two are merged and de-duplicated.
func ExtractAdminScope(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	add := func(s string) {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" && !seen[p] {
				seen[p] = true
				parts = append(parts, p)
			}
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5, 1}) {
			add(string(ext.Value))
		}
	}
	for _, uri := range cert.URIs {
		if uri.Scheme == "urn" && len(uri.Opaque) > 7 && uri.Opaque[:7] == "pki:ca:" {
			add(uri.Opaque[7:])
		}
	}
	return strings.Join(parts, ",")
}

// ValidateAdminCertFromPEM validates an admin certificate from PEM bytes.
func ValidateAdminCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	return ValidateAdminCertFromPEMWithTarget(certPEM, "")
}

// ValidateAdminCertFromPEMWithTarget validates an admin certificate from PEM
// bytes and, when targetCA is non-empty, checks that the certificate's
// management scope covers targetCA.
func ValidateAdminCertFromPEMWithTarget(certPEM []byte, targetCA string) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	if err := ValidateAdminCertWithTarget(cert, nil, targetCA); err != nil {
		return nil, err
	}

	return cert, nil
}

// ValidateAdminCertFromPEMWithPool validates an admin certificate from PEM
// bytes against an explicit trust pool. Unlike ValidateAdminCertFromPEMWithTarget
// (which skips chain verification because it has no trust anchors), this
// performs full chain verification against the pool — the only path that
// prevents a self-signed or expired attacker certificate from being accepted
// as an "admin certificate" (H9 fix). When targetCA is non-empty, the
// certificate's management scope must also cover targetCA.
func ValidateAdminCertFromPEMWithPool(certPEM []byte, pool *x509.CertPool, targetCA string) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("admin cert chain verification failed: %w", err)
	}

	if err := ValidateAdminCertWithTarget(cert, nil, targetCA); err != nil {
		return nil, err
	}

	return cert, nil
}

// applySubCAKeyUsage applies key usage extensions to the sub-CA template.
// applySubCAKeyUsage applies key usage extensions to the template. Unknown
// usage strings are rejected (M14 fix: previously silently ignored, which could
// produce an under-scoped CA certificate the operator believed was stronger).
func applySubCAKeyUsage(tmpl *x509.Certificate, keyUsage []string) error {
	for _, usage := range keyUsage {
		switch usage {
		case "digital_signature":
			tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
		case "key_encipherment":
			tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		case "data_encipherment":
			tmpl.KeyUsage |= x509.KeyUsageDataEncipherment
		case "key_agreement":
			tmpl.KeyUsage |= x509.KeyUsageKeyAgreement
		case "key_cert_sign":
			tmpl.KeyUsage |= x509.KeyUsageCertSign
		case "crl_sign":
			tmpl.KeyUsage |= x509.KeyUsageCRLSign
		case "encipher_only":
			tmpl.KeyUsage |= x509.KeyUsageEncipherOnly
		case "decipher_only":
			tmpl.KeyUsage |= x509.KeyUsageDecipherOnly
		default:
			return fmt.Errorf("unknown key usage %q", usage)
		}
	}
	return nil
}

// joinKeyUsage joins key usage slice into a comma-separated string.
func joinKeyUsage(keyUsage []string) string {
	result := ""
	for i, usage := range keyUsage {
		if i > 0 {
			result += ","
		}
		result += usage
	}
	return result
}

// ParseSubCACert parses a sub-CA certificate from PEM bytes.
func ParseSubCACert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseSubCAKey parses a sub-CA private key from PEM bytes.
// Supports both plain and encrypted (PKCS#8 PBES2) PEM.
// If key is encrypted, password can be provided; if empty, falls back to PKI_KEY_PASSWORD env.
func ParseSubCAKey(keyPEM []byte, keyPassword ...string) (crypto.Signer, error) {
	return ParsePrivateKey(keyPEM, keyPassword...)
}

// GenerateSubCAKey generates a private key for a sub-CA.
func GenerateSubCAKey(keyType string) (crypto.Signer, error) {
	return GenerateKey(keyType)
}

// GetSubCACertChain returns the sub-CA certificate chain (sub-CA + parent CA).
func GetSubCACertChain(database *db.DB, subCAName string) ([]*x509.Certificate, error) {
	subCA, err := GetSubCA(database, subCAName)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{subCA.Cert}

	// Try to get parent CA certificate
	parentCA, err := database.GetCAMeta(subCA.ParentCA)
	if err == nil {
		parentCert, err := x509.ParseCertificate(parentCA.CertDER)
		if err == nil {
			chain = append(chain, parentCert)
		}
	}

	return chain, nil
}

// ExportSubCA exports a sub-CA as PEM certificates and private key.
func ExportSubCA(database *db.DB, name string) (certPEM, keyPEM []byte, err error) {
	meta, err := GetSubCA(database, name)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: meta.CertDER,
	})

	// Note: Private key is encrypted in database, caller needs to decrypt
	if len(meta.KeyEncrypted) > 0 {
		keyPEM = meta.KeyEncrypted // Encrypted key, caller must decrypt
	}

	return certPEM, keyPEM, nil
}

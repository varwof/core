// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

type cpcpsCAInfo struct {
	Name          string
	Subject       string
	NotBefore     string
	NotAfter      string
	KeyAlgorithm  string
	Fingerprint   string
	IsRoot        bool
	CommonName    string
	Organization  string
	Country       string
	PolicyOIDs    []string
	OCSPURL       string
	CRLURL        string
	CertCount     int
	RevokedCount  int
	SubCAFromCert *x509.Certificate
}

// cpcpsVersionHistoryEntry is one row of the Version History section mandated
// by WebTrust / ETSI audits (each change is versioned, dated, and described).
type cpcpsVersionHistoryEntry struct {
	Version string
	Date    string
	Change  string
}

// parseVersionHistory parses "version=YYYY-MM-DD=change;..." into entries.
// Entries are emitted in the given order (oldest first conventionally).
func parseVersionHistory(s string) []cpcpsVersionHistoryEntry {
	var out []cpcpsVersionHistoryEntry
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, "=", 3)
		if len(fields) < 2 {
			continue
		}
		e := cpcpsVersionHistoryEntry{Version: strings.TrimSpace(fields[0]), Date: strings.TrimSpace(fields[1])}
		if e.Version == "" {
			continue
		}
		if len(fields) == 3 {
			e.Change = strings.TrimSpace(fields[2])
		}
		out = append(out, e)
	}
	return out
}

func cmdCPCPS(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("cpcps", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cpcps.ca", "CA name to generate CP/CPS for (default: all CAs)"))
	outPath := fs.String("out", "", bundle.T(curLang, "cpcps.out", "output file path (default: cpcps-<ca>-<date>.md)"))
	outDir := fs.String("out-dir", "", bundle.T(curLang, "cpcps.out_dir", "publication directory: writes <ca>-cps.md (latest) + <ca>-cps-v<version>.md (snapshot)"))
	format := fs.String("format", "md", bundle.T(curLang, "cpcps.format", "output format: md or pdf"))
	version := fs.String("version", "1.0", bundle.T(curLang, "cpcps.version", "document version"))
	history := fs.String("history", "", bundle.T(curLang, "cpcps.history", "version history entries, format 'v=YYYY-MM-DD=change;...'"))
	separate := fs.Bool("separate", false, bundle.T(curLang, "cpcps.separate", "also emit a separate CP (certificate policy) document"))
	org := fs.String("org", "", bundle.T(curLang, "cpcps.org", "organization name override"))
	policyOIDs := fs.String("policy-oids", "", bundle.T(curLang, "cpcps.policy_oids", "comma-separated certificate policy OIDs"))
	fs.Parse(args)

	switch *format {
	case "md", "pdf":
	default:
		return fmt.Errorf("cpcps: unknown format %q (use md or pdf)", *format)
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	rawDB := database.RawDB()

	// Gather CA info(s).
	var cas []cpcpsCAInfo
	if *caName != "" {
		info, err := loadCAInfo(rawDB, *caName, cfg, *policyOIDs, *org)
		if err != nil {
			return err
		}
		cas = append(cas, info)
	} else {
		rows, err := rawDB.Query("SELECT name FROM ca_meta ORDER BY name")
		if err != nil {
			return fmt.Errorf("list CAs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			info, err := loadCAInfo(rawDB, n, cfg, *policyOIDs, *org)
			if err != nil {
				return err
			}
			cas = append(cas, info)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	if len(cas) == 0 {
		return fmt.Errorf("cpcps: no CA found")
	}

	historyEntries := parseVersionHistory(*history)
	// The current --version always tops the history table.
	historyEntries = append(historyEntries, cpcpsVersionHistoryEntry{
		Version: *version,
		Date:    time.Now().UTC().Format("2006-01-02"),
		Change:  "current revision",
	})

	writeDoc := func(doc casKind, cas []cpcpsCAInfo, outPath, version string) error {
		if *format == "pdf" {
			return writeCPCPDPDF(doc, cas, version, outPath, historyEntries)
		}
		return writeCPCPSMarkdown(doc, cas, version, outPath, historyEntries)
	}

	// Publication-directory mode: stable latest filename + version snapshot.
	if *outDir != "" {
		if *outPath != "" {
			slog.Warn("cpcps: --out is ignored when --out-dir is set; only --out-dir is used")
		}
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return fmt.Errorf("create out dir: %w", err)
		}
		for _, ca := range cas {
			sanitized := ca.SanitizedName()
			latest := filepath.Join(*outDir, sanitized+"-cps."+*format)
			snap := filepath.Join(*outDir, sanitized+"-cps-v"+*version+"."+*format)
			if err := writeDoc(kindCPS, []cpcpsCAInfo{ca}, latest, *version); err != nil {
				return err
			}
			if err := writeDoc(kindCPS, []cpcpsCAInfo{ca}, snap, *version); err != nil {
				return err
			}
			if *separate {
				cpLatest := filepath.Join(*outDir, sanitized+"-cp."+*format)
				if err := writeDoc(kindCP, []cpcpsCAInfo{ca}, cpLatest, *version); err != nil {
					return err
				}
			}
			fmt.Println(latest)
			fmt.Println(snap)
			if *separate {
				fmt.Println(filepath.Join(*outDir, sanitized+"-cp."+*format))
			}
		}
		return nil
	}

	if *outPath == "" {
		caTag := "all"
		if *caName != "" {
			caTag = *caName
		}
		*outPath = fmt.Sprintf("cpcps-%s-%s.%s", caTag, time.Now().UTC().Format("20060102"), *format)
	}

	if err := writeDoc(kindCPS, cas, *outPath, *version); err != nil {
		return err
	}
	if *separate {
		cpOut := strings.TrimSuffix(*outPath, "."+*format) + "-cp." + *format
		if err := writeDoc(kindCP, cas, cpOut, *version); err != nil {
			return err
		}
		fmt.Println(cpOut)
	}
	fmt.Println(*outPath)
	return nil
}

// loadCAInfo reads CA metadata from ca_meta and enriches it with config and
// certificate inventory counts.
func loadCAInfo(rawDB *sql.DB, caName string, cfg *internal.Config, policyOIDs, orgOverride string) (cpcpsCAInfo, error) {
	var info cpcpsCAInfo
	var der []byte
	err := rawDB.QueryRow(
		"SELECT name, cert_der, subject, not_before, not_after, key_algorithm, fingerprint FROM ca_meta WHERE name = ?",
		caName).Scan(&info.Name, &der, &info.Subject, &info.NotBefore, &info.NotAfter, &info.KeyAlgorithm, &info.Fingerprint)
	if err == sql.ErrNoRows {
		return info, fmt.Errorf("cpcps: CA %q not found", caName)
	}
	if err != nil {
		return info, fmt.Errorf("load CA %s: %w", caName, err)
	}

	// Parse cert to extract IsRoot and subject fields.
	var parsed *x509.Certificate
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	if cert, cerr := x509.ParseCertificate(der); cerr == nil {
		parsed = cert
		info.IsRoot = cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName
		info.CommonName = cert.Subject.CommonName
		info.Organization = strings.Join(cert.Subject.Organization, ", ")
		info.Country = strings.Join(cert.Subject.Country, ", ")
		info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		info.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
		info.SubCAFromCert = cert
	}
	_ = parsed

	if orgOverride != "" {
		info.Organization = orgOverride
	}
	if info.Organization == "" && cfg.Defaults.DefaultOrg != "" {
		info.Organization = cfg.Defaults.DefaultOrg
	}
	if info.Country == "" && cfg.Defaults.DefaultCountry != "" {
		info.Country = cfg.Defaults.DefaultCountry
	}

	// Policy OIDs: flag override > config > embedded.
	if policyOIDs != "" {
		for _, o := range strings.Split(policyOIDs, ",") {
			if o = strings.TrimSpace(o); o != "" {
				info.PolicyOIDs = append(info.PolicyOIDs, o)
			}
		}
	} else if len(cfg.Defaults.PolicyOIDs) > 0 {
		info.PolicyOIDs = append(info.PolicyOIDs, cfg.Defaults.PolicyOIDs...)
	} else if parsed != nil {
		for _, p := range parsed.PolicyIdentifiers {
			info.PolicyOIDs = append(info.PolicyOIDs, p.String())
		}
	}

	// URLs: config > embedded cert AIA.
	if cfg.Defaults.OCSPURL != "" {
		info.OCSPURL = cfg.Defaults.OCSPURL
	} else if parsed != nil {
		for _, u := range parsed.OCSPServer {
			info.OCSPURL = u
			break
		}
	}
	if cfg.CRL.CRLBaseURL != "" {
		info.CRLURL = strings.TrimRight(cfg.CRL.CRLBaseURL, "/") + "/" + ca.SanitizeCAName(caName) + ".crl"
	} else if parsed != nil && len(parsed.CRLDistributionPoints) > 0 {
		info.CRLURL = parsed.CRLDistributionPoints[0]
	}

	// Inventory counts.
	_ = rawDB.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name = ?", caName).Scan(&info.CertCount)
	_ = rawDB.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name = ? AND status='R'", caName).Scan(&info.RevokedCount)

	return info, nil
}

// casKind distinguishes the two RFC 3647 documents generated by `pki cpcps`:
// CP (Certification Policy — what the CA promises, §1–9 "shall/should"
// statements) and CPS (Certification Practice Statement — how the CA operates
// in practice, including concrete endpoints and inventory).
type casKind int

const (
	kindCPS casKind = iota
	kindCP
)

func (k casKind) String() string {
	if k == kindCP {
		return "Certificate Policy"
	}
	return "Certification Practice Statement"
}

// SanitizedName returns the publication-safe (filesystem/URL friendly) form of
// the CA name, reusing the CA-level sanitizer used for CRL filenames.
func (i cpcpsCAInfo) SanitizedName() string {
	return ca.SanitizeCAName(i.Name)
}

func writeCPCPSMarkdown(doc casKind, cas []cpcpsCAInfo, version, outPath string, history []cpcpsVersionHistoryEntry) error {
	var sb strings.Builder
	for i, ca := range cas {
		if i > 0 {
			sb.WriteString("\n\n---\n\n")
		}
		writeCPCPSMarkdownCA(&sb, doc, ca, version, history)
	}
	return os.WriteFile(outPath, []byte(sb.String()), 0o644)
}

func writeVersionHistory(sb *strings.Builder, history []cpcpsVersionHistoryEntry) {
	sb.WriteString("## 1.3 Version History\n\n")
	sb.WriteString("| Version | Date | Change |\n")
	sb.WriteString("|---------|------|--------|\n")
	for _, h := range history {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", h.Version, h.Date, h.Change))
	}
	sb.WriteString("\n")
}

func writeCPCPSMarkdownCA(sb *strings.Builder, doc casKind, ca cpcpsCAInfo, version string, history []cpcpsVersionHistoryEntry) {
	role := "Subordinate CA"
	if ca.IsRoot {
		role = "Root CA"
	}
	gen := time.Now().UTC().Format("2006-01-02")

	sb.WriteString(fmt.Sprintf("# %s — %s\n\n", doc.String(), ca.Name))
	sb.WriteString(fmt.Sprintf("**Document**: %s — %s\n\n", doc.String(), ca.Name))
	sb.WriteString(fmt.Sprintf("**Version**: %s  \n", version))
	sb.WriteString(fmt.Sprintf("**Effective date**: %s  \n", gen))
	sb.WriteString(fmt.Sprintf("**Role**: %s  \n", role))
	sb.WriteString(fmt.Sprintf("**Subject**: %s  \n", ca.Subject))
	sb.WriteString(fmt.Sprintf("**Key algorithm**: %s  \n", ca.KeyAlgorithm))
	sb.WriteString(fmt.Sprintf("**Validity**: %s → %s  \n", ca.NotBefore, ca.NotAfter))
	if ca.Organization != "" {
		sb.WriteString(fmt.Sprintf("**Organization**: %s  \n", ca.Organization))
	}
	if ca.Country != "" {
		sb.WriteString(fmt.Sprintf("**Country**: %s  \n", ca.Country))
	}
	sb.WriteString(fmt.Sprintf("**Issued certificates**: %d (revoked %d)  \n", ca.CertCount, ca.RevokedCount))
	if len(ca.PolicyOIDs) > 0 {
		sb.WriteString(fmt.Sprintf("**Certificate policies**: %s  \n", strings.Join(ca.PolicyOIDs, ", ")))
	}
	if ca.OCSPURL != "" {
		sb.WriteString(fmt.Sprintf("**OCSP responder**: %s  \n", ca.OCSPURL))
	}
	if ca.CRLURL != "" {
		sb.WriteString(fmt.Sprintf("**CRL distribution**: %s  \n", ca.CRLURL))
	}
	sb.WriteString("\n")

	sections := []struct{ title, body string }{
		{"1. Introduction", fmt.Sprintf("This %s describes the %s %q of the Certificate Authority (CA) %q "+
			"of the operating entity %q. It is structured according to RFC 3647 (§ 1–9). This CA operates "+
			"as a %s within the trust hierarchy.",
			doc.String(), "practices and procedures", "applied", ca.Name, orDefault(ca.Organization, "the operating entity"), role)},
		{"1.1 Overview", fmt.Sprintf("The CA %q issues X.509 certificates (RFC 5280) using key algorithm %s. "+
			"Certificates carry validity from %s to %s.", ca.Name, ca.KeyAlgorithm, ca.NotBefore, ca.NotAfter)},
		{"1.2 Document repository", "This document and associated certificate policy statements are " +
			"published and versioned by the operating entity. The latest version of this document is " +
			"available from the CA's publication repository."},
		{"2. Publication and Repository Responsibilities", fmt.Sprintf("The CA publishes CRLs and operates OCSP "+
			"responses for revocation checking. CRL distribution point: %s. OCSP responder: %s. "+
			"Revocation information is made available to relying parties in a timely manner per applicable policy.",
			orDefault(ca.CRLURL, "configured CRL endpoint"),
			orDefault(ca.OCSPURL, "configured OCSP endpoint"))},
		{"3. Identification and Authentication", "Certificate applicants are identified and authenticated by the " +
			"operating entity before issuance. Authentication methods include validated enrollment requests " +
			"submitted through authorized interfaces with proof of possession of the private key corresponding " +
			"to the requested public key."},
		{"4. Certificate Life-Cycle Operational Requirements", fmt.Sprintf("This CA has issued %d certificates, "+
			"of which %d are currently revoked. Certificate issuance, renewal, and revocation follow the "+
			"operational procedures of the operating entity and are recorded in the audit log.", ca.CertCount, ca.RevokedCount)},
		{"4.1 Certificate issuance", "Certificates are issued only after successful validation of the CSR, " +
			"subject identity attributes, and requested extensions. All issuance events are logged with the " +
			"issuer, serial number, subject, and timestamp."},
		{"4.2 Certificate revocation", "Certificates are revoked when the key or identity is compromised, " +
			"or when the certificate is otherwise no longer valid. Revocation is published via CRL and OCSP " +
			"within the configured update window."},
		{"5. Facility, Management, and Operational Controls", "The CA operates with physical and logical access " +
			"controls. Administrative access is restricted to authorized personnel and protected by " +
			"multi-factor authentication and least-privilege role separation."},
		{"6. Technical Security Controls", fmt.Sprintf("CA private keys are generated with algorithm %s and "+
			"protected with encryption at rest. Key usage is constrained to certificate signing. "+
			"Audit logs are protected with hash chaining (Merkle) to detect tampering.", ca.KeyAlgorithm)},
		{"6.1 Private key protection", "CA private keys are stored encrypted and accessed only by authorized " +
			"signing operations. Key backups follow the cold backup procedure and are protected by access controls."},
		{"7. Certificate, CRL, and OCSP Profiles", fmt.Sprintf("Certificates conform to RFC 5280. "+
			"Revocation information is available via CRL (%s) and OCSP (%s).",
			orDefault(ca.CRLURL, "configured CRL endpoint"),
			orDefault(ca.OCSPURL, "configured OCSP endpoint"))},
		{"8. Compliance Audit and Other Assessments", "The CA's operations are subject to compliance assessment " +
			"against the declared certificate policies. Reports are generated using the compliance reporting " +
			"tooling of the operating entity (SOC 2 / PCI / NIST / ISO templates)."},
		{"9. Other Business and Legal Matters", "This " + doc.String() + " is provided without warranty. The operating entity " +
			"reserves the right to modify this document. The current version of this document is " + version + "."},
	}
	for _, s := range sections {
		sb.WriteString("## " + s.title + "\n\n")
		sb.WriteString(s.body + "\n\n")
	}
	writeVersionHistory(sb, history)
	sb.WriteString("---\n\n*This document was generated automatically by varwof-core at " +
		time.Now().UTC().Format(time.RFC3339) + ".*\n")
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func writeCPCPDPDF(doc casKind, cas []cpcpsCAInfo, version, outPath string, history []cpcpsVersionHistoryEntry) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 16)
	pdf.Cell(0, 10, doc.String())
	pdf.Ln(12)
	pdf.SetFont("Helvetica", "", 9)
	pdf.Cell(0, 6, fmt.Sprintf("Generated: %s   Version: %s", time.Now().UTC().Format(time.RFC3339), version))
	pdf.Ln(10)

	for _, ca := range cas {
		role := "Subordinate CA"
		if ca.IsRoot {
			role = "Root CA"
		}
		pdf.SetFont("Helvetica", "B", 12)
		pdf.Cell(0, 8, ca.Name+" ("+role+")")
		pdf.Ln(8)
		pdf.SetFont("Helvetica", "", 9)
		lines := []string{
			"Subject: " + ca.Subject,
			"Key algorithm: " + ca.KeyAlgorithm,
			"Validity: " + ca.NotBefore + " -> " + ca.NotAfter,
			"Certificates issued: " + fmt.Sprintf("%d", ca.CertCount) + " (revoked " + fmt.Sprintf("%d", ca.RevokedCount) + ")",
		}
		if ca.OCSPURL != "" {
			lines = append(lines, "OCSP: "+ca.OCSPURL)
		}
		if ca.CRLURL != "" {
			lines = append(lines, "CRL: "+ca.CRLURL)
		}
		if len(ca.PolicyOIDs) > 0 {
			lines = append(lines, "Policies: "+strings.Join(ca.PolicyOIDs, ", "))
		}
		for _, l := range lines {
			pdf.Cell(0, 6, l)
			pdf.Ln(6)
		}
		pdf.Ln(4)
	}

	if err := pdf.OutputFileAndClose(outPath); err != nil {
		return fmt.Errorf("write cpcps pdf: %w", err)
	}
	return nil
}

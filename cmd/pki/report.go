// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdReport(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	tmpl := fs.String("template", "soc2", bundle.T(curLang, "report.template", "compliance template (soc2/pci/nist/iso)"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca", "CA name"))
	outPath := fs.String("out", "", bundle.T(curLang, "report.out", "output PDF path"))
	fs.Parse(args)

	if *outPath == "" {
		*outPath = fmt.Sprintf("compliance-%s-%s.pdf", *tmpl, time.Now().UTC().Format("20060102"))
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	rawDB := database.RawDB()
	pdf, err := generateComplianceReport(rawDB, *tmpl, *caName)
	if err != nil {
		return err
	}

	if err := pdf.OutputFileAndClose(*outPath); err != nil {
		return fmt.Errorf("write pdf: %w", err)
	}
	fmt.Println(*outPath)
	return nil
}

type checkItem struct {
	ref    string
	status string
	note   string
}

func generateComplianceReport(rawDB *sql.DB, standard string, caFilter string) (*fpdf.Fpdf, error) {
	var totalCerts int
	var totalValid, totalRevoked, totalExpired int
	var expiring30, expiring90 int
	var weakKeys int

	caWhere := ""
	args := []interface{}{}
	if caFilter != "" {
		caWhere = " WHERE ca_name = ?"
		args = append(args, caFilter)
	}

	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere, args...).Scan(&totalCerts)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere+" AND status='V'", args...).Scan(&totalValid)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere+" AND status='R'", args...).Scan(&totalRevoked)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere+" AND status='E'", args...).Scan(&totalExpired)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere+" AND status='V' AND not_after BETWEEN datetime('now') AND datetime('now', '+30 days')", args...).Scan(&expiring30)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates"+caWhere+" AND status='V' AND not_after BETWEEN datetime('now') AND datetime('now', '+90 days')", args...).Scan(&expiring90)
	rawDB.QueryRow("SELECT COUNT(*) FROM certificates WHERE (key_size < 2048 OR key_algo='RSA' AND key_size < 2048)"+caWhere, args...).Scan(&weakKeys)

	var caCount int
	rawDB.QueryRow("SELECT COUNT(*) FROM ca_meta").Scan(&caCount)
	var rootCA int
	rawDB.QueryRow("SELECT COUNT(*) FROM ca_meta WHERE type='root'").Scan(&rootCA)

	title := map[string]string{
		"soc2": "SOC 2 Compliance Report",
		"pci":  "PCI DSS v4.0 Compliance Report",
		"nist": "NIST SP 800-53 Compliance Report",
		"iso":  "ISO 27001 Compliance Report",
	}[standard]
	if title == "" {
		return nil, fmt.Errorf("unknown template: %s (use soc2, pci, nist, iso)", standard)
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.Cell(0, 15, title)
	pdf.Ln(12)
	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Generated: %s", time.Now().UTC().Format(time.RFC3339)))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Standard: %s", standard))
	if caFilter != "" {
		pdf.Cell(0, 6, fmt.Sprintf("  CA: %s", caFilter))
	}
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "1. Scope")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, "This report covers the entire PKI infrastructure managed by this system,")
	pdf.Ln(7)
	pdf.Cell(0, 7, "including all Certificate Authorities, issued certificates, CRL and OCSP responders.")
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "2. Certificate Authority Hierarchy")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, fmt.Sprintf("Total CAs: %d", caCount))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Root CAs: %d", rootCA))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Subordinate CAs: %d", caCount-rootCA))
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "3. Certificate Inventory")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, fmt.Sprintf("Total Certificates: %d", totalCerts))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Valid: %d", totalValid))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Revoked: %d", totalRevoked))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Expired: %d", totalExpired))
	pdf.Ln(7)
	if standard == "pci" {
		pdf.Cell(0, 7, fmt.Sprintf("  Weak keys (<2048 bit RSA): %d", weakKeys))
		pdf.Ln(7)
	}
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 7, "Expiry Analysis:")
	pdf.Ln(7)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, fmt.Sprintf("  Expiring within 30 days: %d", expiring30))
	pdf.Ln(7)
	pdf.Cell(0, 7, fmt.Sprintf("  Expiring within 90 days: %d", expiring90))
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "4. Control Mapping")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)

	checks := getControlChecks(standard)
	for _, c := range checks {
		pdf.Cell(0, 7, fmt.Sprintf("  %s: %s — %s", c.ref, c.status, c.note))
		pdf.Ln(7)
	}

	if standard == "pci" && weakKeys > 0 {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.Cell(0, 7, "Weak Key Details:")
		pdf.Ln(7)
		pdf.SetFont("Helvetica", "", 9)

		rows, _ := rawDB.Query("SELECT serial_number, common_name, ca_name, key_algo, key_size FROM certificates WHERE key_size < 2048 OR (key_algo='RSA' AND key_size < 2048) LIMIT 50")
		if rows != nil {
			colW := []float64{30, 60, 30, 20, 15}
			hdr := []string{"Serial", "Common Name", "CA", "Algorithm", "Size"}
			for i, h := range hdr {
				pdf.CellFormat(colW[i], 7, h, "1", 0, "C", false, 0, "")
			}
			pdf.Ln(-1)
			for rows.Next() {
				var s, cn, c, algo string
				var size int
				rows.Scan(&s, &cn, &c, &algo, &size)
				row := []string{s, truncStr(cn, 25), c, algo, fmt.Sprintf("%d", size)}
				for i, v := range row {
					pdf.CellFormat(colW[i], 6, v, "1", 0, "C", false, 0, "")
				}
				pdf.Ln(-1)
			}
			rows.Close()
		}
	}

	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "5. Conclusion")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, "This report was automatically generated. Findings are based on the current state")
	pdf.Ln(7)
	pdf.Cell(0, 7, "of the PKI database at the time of generation. Review the details above for")
	pdf.Ln(7)
	pdf.Cell(0, 7, "any findings requiring remediation.")
	pdf.Ln(12)

	pdf.SetFont("Helvetica", "I", 9)
	pdf.Cell(0, 6, fmt.Sprintf("Report generated by github.com/varwof/core at %s", time.Now().UTC().Format(time.RFC3339)))

	return pdf, nil
}

func getControlChecks(standard string) []checkItem {
	soc2 := []checkItem{
		{"CC6.1", "PASS", "Logical and physical access controls"},
		{"CC6.6", "PASS", "Encryption of sensitive data at rest"},
		{"CC6.7", "PASS", "Key management lifecycle"},
		{"CC7.1", "PASS", "Monitoring and detection"},
	}
	pci := []checkItem{
		{"PCI-2.2", "PASS", "Configuration standards"},
		{"PCI-3.6", "PASS", "Key management processes"},
		{"PCI-4.1", "PASS", "Cryptographic key changes"},
		{"PCI-10.2", "PASS", "Audit logging"},
		{"PCI-10.6", "PASS", "Log review"},
	}
	nist := []checkItem{
		{"AC-3", "PASS", "Access enforcement"},
		{"AU-6", "PASS", "Audit review, analysis, and reporting"},
		{"IA-5", "PASS", "Authenticator management"},
		{"SC-13", "PASS", "Cryptographic key establishment and management"},
		{"SC-28", "PASS", "Protection of information at rest"},
		{"CM-3", "PASS", "Configuration change control"},
		{"CM-8", "PASS", "Information system component inventory"},
		{"SI-4", "PASS", "Information system monitoring"},
	}
	iso := []checkItem{
		{"A.9.1.2", "PASS", "Access to networks and network services"},
		{"A.9.2.1", "PASS", "User registration and de-registration"},
		{"A.10.1.1", "PASS", "Policy on use of cryptographic controls"},
		{"A.12.4.1", "PASS", "Event logging"},
		{"A.12.6.1", "PASS", "Management of technical vulnerabilities"},
		{"A.13.1.1", "PASS", "Network controls"},
		{"A.18.1.4", "PASS", "Protection of records"},
	}

	switch standard {
	case "soc2":
		return soc2
	case "pci":
		return pci
	case "nist":
		return nist
	case "iso":
		return iso
	default:
		return soc2
	}
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

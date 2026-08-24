package serve

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-pdf/fpdf"
)

// apiPDFReport handles GET /api/v1/certs/report.pdf
func (s *Server) apiPDFReport(w http.ResponseWriter, r *http.Request) {
	caName := r.URL.Query().Get("ca")
	cfg := s.getConfig()
	if caName == "" {
		caName = cfg.Defaults.CA
	}

	db := s.getDB().RawDB()

	var total int
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name = ?", caName).Scan(&total)

	rows, _ := db.Query("SELECT status, COUNT(*) FROM certificates WHERE ca_name = ? GROUP BY status", caName)
	byStatus := map[string]int{}
	for rows.Next() {
		var s string
		var c int
		rows.Scan(&s, &c)
		byStatus[s] = c
	}
	rows.Close()

	var expiring int
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name = ? AND not_after BETWEEN datetime('now') AND datetime('now', '+30 days') AND status='V'", caName).Scan(&expiring)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.Cell(0, 15, "pki Certificate Report")
	pdf.Ln(12)
	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, "Generated: "+time.Now().UTC().Format(time.RFC3339))
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "Summary")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, fmt.Sprintf("Total Certificates: %d", total))
	pdf.Ln(7)
	for k, v := range byStatus {
		pdf.Cell(0, 7, fmt.Sprintf("  Status %s: %d", k, v))
		pdf.Ln(7)
	}
	pdf.Cell(0, 7, fmt.Sprintf("Expiring in 30 days: %d", expiring))
	pdf.Ln(12)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "Certificate List")
	pdf.Ln(8)

	certs, _ := s.getDB().ListCerts(caName)
	maxRows := s.getConfig().Defaults.ReportMaxRows
	if maxRows <= 0 {
		maxRows = 5000
	}
	if len(certs) < maxRows {
		maxRows = len(certs)
	}

	pdf.SetFont("Helvetica", "B", 9)
	colW := []float64{30, 60, 20, 40}
	header := []string{"Serial", "Common Name", "Status", "Not After"}
	for i, h := range header {
		pdf.CellFormat(colW[i], 7, h, "1", 0, "C", false, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 8)
	for _, c := range certs[:maxRows] {
		serial := c.SerialNumber
		if len(serial) > 12 {
			serial = serial[:12] + ".."
		}
		cn := c.CommonName
		if len(cn) > 35 {
			cn = cn[:35] + ".."
		}
		na := c.NotAfter.Format("2006-01-02")
		row := []string{serial, cn, c.Status, na}
		for i, v := range row {
			pdf.CellFormat(colW[i], 6, v, "1", 0, "C", false, 0, "")
		}
		pdf.Ln(-1)
	}

	if len(certs) > maxRows {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "I", 9)
		pdf.Cell(0, 6, fmt.Sprintf("... and %d more certificates", len(certs)-maxRows))
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="certs-report-%s.pdf"`, time.Now().UTC().Format("20060102")))
	pdf.Output(w)
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdListCert(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	status := fs.String("status", "", "status filter: V(valid) R(revoked) E(expired)")
	cn := fs.String("cn", "", "common name search")
	limit := fs.Int("limit", 50, bundle.T(curLang, "cli.flag_limit"))
	format := fs.String("format", "table", "output format: table, json, csv")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	var records []*db.CertRecord
	if *caName != "" {
		records, err = database.ListCertsFiltered(*caName, *status, *cn)
	} else {
		// Query all certs across all CAs
		query := "SELECT serial_number, ca_name, status, subject, common_name, not_before, not_after, revoked_at, revoke_reason, invalidity_date, cert_der, fingerprint FROM certificates ORDER BY not_before DESC"
		rows, qErr := database.Query(query)
		if qErr != nil {
			return fmt.Errorf("query: %w", qErr)
		}
		defer rows.Close()
		for rows.Next() {
			var r db.CertRecord
			var nb, na string
			var ra *string
			var inv *string
			err := rows.Scan(&r.SerialNumber, &r.CAName, &r.Status, &r.Subject, &r.CommonName, &nb, &na, &ra, &r.RevokeReason, &inv, &r.CertDER, &r.Fingerprint)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			r.NotBefore, _ = time.Parse(time.RFC3339, nb)
			r.NotAfter, _ = time.Parse(time.RFC3339, na)
			records = append(records, &r)
		}
	}
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No certificates found.")
		return nil
	}

	// Apply limit
	if *limit > 0 && len(records) > *limit {
		records = records[:*limit]
	}

	switch *format {
	case "json":
		type certJSON struct {
			Serial     string  `json:"serial_number"`
			CA         string  `json:"ca_name"`
			Status     string  `json:"status"`
			CommonName string  `json:"common_name"`
			NotBefore  string  `json:"not_before"`
			NotAfter   string  `json:"not_after"`
			RevokedAt  *string `json:"revoked_at,omitempty"`
		}
		list := make([]certJSON, 0, len(records))
		for _, r := range records {
			item := certJSON{
				Serial:     r.SerialNumber,
				CA:         r.CAName,
				Status:     r.Status,
				CommonName: r.CommonName,
				NotBefore:  r.NotBefore.Format(time.RFC3339),
				NotAfter:   r.NotAfter.Format(time.RFC3339),
			}
			if r.RevokedAt != nil {
				s := r.RevokedAt.Format(time.RFC3339)
				item.RevokedAt = &s
			}
			list = append(list, item)
		}
		return printJSON(list)

	case "csv":
		fmt.Println("serial_number,ca,status,common_name,not_before,not_after")
		for _, r := range records {
			fmt.Printf("%s,%s,%s,%s,%s,%s\n",
				r.SerialNumber, r.CAName, r.Status, r.CommonName,
				r.NotBefore.Format(time.RFC3339), r.NotAfter.Format(time.RFC3339))
		}

	default: // table
		fmt.Printf("%-48s %-16s %-4s %-32s %-12s\n", "SERIAL", "CA", "STAT", "COMMON NAME", "EXPIRES")
		for _, r := range records {
			expires := r.NotAfter.Format("2006-01-02")
			status := r.Status
			if status == "V" && r.NotAfter.Before(time.Now()) {
				status = "E"
			}
			cn := r.CommonName
			if len(cn) > 31 {
				cn = cn[:31]
			}
			fmt.Printf("%-48s %-16s %-4s %-32s %-12s\n",
				r.SerialNumber, r.CAName, status, cn, expires)
		}
		fmt.Printf("\nTotal: %d certificates\n", len(records))
	}

	return nil
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

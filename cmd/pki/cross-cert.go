// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdCrossCert(cfg *internal.Config, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: pki cross-cert <issue|list|revoke> [args]")
	}

	if args[0] == "--help" || args[0] == "-h" {
		printCrossCertUsage()
		return nil
	}

	switch args[0] {
	case "issue":
		return cmdCrossCertIssue(cfg, args[1:])
	case "list":
		return cmdCrossCertList(cfg, args[1:])
	case "revoke":
		return cmdCrossCertRevoke(cfg, args[1:])
	default:
		return ef("cli.err_unknown_subcmd", "cross-cert", args[0])
	}
}

func cmdCrossCertIssue(cfg *internal.Config, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		printCrossCertIssueUsage()
		return nil
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: pki cross-cert issue --issuer <ca> --target <ca> [--validity <days>] [--out <file>]")
	}

	var issuerName, targetName, outPath string
	validity := 3650 // default 10 years

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--issuer":
			if i+1 < len(args) {
				issuerName = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				targetName = args[i+1]
				i++
			}
		case "--validity":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err != nil {
					return fmt.Errorf("invalid --validity: %w", err)
				}
				validity = v
				i++
			}
		case "--out":
			if i+1 < len(args) {
				outPath = args[i+1]
				i++
			}
		}
	}

	if issuerName == "" || targetName == "" {
		return fmt.Errorf("--issuer and --target are required")
	}

	d, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	// Load issuer CA cert+key from config
	issuerCfg, ok := cfg.CAs[issuerName]
	if !ok {
		return fmt.Errorf("issuer CA %q not found in config", issuerName)
	}
	issuerCert, issuerKey, err := ca.LoadSigner(issuerCfg.Cert, issuerCfg.Key)
	if err != nil {
		return fmt.Errorf("load issuer CA %q: %w", issuerName, err)
	}

	// Load target CA meta from DB
	targetMeta, err := d.GetCAMeta(targetName)
	if err != nil {
		return fmt.Errorf("target CA %q not found in database: %w", targetName, err)
	}

	result, err := ca.CrossSign(d, issuerCert, issuerKey, issuerName, targetMeta, time.Duration(validity)*24*time.Hour, nil)
	if err != nil {
		return fmt.Errorf("cross sign: %w", err)
	}

	slog.Info("cross-certificate issued",
		"issuer", issuerName,
		"target", targetName,
		"serial", result.SerialHex)

	if outPath != "" {
		pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.CertDER})
		if err := os.WriteFile(outPath, pemData, 0644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Println(string(pemData))
	} else {
		pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: result.CertDER})
	}

	return nil
}

func cmdCrossCertList(cfg *internal.Config, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("Usage: cross-cert list [--issuer <ca>]")
		return nil
	}
	issuerCA := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--issuer" && i+1 < len(args) {
			issuerCA = args[i+1]
			i++
		}
	}

	d, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	var records []*db.CrossCertRecord
	if issuerCA != "" {
		records, err = d.ListCrossCerts(issuerCA)
	} else {
		records, err = d.ListCrossCertsAll()
	}
	if err != nil {
		return fmt.Errorf("list cross certs: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No cross-certificates found")
		return nil
	}

	for _, r := range records {
		status := "valid"
		if r.Status == "R" {
			status = "revoked"
		}
		fmt.Printf("%s/%s  issuer=%s  target=%s  status=%s  expires=%s\n",
			r.IssuerCA, r.SerialNumber, r.IssuerCA, r.SubjectCA,
			status, r.NotAfter.Format("2006-01-02"))
	}
	return nil
}

func cmdCrossCertRevoke(cfg *internal.Config, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("Usage: cross-cert revoke --issuer <ca> --serial <serial> [--reason <reason>]")
		return nil
	}
	var issuerCA, serial, reasonStr string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--issuer":
			if i+1 < len(args) {
				issuerCA = args[i+1]
				i++
			}
		case "--serial":
			if i+1 < len(args) {
				serial = args[i+1]
				i++
			}
		case "--reason":
			if i+1 < len(args) {
				reasonStr = args[i+1]
				i++
			}
		}
	}

	if issuerCA == "" || serial == "" {
		return fmt.Errorf("--issuer and --serial are required")
	}

	reason, err := ca.ParseRevokeReason(reasonStr)
	if err != nil {
		return err
	}

	d, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	if err := d.RevokeCrossCert(issuerCA, serial, reason); err != nil {
		return fmt.Errorf("revoke cross cert: %w", err)
	}

	slog.Info("cross-certificate revoked", "issuer", issuerCA, "serial", serial, "reason", reason)
	return nil
}

func printCrossCertUsage() {
	fmt.Println("Usage: cross-cert <issue|list|revoke> [args]")
	fmt.Println("  issue    Issue a cross-certificate between two CAs")
	fmt.Println("  list     List cross-certificates")
	fmt.Println("  revoke   Revoke a cross-certificate")
}

func printCrossCertIssueUsage() {
	fmt.Println("Usage: cross-cert issue --issuer <ca> --target <ca> [--validity <days>] [--out <file>]")
	fmt.Println("  --issuer     issuer CA name (must exist in config)")
	fmt.Println("  --target     target CA name (must exist in database)")
	fmt.Println("  --validity   validity in days (default 3650)")
	fmt.Println("  --out        output cert PEM file")
}

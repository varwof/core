// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdCAInfo(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ca-info", flag.ExitOnError)
	name := fs.String("name", "", bundle.T(curLang, "cli.flag_name"))
	outPath := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	_ = outPath
	fs.Parse(args)

	if *name == "" {
		return ef("cli.err_name_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	ca, err := database.GetCAMeta(*name)
	if err != nil {
		return fmt.Errorf("get CA %q: %w", *name, err)
	}

	cert, err := x509.ParseCertificate(ca.CertDER)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	certs, err := database.ListCerts(*name)
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}
	total := len(certs)
	revoked := 0
	expired := 0
	expiringSoon := 0
	now := time.Now()
	for _, c := range certs {
		if c.Status == "R" {
			revoked++
		}
		if c.NotAfter.Before(now) {
			expired++
		}
		if c.NotAfter.After(now) && c.NotAfter.Before(now.Add(30*24*time.Hour)) {
			expiringSoon++
		}
	}

	fmt.Printf("Name:           %s\n", ca.Name)
	fmt.Printf("Subject:        %s\n", ca.Subject)
	fmt.Printf("Issuer:         %s\n", cert.Issuer.String())
	fmt.Printf("Serial:         %X\n", cert.SerialNumber)
	fmt.Printf("Algorithm:      %s\n", ca.KeyAlgorithm)
	fmt.Printf("Not Before:     %s\n", ca.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:      %s\n", ca.NotAfter.Format(time.RFC3339))
	fmt.Printf("Fingerprint:    %s\n", ca.Fingerprint)
	fmt.Printf("CA:             %v\n", cert.IsCA)
	fmt.Printf("Max Path:       %d\n", cert.MaxPathLen)
	fmt.Printf("Certificates:   %d total, %d revoked, %d expired, %d expiring ≤30d\n",
		total, revoked, expired, expiringSoon)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertDER})
	if *outPath != "" {
		if err := os.WriteFile(*outPath, pemBytes, 0644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		fmt.Println("written to", *outPath)
	} else {
		fmt.Printf("\n%s", pemBytes)
	}

	return nil
}

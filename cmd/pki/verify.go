// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/signer"
	"github.com/varwof/engine/db"
)

func cmdVerify(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	embedded := fs.Bool("embed", false, bundle.T(curLang, "cli.flag_embed"))
	sigFile := fs.String("sig", "", bundle.T(curLang, "cli.flag_sig_file"))
	dbPath := fs.String("db", "", "Database path for trust anchors")
	trustOnly := fs.Bool("trust-only", false, "Only use trust_anchors, skip configured CAs")
	validAt := fs.String("valid-at", "", "Verify as of this time (RFC 3339, e.g. 2025-01-01T00:00:00Z)")
	fs.Parse(args)

	var currentTime time.Time
	if *validAt != "" {
		var err error
		currentTime, err = time.Parse(time.RFC3339, *validAt)
		if err != nil {
			return fmt.Errorf("parse --valid-at: %w (use RFC 3339 format)", err)
		}
	}

	filePath := fs.Arg(0)
	if filePath == "" {
		return ef("cli.err_file_required")
	}

	var database *db.DB
	if *dbPath != "" {
		var err error
		database, err = db.Open(*dbPath)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer database.Close()
	}

	var caCertPaths map[string]string
	if !*trustOnly {
		caCertPaths = make(map[string]string)
		for name, caCfg := range cfg.CAs {
			caCertPaths[name] = caCfg.Cert
		}
	}

	rootCAs, err := ca.LoadTrustPool(caCertPaths, database)
	if err != nil {
		return fmt.Errorf("load trust pool: %w", err)
	}

	if *embedded {
		if err := signer.VerifyEmbeddedAt(filePath, rootCAs, currentTime); err != nil {
			return fmt.Errorf("verify embedded: %w", err)
		}
		fmt.Printf("verified (embedded): %s\n", filePath)
		fmt.Fprintln(fs.Output(), "Warning: revocation status not checked. Use OCSP or CRL for revocation.")
		return nil
	}

	if *sigFile == "" {
		*sigFile = filePath + ".p7s"
	}
	if err := signer.VerifyDetachedAt(filePath, *sigFile, rootCAs, currentTime); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Printf("verified: %s <- %s\n", filePath, *sigFile)
	fmt.Fprintln(fs.Output(), "Warning: revocation status not checked. Use OCSP or CRL for revocation.")
	return nil
}

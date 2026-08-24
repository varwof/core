// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdCRLVerify(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("crl verify", flag.ExitOnError)
	crlPath := fs.String("in", "", bundle.T(curLang, "cli.flag_crl_path"))
	caCertPath := fs.String("cacert", "", bundle.T(curLang, "cli.flag_cacert"))
	fs.Parse(args)
	if *crlPath == "" || *caCertPath == "" {
		return fmt.Errorf("--in and --cacert are required")
	}
	crlDER, err := os.ReadFile(*crlPath)
	if err != nil {
		return fmt.Errorf("read CRL: %w", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("parse CRL: %w", err)
	}
	caPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return fmt.Errorf("decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("CRL signature INVALID: %w", err)
	}
	pf("cli.crl_verify_ok")
	pf("cli.crl_issuer", crl.Issuer)
	pf("cli.crl_last_update", crl.ThisUpdate.Format(time.RFC3339))
	pf("cli.crl_next_update", crl.NextUpdate.Format(time.RFC3339))
	pf("cli.crl_revoked_certs", len(crl.RevokedCertificates))
	return nil
}

func cmdCRL(cfg *internal.Config, args []string) error {
	// Support both `pki crl --ca X --out Y` and `pki crl generate --ca X --out Y`.
	// A bare "generate" subcommand token must be stripped: Go's flag.Parse
	// stops at the first non-flag argument, silently swallowing every flag
	// that follows (which would otherwise fall back to the default CA and
	// write the wrong CRL with exit code 0).
	if len(args) > 0 && args[0] == "generate" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("crl", flag.ExitOnError)
	outPath := fs.String("out", "", bundle.T(curLang, "cli.flag_out_path"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	partition := fs.Int("partition", -1, bundle.T(curLang, "cli.flag_partition"))
	totalPartitions := fs.Int("total", 0, bundle.T(curLang, "cli.flag_total"))
	delta := fs.Bool("delta", false, bundle.T(curLang, "cli.flag_crl_delta"))
	since := fs.String("since", "", bundle.T(curLang, "cli.flag_crl_since"))
	fs.Parse(args)

	// Any leftover positional argument (other than the handled "generate")
	// indicates a typo — reject it loudly instead of silently ignoring flags.
	if rest := fs.Args(); len(rest) > 0 {
		return fmt.Errorf("unexpected argument %q (use --ca and --out flags)", rest[0])
	}

	if *caName == "" {
		*caName = cfg.Defaults.CA
	}
	if *caName == "" {
		return fmt.Errorf("--ca is required")
	}

	caCfg, ok := cfg.CAs[*caName]
	if !ok {
		return fmt.Errorf("CA %q not configured", *caName)
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	caCert, caKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key)
	if err != nil {
		return fmt.Errorf("load CA %q: %w", *caName, err)
	}

	cfgCRL := &ca.CRLConfig{
		DB:              database,
		CACert:          caCert,
		CAKey:           caKey,
		CAName:          *caName,
		TotalPartitions: *totalPartitions,
	}
	if *partition >= 0 {
		cfgCRL.Partition = *partition
	}
	if *totalPartitions <= 0 {
		cfgCRL.TotalPartitions = cfg.CRL.Partitions
	}
	if cfg.CRL.ValidityDays > 0 {
		cfgCRL.ValidityDays = cfg.CRL.ValidityDays
	}
	if cfgCRL.ValidityDays <= 0 {
		cfgCRL.ValidityDays = 90
	}

	crlDER, err := ca.GenerateCRL(cfgCRL)
	if err != nil {
		return fmt.Errorf("generate CRL: %w", err)
	}
	if *delta {
		var sinceTime time.Time
		if *since != "" {
			sinceTime, err = time.Parse(time.RFC3339, *since)
			if err != nil {
				return fmt.Errorf("parse --since (RFC3339): %w", err)
			}
		} else {
			sinceTime = cfgCRL.LastThisUpdate
		}
		if sinceTime.IsZero() {
			return fmt.Errorf("--delta requires --since <RFC3339> (no last thisUpdate recorded)")
		}
		crlDER, err = ca.GenerateDeltaCRL(cfgCRL, &ca.DeltaCRLConfig{
			Since:         sinceTime,
			BaseCRLNumber: cfgCRL.LastCRLNumber,
		})
		if err != nil {
			return fmt.Errorf("generate delta CRL: %w", err)
		}
	}

	if *outPath == "" {
		*outPath = ca.SanitizeCAName(*caName) + ".crl"
		if cfg.CRL.OutputDir != "" {
			*outPath = filepath.Join(cfg.CRL.OutputDir, *outPath)
		}
		if *delta {
			*outPath = ca.SanitizeCAName(*caName) + ".delta.crl"
			if cfg.CRL.OutputDir != "" {
				*outPath = filepath.Join(cfg.CRL.OutputDir, *outPath)
			}
		}
	}
	if err := os.WriteFile(*outPath, crlDER, 0644); err != nil {
		return fmt.Errorf("write CRL: %w", err)
	}
	pf("cli.crl_written", *outPath, len(crlDER))
	return nil
}

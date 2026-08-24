// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdRevoke(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	serial := fs.String("serial", "", bundle.T(curLang, "cli.flag_serial"))
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_cert"))
	reason := fs.String("reason", "unspecified", bundle.T(curLang, "cli.flag_reason"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	principalUid := fs.String("principal-uid", "", "Revoke all AIC certs for this principal (person)")
	subCA := fs.String("sub-ca", "", "Revoke all valid certs under this sub-CA name")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	revokeReason, err := ca.ParseRevokeReason(*reason)
	if err != nil {
		return fmt.Errorf("parse reason: %w", err)
	}

	if *principalUid != "" {
		count, err := ca.RevokeByPrincipalUid(database, *principalUid, revokeReason)
		if err != nil {
			return fmt.Errorf("revoke by principal-uid: %w", err)
		}
		fmt.Printf("Revoked %d cert(s) for principal %s\n", count, *principalUid)
		return nil
	}

	if *subCA != "" {
		count, err := ca.RevokeBySubCA(database, *subCA, revokeReason)
		if err != nil {
			return fmt.Errorf("revoke by sub-ca: %w", err)
		}
		fmt.Printf("Revoked %d cert(s) under sub-CA %s\n", count, *subCA)
		return nil
	}

	if *serial == "" && *certFile == "" {
		return ef("cli.err_serial_or_cert")
	}

	if *serial == "" {
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			return fmt.Errorf("read cert: %w", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("invalid cert PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse cert: %w", err)
		}
		*serial = fmt.Sprintf("%X", cert.SerialNumber)
	}

	if *caName == "" {
		*caName = cfg.Defaults.CA
	}

	if err := ca.Revoke(database, *caName, *serial, revokeReason); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	notifyEvent(cfg, database, "cert_revoked", *caName, *serial, "", *reason)

	fmt.Println(bundle.T(curLang, "cli.revoked_msg", *caName, *serial, *reason))
	return nil
}

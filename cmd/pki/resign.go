// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/secrets"
	"github.com/varwof/engine/db"
)

// cmdReSign re-issues a certificate using the original public key,
// optionally under a different CA / profile / validity period.
func cmdReSign(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("re-sign", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	serial := fs.String("serial", "", bundle.T(curLang, "cli.flag_serial"))
	targetCA := fs.String("target-ca", "", bundle.T(curLang, "cli.flag_target_ca"))
	profile := fs.String("profile", "", bundle.T(curLang, "cli.flag_profile"))
	validity := fs.Int("validity", 365, bundle.T(curLang, "cli.flag_validity"))
	out := fs.String("out", "", bundle.T(curLang, "cli.flag_out_path"))
	fs.Parse(args)

	if *caName == "" {
		*caName = cfg.Defaults.CA
	}
	if *caName == "" || *serial == "" {
		return ef("cli.err_ca_serial_required")
	}
	if *targetCA == "" {
		*targetCA = *caName
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	rec, err := database.GetCert(*caName, *serial)
	if err != nil {
		return fmt.Errorf("get cert %s/%s: %w", *caName, *serial, err)
	}
	oldCert, err := x509.ParseCertificate(rec.CertDER)
	if err != nil {
		return fmt.Errorf("parse stored cert: %w", err)
	}

	caCfg, ok := cfg.CAs[*targetCA]
	if !ok {
		return fmt.Errorf("CA %q not found in config", *targetCA)
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, secrets.ResolveCAKeyPassword(*targetCA, caCfg.Password))
	if err != nil {
		return fmt.Errorf("load CA %q: %w", *targetCA, err)
	}

	sc := &ca.SignConfig{
		DB:                    database,
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                *targetCA,
		SubjectPubKey:         oldCert.PublicKey,
		CommonName:            rec.CommonName,
		SANs:                  splitSANsCSV(rec.SAN),
		Profile:               ca.Profile(*profile),
		KeyType:               rec.KeyAlgo,
		Hash:                  cfg.Defaults.Hash,
		Validity:              time.Duration(*validity) * 24 * time.Hour,
		CRLBaseURL:            cfg.CRL.CRLBaseURL,
		OCSPURL:               cfg.Defaults.OCSPURL,
		IssuerURL:             cfg.Defaults.IssuerURL,
		IssuerAltNames:        cfg.Defaults.IssuerAltNames,
		SubjectInfoAccess:     cfg.Defaults.SubjectInfoAccess,
		PolicyOIDs:            cfg.Defaults.PolicyOIDs,
		PolicyMappings:        mustPolicyMappings(cfg.Defaults.PolicyMappings),
		RequireExplicitPolicy: cfg.Defaults.RequireExplicitPolicy,
		InhibitPolicyMapping:  cfg.Defaults.InhibitPolicyMapping,
		InhibitAnyPolicy:      cfg.Defaults.InhibitAnyPolicy,
		PolicyFile:            cfg.Policy,
	}
	if sc.Profile == "" {
		sc.Profile = ca.Profile(rec.Profile)
	}
	if sc.Profile == "" {
		sc.Profile = ca.ProfileTLSServer
	}

	result, err := ca.Sign(sc)
	if err != nil {
		return fmt.Errorf("re-sign: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.CertDER})
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
	}
	fmt.Printf("Re-signed: %s (new serial: %s, CA: %s)\n", result.Cert.Subject.CommonName, result.SerialHex, *targetCA)
	if *out != "" {
		fmt.Printf("Cert: %s\n", *out)
	} else {
		os.Stdout.Write(certPEM)
	}
	return nil
}

// splitSANsCSV splits a comma-separated SAN list from a stored cert record.
func splitSANsCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

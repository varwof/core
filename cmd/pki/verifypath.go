// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// cmdVerifyPath implements `pki verify-path <cert.pem>`: builds and verifies a
// certificate path from the leaf up to a trust anchor using the self-contained
// path engine (internal/ca/pathval.go), with optional RFC 5280 §6.1 policy
// processing (Policy Mappings / Policy Constraints / Inhibit anyPolicy).
func cmdVerifyPath(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("verify-path", flag.ExitOnError)
	dbPath := fs.String("db", "", "Database path for CA metas and trust anchors")
	policy := fs.String("policy", "", "Acceptable certificate policy OID (repeatable, comma-separated). Empty = accept any policy")
	verifyPolicy := fs.Bool("policy-check", false, "Enable RFC 5280 policy processing")
	maxDepth := fs.Int("max-depth", 16, "Maximum chain depth")
	jsonOut := fs.Bool("json", false, "Output result as JSON")
	fs.Parse(args)

	filePath := fs.Arg(0)
	if filePath == "" {
		return ef("cli.err_file_required")
	}

	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no PEM certificate found in %s", filePath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	var src ca.CertSource
	if *dbPath != "" {
		database, err := db.Open(*dbPath)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer database.Close()
		src = &ca.DBSource{DB: database}
	} else {
		database, err := db.Open(cfg.DB)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer database.Close()
		src = &ca.DBSource{DB: database}
	}

	opts := ca.VerifyPathOptions{
		VerifyPolicy: *verifyPolicy,
		MaxDepth:     *maxDepth,
	}
	if *policy != "" {
		for _, p := range splitComma(*policy) {
			if p != "" {
				opts.UserInitialPolicySet = append(opts.UserInitialPolicySet, p)
			}
		}
	}

	res, err := ca.VerifyPath([]*x509.Certificate{cert}, src, opts)
	if err != nil {
		return fmt.Errorf("verify path: %w", err)
	}

	// H6 fix: a rejected path (structural OR policy) must be treated as
	// failure — non-zero exit — so scripts branching on exit status do not
	// silently accept a path that failed policy intersection (previously the
	// command always returned nil even with reject_reason set).
	rejected := res.RejectReason != ""
	if *jsonOut {
		out := map[string]any{
			"valid":           res.Valid,
			"root_is_trusted": res.RootIsTrusted,
			"reject_reason":   res.RejectReason,
		}
		if res.Policy != nil {
			out["policy"] = res.Policy
		}
		var chain []map[string]string
		for _, c := range res.Chain {
			chain = append(chain, map[string]string{
				"subject": c.Subject.String(),
				"issuer":  c.Issuer.String(),
			})
		}
		out["chain"] = chain
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		if rejected {
			return fmt.Errorf("certificate path rejected: %s", res.RejectReason)
		}
		return nil
	}

	fmt.Printf("path: %d certificate(s)\n", len(res.Chain))
	for i, c := range res.Chain {
		marker := ""
		if i == len(res.Chain)-1 {
			if res.RootIsTrusted {
				marker = " [TRUSTED ROOT]"
			} else {
				marker = " [NOT TRUSTED]"
			}
		}
		fmt.Printf("  %d. CN=%s issuer=%s%s\n", i+1, c.Subject.CommonName, c.Issuer.CommonName, marker)
	}
	fmt.Printf("structurally valid: %v\n", res.Valid)
	fmt.Printf("root is trusted: %v\n", res.RootIsTrusted)
	if res.RejectReason != "" {
		fmt.Printf("reject reason: %s\n", res.RejectReason)
	}
	if res.Policy != nil {
		fmt.Printf("accepted user policies: %v\n", res.Policy.AcceptedUserPolicies)
	}
	if rejected {
		return fmt.Errorf("certificate path rejected: %s", res.RejectReason)
	}
	return nil
}

// splitComma splits a comma-separated string, trimming spaces.
func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

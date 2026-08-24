// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/pkcs7"
)

// cmdPolicy handles the `pki policy` subcommand (policy signing).
func cmdPolicy(cfg *internal.Config, args []string) error {
	if len(args) == 0 || args[0] == "help" {
		fmt.Println("Usage: pki policy sign --file authz.json --cert admin.pem --key admin-key.pem [--out authz.json.sig]")
		fmt.Println("  sign    Use admin certificate to PKCS#7 detached-sign the policy file")
		return nil
	}
	switch args[0] {
	case "sign":
		return cmdPolicySign(cfg, args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand: %s", args[0])
	}
}

// cmdPolicySign performs a PKCS#7 detached signature on a policy file (SHA-256).
func cmdPolicySign(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("policy sign", flag.ExitOnError)
	file := fs.String("file", "", "policy file to sign (authz.json / routes.json)")
	certPath := fs.String("cert", "", "admin certificate PEM")
	keyPath := fs.String("key", "", "admin private key PEM")
	outPath := fs.String("out", "", "output signature path (default <file>.sig)")
	fs.Parse(args)

	if *file == "" || *certPath == "" || *keyPath == "" {
		return fmt.Errorf("policy sign: --file, --cert and --key are required")
	}

	data, err := os.ReadFile(filepath.Clean(*file))
	if err != nil {
		return fmt.Errorf("policy sign: read %s: %w", *file, err)
	}

	certPEM, err := os.ReadFile(filepath.Clean(*certPath))
	if err != nil {
		return fmt.Errorf("policy sign: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Clean(*keyPath))
	if err != nil {
		return fmt.Errorf("policy sign: read key: %w", err)
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("policy sign: parse cert: %w", err)
	}
	signer, err := ca.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("policy sign: parse key: %w", err)
	}
	key, ok := signer.(crypto.Signer)
	if !ok {
		return fmt.Errorf("policy sign: key is not a crypto.Signer")
	}

	if !auth.SignerHasAdminOU(cert) {
		return fmt.Errorf("policy sign: signer cert must carry admin OU (got subject=%q)", cert.Subject.String())
	}

	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, cert, key, nil)
	if err != nil {
		return fmt.Errorf("policy sign: build signature: %w", err)
	}

	out := *outPath
	if out == "" {
		out = *file + ".sig"
	}
	if err := os.WriteFile(filepath.Clean(out), sig, 0600); err != nil {
		return fmt.Errorf("policy sign: write %s: %w", out, err)
	}

	// Self-verify: read back signer identity to confirm.
	if _, err := auth.VerifySignedPolicy(sig, data, nil); err != nil {
		return fmt.Errorf("policy sign: self-verify failed (do not deploy this signature): %w", err)
	}

	fmt.Printf("policy signed: %s -> %s (signer=%s, serial=%s)\n",
		*file, out, cert.Subject.String(), cert.SerialNumber.String())
	return nil
}

// parseCertPEM parses the first certificate from PEM bytes.
func parseCertPEM(data []byte) (*x509.Certificate, error) {
	return auth.ParseCertPEM(data)
}

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/signer"
)

// execFn can be replaced in tests to simulate exec behavior.
var execFn = execBinary

// cmdRun verifies the detached signature of a target binary (default <binary>.p7s),
// then execs the binary as a loader (replaces the current process on Unix, runs as a
// child process and passes through the exit code on Windows).
// This is the loader form of "detached + self-verifying" deployment: it enforces
// verification before execution without modifying the binary source code.
func cmdRun(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	caFile := fs.String("ca", "", bundle.T(curLang, "cli.flag_run_ca"))
	sigFile := fs.String("sig", "", bundle.T(curLang, "cli.flag_sig_file"))
	validAt := fs.String("valid-at", "", bundle.T(curLang, "cli.flag_valid_at"))
	fs.Parse(args)

	var currentTime time.Time
	if *validAt != "" {
		var err error
		currentTime, err = time.Parse(time.RFC3339, *validAt)
		if err != nil {
			return fmt.Errorf("parse --valid-at: %w (use RFC 3339 format)", err)
		}
	}

	binary := fs.Arg(0)
	if binary == "" {
		return ef("cli.err_file_required")
	}
	rest := fs.Args()[1:]

	var rootCAs *x509.CertPool
	if *caFile != "" {
		data, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("read --ca: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(data) {
			return fmt.Errorf("no PEM certificates found in --ca %s", *caFile)
		}
	} else {
		rootCAs = loadRootPool(cfg)
	}
	if rootCAs == nil {
		return fmt.Errorf("no trust anchors available; use --ca <root.pem>")
	}

	if *sigFile == "" {
		*sigFile = binary + ".p7s"
	}
	if err := signer.VerifyDetachedAt(binary, *sigFile, rootCAs, currentTime); err != nil {
		return fmt.Errorf("refusing to run %s: signature verification failed: %w", binary, err)
	}
	fmt.Printf("verified: %s <- %s\n", binary, *sigFile)
	fmt.Fprintln(fs.Output(), "Warning: revocation status not checked. Use OCSP or CRL for revocation.")

	return execFn(binary, rest)
}

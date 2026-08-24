package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// verifySCTWithKey runs full RFC 6962 §3.2 SCT signature verification when a
// CT log public key is configured; without one it reports a clear warning that
// the SCT was not cryptographically verified (H11 — no more silent pass).
func verifySCTWithKey(cert *x509.Certificate, sctVersion int, logID string, timestamp uint64, extensions string, sigDER []byte, pubKey string) error {
	if pubKey == "" {
		return fmt.Errorf("ct log public_key not configured; SCT signature NOT verified (set ct_log.public_key for real verification)")
	}
	key, err := ca.ParseCTLogPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse ct log public_key: %w", err)
	}
	var logKey crypto.PublicKey = key
	return ca.VerifySCT(cert, sctVersion, logID, timestamp, extensions, sigDER, logKey)
}

func cmdCTSubmit(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ct-submit", flag.ExitOnError)
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_ct_cert"))
	chainFile := fs.String("chain", "", bundle.T(curLang, "cli.flag_ct_chain"))
	url := fs.String("url", "", bundle.T(curLang, "cli.flag_ct_url"))
	apiKey := fs.String("api-key", "", bundle.T(curLang, "cli.flag_ct_api_key"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ct_ca"))
	serial := fs.String("serial", "", bundle.T(curLang, "cli.flag_ct_serial"))
	fs.Parse(args)

	ctURL := *url
	if ctURL == "" {
		ctURL = cfg.CTLog.URL
	}
	if ctURL == "" {
		return ef("cli.err_ct_url")
	}
	ctKey := *apiKey
	if ctKey == "" {
		ctKey = cfg.CTLog.APIKey
	}

	if *certFile == "" {
		return ef("cli.err_ct_cert")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("parse cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	var chain []*x509.Certificate
	if *chainFile != "" {
		chainPEM, err := os.ReadFile(*chainFile)
		if err != nil {
			return fmt.Errorf("read chain: %w", err)
		}
		rest := chainPEM
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return fmt.Errorf("parse chain cert: %w", err)
			}
			chain = append(chain, c)
		}
	}

	sctVersion, logID, timestamp, extensions, sigDER, err := ca.SubmitCertificate(ctURL, ctKey, cert, chain)
	if err != nil {
		return fmt.Errorf("submit to CT log: %w", err)
	}

	if err := verifySCTWithKey(cert, sctVersion, logID, timestamp, extensions, sigDER, cfg.CTLog.PublicKey); err != nil {
		slog.Warn("ct-verify", "error", err)
	}

	if *caName != "" && *serial != "" {
		database, err := db.Open(cfg.DB)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer database.Close()
		if err := database.StoreSCT(*caName, *serial, sctVersion, logID, timestamp, sigDER); err != nil {
			return fmt.Errorf("store SCT: %w", err)
		}
	}

	fmt.Printf("SCT version: %d\n", sctVersion)
	fmt.Printf("Log ID: %s\n", logID)
	fmt.Printf("Timestamp: %d\n", timestamp)
	fmt.Printf("Signature: %x\n", sigDER)
	return nil
}

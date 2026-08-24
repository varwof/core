package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/pkcs12"
)

func cmdExport(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_cert"))
	keyFile := fs.String("key", "", "private key PEM path")
	chainFile := fs.String("chain", "", bundle.T(curLang, "cli.flag_chain"))
	outFile := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	pfx := fs.Bool("pfx", false, bundle.T(curLang, "cli.flag_pfx"))
	fs.Parse(args)

	if *certFile == "" || *keyFile == "" {
		return ef("cli.err_cert_key_required")
	}
	if *outFile == "" {
		return ef("cli.err_out_required")
	}
	if !*pfx {
		return ef("cli.err_pfx_only")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no certificate PEM block in %s", *certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	key, err := ca.LoadPrivateKey(*keyFile)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("key does not implement crypto.Signer")
	}
	privateKey := signer

	var chain []*x509.Certificate
	if *chainFile != "" {
		chain, err = loadChain(*chainFile)
		if err != nil {
			return fmt.Errorf("load chain: %w", err)
		}
	}

	pfxData, err := pkcs12.Encode(privateKey, cert, chain, *password)
	if err != nil {
		return fmt.Errorf("encode PFX: %w", err)
	}

	if err := os.WriteFile(*outFile, pfxData, 0600); err != nil {
		return fmt.Errorf("write PFX: %w", err)
	}
	fmt.Println(*outFile)
	return nil
}

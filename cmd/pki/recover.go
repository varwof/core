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
	"github.com/varwof/engine/db"
)

func cmdRecover(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	serial := fs.String("serial", "", bundle.T(curLang, "cli.flag_serial"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	out := fs.String("out", "recovered.key", bundle.T(curLang, "cli.flag_out_key_path"))
	adminKey := fs.String("admin-key", "", bundle.T(curLang, "cli.flag_admin_key"))
	fs.Parse(args)

	if *serial == "" {
		return ef("cli.err_serial_required")
	}
	if *caName == "" {
		*caName = cfg.Defaults.CA
	}

	adminKeyPath := *adminKey
	if adminKeyPath == "" {
		adminKeyPath = cfg.KeyEscrow.AdminPublicKey
	}
	if adminKeyPath == "" {
		return ef("cli.err_admin_key")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	encBlob, err := database.GetEscrowedKey(*caName, *serial)
	if err != nil {
		return fmt.Errorf("get escrowed key: %w", err)
	}

	adminKeyPEM, err := os.ReadFile(adminKeyPath)
	if err != nil {
		return fmt.Errorf("read admin key: %w", err)
	}
	block, _ := pem.Decode(adminKeyPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in admin key")
	}
	adminPriv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		adminPriv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse admin private key: %w", err)
		}
	}

	privDER, err := ca.DecryptPrivateKey(encBlob, adminPriv)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("parse recovered key: %w", err)
	}
	privKey, ok := rawKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("recovered key is not a signer")
	}

	keyPEM, err := ca.KeyToPEM(privKey)
	if err != nil {
		return fmt.Errorf("key to pem: %w", err)
	}

	if err := os.WriteFile(*out, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	fmt.Println(bundle.T(curLang, "cli.file_written", *out))
	return nil
}

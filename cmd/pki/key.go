package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

func cmdKeyEncrypt(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("key encrypt", flag.ExitOnError)
	inFile := fs.String("in", "", bundle.T(curLang, "cli.flag_in"))
	outFile := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	fs.Parse(args)

	if *inFile == "" || *outFile == "" || *password == "" {
		return ef("cli.err_inkey_outkey_password")
	}

	inPEM, err := os.ReadFile(*inFile)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	block, _ := pem.Decode(inPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in input")
	}

	priv, err := ca.ParsePrivateKey(inPEM)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	encDER, err := ca.EncryptKeyPKCS8(priv, *password)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	encPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encDER,
	})

	if err := os.WriteFile(*outFile, encPEM, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	fmt.Println(*outFile)
	return nil
}

func cmdKeyDecrypt(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("key decrypt", flag.ExitOnError)
	inFile := fs.String("in", "", bundle.T(curLang, "cli.flag_in"))
	outFile := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	fs.Parse(args)

	if *inFile == "" || *outFile == "" || *password == "" {
		return ef("cli.err_inkey_outkey_password")
	}

	inPEM, err := os.ReadFile(*inFile)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	block, _ := pem.Decode(inPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in input")
	}

	priv, err := ca.DecryptKeyPKCS8(block.Bytes, *password)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	keyPEM, err := ca.KeyToPEM(priv)
	if err != nil {
		return fmt.Errorf("key to pem: %w", err)
	}

	if err := os.WriteFile(*outFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	fmt.Println(*outFile)
	return nil
}

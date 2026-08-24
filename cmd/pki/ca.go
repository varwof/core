// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

func cmdCAOfflineSign(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ca offline-sign", flag.ExitOnError)
	caCertPath := fs.String("ca-cert", "", bundle.T(curLang, "cli.offline_sign_flag_ca_cert"))
	caKeyPath := fs.String("ca-key", "", bundle.T(curLang, "cli.offline_sign_flag_ca_key"))
	caKeyPassword := fs.String("ca-key-password", "", "root CA key decryption password (default: PKI_KEY_PASSWORD env)")
	csrPath := fs.String("csr", "", bundle.T(curLang, "cli.offline_sign_flag_csr"))
	outPath := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	validityDays := fs.Int("validity", 3650, bundle.T(curLang, "cli.flag_validity"))
	pathLen := fs.Int("pathlen", 0, bundle.T(curLang, "cli.flag_pathlen"))
	hash := fs.String("hash", "sha256", bundle.T(curLang, "cli.offline_sign_flag_hash"))
	fs.Parse(args)

	if *caCertPath == "" {
		return fmt.Errorf("--ca-cert is required")
	}
	if *caKeyPath == "" {
		return fmt.Errorf("--ca-key is required")
	}
	if *csrPath == "" {
		return fmt.Errorf("--csr is required")
	}
	if *outPath == "" {
		return fmt.Errorf("--out is required")
	}

	// Load root CA cert
	caCertPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	// Load root CA key (support encrypted)
	var caKey crypto.Signer
	caKeyPEM, err := os.ReadFile(*caKeyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock != nil && keyBlock.Type == "ENCRYPTED PRIVATE KEY" {
		pwd := *caKeyPassword
		if pwd == "" {
			pwd = os.Getenv("PKI_KEY_PASSWORD")
		}
		if pwd == "" {
			pwd, err = readPassword(bundle.T(curLang, "cli.prompt_root_key_password"))
			if err != nil {
				return fmt.Errorf("read password: %w", err)
			}
		}
		caKey, err = ca.DecryptKeyPKCS8(keyBlock.Bytes, pwd)
		if err != nil {
			return fmt.Errorf("decrypt CA key: %w", err)
		}
	} else {
		caKey, err = ca.ParsePrivateKey(caKeyPEM)
		if err != nil {
			return fmt.Errorf("parse CA key: %w", err)
		}
	}

	// Load CSR
	csrPEM, err := os.ReadFile(*csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}
	csr, err := ca.ParseCSR(csrPEM)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	// Sign
	hashVal := strings.ToLower(*hash)
	switch hashVal {
	case "sha256", "sha384", "sha512":
	default:
		hashVal = "sha256"
	}

	certDER, serial, err := ca.SignCACSR(&ca.OfflineSignConfig{
		CACert:   caCert,
		CAKey:    caKey,
		CSR:      csr,
		Validity: time.Duration(*validityDays) * 24 * time.Hour,
		Hash:     hashVal,
		PathLen:  *pathLen,
	})
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	// Write output
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(*outPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	fmt.Println(bundle.T(curLang, "cli.offline_sign_success", *outPath, fmt.Sprintf("%040X", serial)))
	return nil
}

func cmdCAEncryptKey(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ca encrypt-key", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key PEM file (plain or encrypted)")
	outPath := fs.String("out", "", "Output path (default: overwrite --key)")
	password := fs.String("password", "", "Encryption password (default: prompt interactive)")
	verify := fs.Bool("verify", false, "Verify the key can be decrypted after encryption")
	fs.Parse(args)

	if *keyPath == "" {
		return fmt.Errorf("--key is required")
	}

	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	// Load the key (handles both plain and already-encrypted)
	signer, err := ca.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	// Get password
	pwd := *password
	if pwd == "" {
		pwd = os.Getenv("PKI_KEY_PASSWORD")
	}
	if pwd == "" {
		pwd, err = readPassword("Encryption password: ")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		confirm, err := readPassword("Confirm password: ")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if pwd != confirm {
			return fmt.Errorf("passwords do not match")
		}
	}

	encPEM, err := ca.EncryptPrivateKeyPEM(signer, pwd)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}

	output := *outPath
	if output == "" {
		// Backup original
		orig, err := os.ReadFile(*keyPath)
		if err == nil {
			os.WriteFile(*keyPath+".bak", orig, 0600)
			fmt.Fprintf(os.Stderr, "backup saved to %s\n", *keyPath+".bak")
		}
		output = *keyPath
	}

	if err := os.WriteFile(output, encPEM, 0600); err != nil {
		return fmt.Errorf("write encrypted key: %w", err)
	}
	fmt.Printf("encrypted key written to %s\n", output)

	if *verify {
		_, err := ca.ParsePrivateKey(encPEM, pwd)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		fmt.Println("verification OK: key decrypts successfully")
	}

	return nil
}

func pwdAsPKCS8(key interface{}) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return der
}

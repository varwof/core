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
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdRenew(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	serial := fs.String("serial", "", bundle.T(curLang, "cli.flag_serial"))
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_cert"))
	keepKey := fs.Bool("keep-key", false, bundle.T(curLang, "cli.flag_keep_key"))
	keyFile := fs.String("key", "", bundle.T(curLang, "cli.flag_key_file"))
	keyTypeName := fs.String("key-type", "", bundle.T(curLang, "cli.flag_key_type_renew"))
	validityDays := fs.Int("validity", 365, bundle.T(curLang, "cli.flag_validity"))
	outDir := fs.String("out-dir", "", bundle.T(curLang, "cli.flag_out_dir"))
	outName := fs.String("out-name", "", bundle.T(curLang, "cli.flag_out_name"))
	fs.Parse(args)

	if *serial == "" && *certFile == "" {
		return ef("cli.err_serial_or_cert")
	}
	if *caName == "" {
		*caName = cfg.Defaults.CA
	}
	if *keyTypeName == "" {
		*keyTypeName = cfg.Defaults.KeyType
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	caInfo, ok := cfg.CAs[*caName]
	if !ok {
		return fmt.Errorf("CA %q not found in config — add it to the 'cas' section of your config file, or use 'pki ca init' with --password to store the key in DB", *caName)
	}

	issuerCert, issuerKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
	if err != nil {
		return fmt.Errorf("load CA %q: %w", *caName, err)
	}

	var oldCert *x509.Certificate
	storedProfile := ""
	if *certFile != "" {
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			return fmt.Errorf("read cert: %w", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("invalid cert PEM")
		}
		oldCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse cert: %w", err)
		}
	} else {
		rec, err := database.GetCert(*caName, *serial)
		if err != nil {
			return fmt.Errorf("get cert %s/%s: %w", *caName, *serial, err)
		}
		storedProfile = rec.Profile
		oldCert, err = x509.ParseCertificate(rec.CertDER)
		if err != nil {
			return fmt.Errorf("parse stored cert: %w", err)
		}
	}

	if oldCert.IsCA {
		return fmt.Errorf("refusing to renew a CA certificate; use 'pki ca init' to create a new one")
	}
	*serial = fmt.Sprintf("%X", oldCert.SerialNumber)

	var privKey crypto.Signer
	if *keepKey {
		if *keyFile == "" {
			return fmt.Errorf("--key is required with --keep-key")
		}
		privKey, err = ca.LoadPrivateKey(*keyFile)
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}
	} else {
		privKey, err = ca.GenerateKey(*keyTypeName)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
	}

	// Preserve VPN-specific profiles on renewal (EKU alone is ambiguous with
	// tls-server/tls-client); fall back to EKU inference for everything else.
	profile := detectProfile(oldCert)
	if strings.HasPrefix(storedProfile, "vpn-") {
		profile = ca.Profile(storedProfile)
	}

	signCfg := &ca.SignConfig{
		DB:                    database,
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                *caName,
		Profile:               profile,
		CommonName:            oldCert.Subject.CommonName,
		SubjectPubKey:         privKey.Public(),
		Hash:                  cfg.Defaults.Hash,
		Validity:              time.Duration(*validityDays) * 24 * time.Hour,
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

	signCfg.SANs = extractSANs(oldCert)

	result, err := ca.Sign(signCfg)
	if err != nil {
		return fmt.Errorf("sign renewed cert: %w", err)
	}

	certPEM := ca.CertToPEM(result.CertDER)
	keyPEM, err := ca.KeyToPEM(privKey)
	if err != nil {
		return fmt.Errorf("key to pem: %w", err)
	}

	if *outDir == "" {
		*outDir = "."
	}
	stem := *outName
	if stem == "" {
		stem = result.SerialHex
	}

	certPath := filepath.Join(*outDir, stem+".pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	fmt.Println(certPath)

	if !*keepKey {
		keyPath := filepath.Join(*outDir, stem+".key")
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		fmt.Println(keyPath)
	}

	return nil
}

func detectProfile(cert *x509.Certificate) ca.Profile {
	hasServer := false
	hasClient := false
	hasCode := false
	hasEmail := false
	hasTSA := false
	hasOCSP := false
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		case x509.ExtKeyUsageCodeSigning:
			hasCode = true
		case x509.ExtKeyUsageEmailProtection:
			hasEmail = true
		case x509.ExtKeyUsageTimeStamping:
			hasTSA = true
		case x509.ExtKeyUsageOCSPSigning:
			hasOCSP = true
		}
	}
	switch {
	case hasServer:
		return ca.ProfileTLSServer
	case hasClient:
		return ca.ProfileTLSClient
	case hasCode:
		return ca.ProfileCodeSigning
	case hasEmail:
		return ca.ProfileEmail
	case hasTSA:
		return ca.ProfileTimestamp
	case hasOCSP:
		return ca.ProfileOCSPSigner
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		return ca.ProfileDocument
	}
	return ca.ProfileTLSServer
}

func extractSANs(cert *x509.Certificate) []string {
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, u := range cert.URIs {
		sans = append(sans, "URI:"+u.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "email:"+email)
	}
	return sans
}

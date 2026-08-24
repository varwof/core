// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
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

func cmdIssue(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	cn := fs.String("cn", "", bundle.T(curLang, "cli.flag_cn"))
	san := fs.String("san", "", bundle.T(curLang, "cli.flag_san"))
	subject := fs.String("subject", "", bundle.T(curLang, "cli.flag_subject"))
	profile := fs.String("profile", "", bundle.T(curLang, "cli.flag_profile"))
	keyType := fs.String("key-type", "", bundle.T(curLang, "cli.flag_key_type"))
	validity := fs.Int("validity", 365, bundle.T(curLang, "cli.flag_validity"))
	out := fs.String("out", "", bundle.T(curLang, "cli.flag_out"))
	outKey := fs.String("out-key", "", bundle.T(curLang, "cli.flag_out_key"))
	as := fs.String("as", "", bundle.T(curLang, "cli.flag_as"))
	caScope := fs.String("ca-scope", "", bundle.T(curLang, "cli.flag_ca_scope"))
	scope := fs.String("scope", "", "admin scope: which CAs this admin can manage (comma-separated, max 3)")
	keyPassword := fs.String("key-password", "", "encrypt private key with this password (PKCS#8 PBES2, OpenSSL compatible)")
	csrFile := fs.String("csr", "", bundle.T(curLang, "cli.flag_csr_file"))
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	caNameStr := *caName
	if caNameStr == "" {
		caNameStr = cfg.Defaults.CA
	}

	caCfg, ok := cfg.CAs[caNameStr]
	if !ok {
		return fmt.Errorf("CA %q not found in config", caNameStr)
	}

	issuerCert, issuerKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, secrets.ResolveCAKeyPassword(caNameStr, caCfg.Password))
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	keyTypeName := *keyType
	if keyTypeName == "" {
		keyTypeName = cfg.Defaults.KeyType
	}

	profileName := *profile
	if profileName == "" {
		profileName = cfg.Defaults.Profile
	}

	var privKey crypto.Signer
	if *csrFile == "" {
		privKey, err = ca.GenerateKey(keyTypeName)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
	}

	var certSubject pkix.Name
	if *subject != "" {
		parsed, err := parseSubject(*subject)
		if err != nil {
			return fmt.Errorf("parse subject: %w", err)
		}
		certSubject = *parsed
		// --cn overrides CN from --subject when both are provided
		if *cn != "" {
			certSubject.CommonName = *cn
		}
	} else {
		certSubject.CommonName = *cn
		certSubject.Organization = []string{cfg.Defaults.DefaultOrg}
		certSubject.Country = []string{cfg.Defaults.DefaultCountry}
		if *as != "" {
			certSubject.OrganizationalUnit = []string{*as}
		}
	}

	var csr *x509.CertificateRequest
	if *csrFile != "" {
		csr, err = parseCSRFile(*csrFile)
		if err != nil {
			return err
		}
		// CN is required; fall back to the CSR subject's CN when --cn is absent.
		if certSubject.CommonName == "" {
			certSubject.CommonName = csr.Subject.CommonName
		}
	}

	if certSubject.CommonName == "" {
		return fmt.Errorf("--cn is required (or include CN in --subject/CSR)")
	}

	// Dual-write the admin scope: SAN URI (CAScope slice) + OID extension
	// (Scope string). If only one flag is given, mirror it to the other so the
	// issued cert always carries both representations.
	scopeVal := *scope
	if scopeVal == "" {
		scopeVal = *caScope
	}
	caScopeVal := *caScope
	if caScopeVal == "" {
		caScopeVal = scopeVal
	}
	var subjectPubKey any
	if csr != nil {
		subjectPubKey = csr.PublicKey
	} else {
		subjectPubKey = privKey.Public()
	}
	signCfg := &ca.SignConfig{
		DB:                    database,
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                caNameStr,
		CommonName:            certSubject.CommonName,
		Subject:               &certSubject,
		SubjectPubKey:         subjectPubKey,
		Profile:               ca.Profile(profileName),
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
		DefaultOrg:            cfg.Defaults.DefaultOrg,
		DefaultCountry:        cfg.Defaults.DefaultCountry,
		PolicyFile:            cfg.Policy,
		CAScope:               splitCSV(caScopeVal),
		Scope:                 scopeVal,
	}

	if *san != "" {
		for _, s := range strings.Split(*san, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				signCfg.SANs = append(signCfg.SANs, s)
			}
		}
	}

	// CSR mode: inherit SANs from the CSR (DNS + IP), matching the
	// POST /api/v1/csr/sign behavior. Explicit --san values take precedence
	// only in the sense that both are merged into the final cert.
	if csr != nil {
		for _, dns := range csr.DNSNames {
			signCfg.SANs = append(signCfg.SANs, "DNS:"+dns)
		}
		for _, ip := range csr.IPAddresses {
			signCfg.SANs = append(signCfg.SANs, "IP:"+ip.String())
		}
	}

	result, err := ca.Sign(signCfg)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	outPath := *out
	if outPath == "" {
		outPath = result.SerialHex + ".pem"
		fmt.Println(outPath)
	}
	certPEM := ca.CertToPEM(result.CertDER)
	if err := os.WriteFile(outPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write private key (from GenerateKey, not SignResult). CSR mode has no
	// private key on this side — the requester holds it.
	if csr == nil {
		keyPath := *outKey
		if keyPath == "" {
			keyPath = strings.TrimSuffix(outPath, ".pem") + ".key"
		}
		var keyPEM []byte
		if *keyPassword != "" {
			keyPEM, err = ca.EncryptPrivateKeyPEM(privKey, *keyPassword)
			if err != nil {
				return fmt.Errorf("encrypt key: %w", err)
			}
		} else {
			keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				return fmt.Errorf("marshal key: %w", err)
			}
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		if *out != "" && *outKey == "" {
			fmt.Println(keyPath)
		}
	}

	return nil
}

func parseCSRFile(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read csr: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in CSR file")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM block type %q (want CERTIFICATE REQUEST)", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature check: %w", err)
	}
	return csr, nil
}

func parseSubject(s string) (*pkix.Name, error) {
	n := &pkix.Name{}
	for _, p := range strings.Split(s, "/") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "CN":
			n.CommonName = kv[1]
		case "O":
			n.Organization = []string{kv[1]}
		case "OU":
			n.OrganizationalUnit = []string{kv[1]}
		case "C":
			n.Country = []string{kv[1]}
		case "L":
			n.Locality = []string{kv[1]}
		case "ST":
			n.Province = []string{kv[1]}
		}
	}
	// CN is not required here; caller may provide it via --cn flag
	return n, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

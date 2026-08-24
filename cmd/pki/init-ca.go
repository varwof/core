package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"golang.org/x/term"
)

func cmdInitCA(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("init-ca", flag.ExitOnError)
	name := fs.String("name", "", bundle.T(curLang, "cli.flag_name"))
	profileName := fs.String("profile", "root-ca", bundle.T(curLang, "cli.flag_profile"))
	parentName := fs.String("parent", "", bundle.T(curLang, "cli.flag_parent"))
	parentKey := fs.String("parent-key", "", bundle.T(curLang, "cli.flag_parent_key"))
	reuseKey := fs.String("reuse-key", "", "reuse existing key to re-sign under new parent")
	keyTypeName := fs.String("key-type", "", bundle.T(curLang, "cli.flag_key_type"))
	validityDays := fs.Int("validity", 3650, bundle.T(curLang, "cli.flag_validity"))
	outCert := fs.String("out-cert", "", bundle.T(curLang, "cli.flag_out_cert"))
	outKey := fs.String("out-key", "", bundle.T(curLang, "cli.flag_out_key"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	promptPwd := fs.Bool("prompt", false, bundle.T(curLang, "cli.flag_prompt"))
	noStoreKey := fs.Bool("no-store-key", false, bundle.T(curLang, "cli.flag_no_store_key"))
	permittedDNS := fs.String("permitted-dns", "", bundle.T(curLang, "cli.flag_permitted_dns"))
	excludedDNS := fs.String("excluded-dns", "", bundle.T(curLang, "cli.flag_excluded_dns"))
	permittedEmails := fs.String("permitted-emails", "", bundle.T(curLang, "cli.flag_permitted_emails"))
	excludedEmails := fs.String("excluded-emails", "", bundle.T(curLang, "cli.flag_excluded_emails"))
	permittedURIs := fs.String("permitted-uris", "", bundle.T(curLang, "cli.flag_permitted_uris"))
	excludedURIs := fs.String("excluded-uris", "", bundle.T(curLang, "cli.flag_excluded_uris"))
	permittedIPs := fs.String("permitted-ips", "", bundle.T(curLang, "cli.flag_permitted_ips"))
	excludedIPs := fs.String("excluded-ips", "", bundle.T(curLang, "cli.flag_excluded_ips"))
	fs.Parse(args)

	if *name == "" {
		return ef("cli.err_name_required")
	}

	if *keyTypeName == "" {
		*keyTypeName = cfg.Defaults.KeyType
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	createCfg := &ca.CreateConfig{
		DB:             database,
		Name:           *name,
		Profile:        ca.Profile(*profileName),
		KeyType:        *keyTypeName,
		Validity:       time.Duration(*validityDays) * 24 * time.Hour,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
		OCSPURL:        cfg.Defaults.OCSPURL,
		IssuerURL:      cfg.Defaults.IssuerURL,
		DefaultCountry: cfg.Defaults.DefaultCountry,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
	}

	if *permittedDNS != "" {
		for _, d := range strings.Split(*permittedDNS, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.PermittedDomains = append(createCfg.PermittedDomains, d)
			}
		}
	}
	if *excludedDNS != "" {
		for _, d := range strings.Split(*excludedDNS, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.ExcludedDomains = append(createCfg.ExcludedDomains, d)
			}
		}
	}
	if *permittedEmails != "" {
		for _, d := range strings.Split(*permittedEmails, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.PermittedEmails = append(createCfg.PermittedEmails, d)
			}
		}
	}
	if *excludedEmails != "" {
		for _, d := range strings.Split(*excludedEmails, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.ExcludedEmails = append(createCfg.ExcludedEmails, d)
			}
		}
	}
	if *permittedURIs != "" {
		for _, d := range strings.Split(*permittedURIs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.PermittedURIs = append(createCfg.PermittedURIs, d)
			}
		}
	}
	if *excludedURIs != "" {
		for _, d := range strings.Split(*excludedURIs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.ExcludedURIs = append(createCfg.ExcludedURIs, d)
			}
		}
	}
	if *permittedIPs != "" {
		for _, d := range strings.Split(*permittedIPs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.PermittedIPRanges = append(createCfg.PermittedIPRanges, d)
			}
		}
	}
	if *excludedIPs != "" {
		for _, d := range strings.Split(*excludedIPs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				createCfg.ExcludedIPRanges = append(createCfg.ExcludedIPRanges, d)
			}
		}
	}

	if *parentName != "" {
		parentMeta, err := database.GetCAMeta(*parentName)
		if err != nil {
			return fmt.Errorf("parent CA %q not found in ca_meta: %w", *parentName, err)
		}
		createCfg.Parent, err = x509.ParseCertificate(parentMeta.CertDER)
		if err != nil {
			return fmt.Errorf("parse parent cert: %w", err)
		}

		keyPath := *parentKey
		if keyPath == "" {
			if caCfg, ok := cfg.CAs[*parentName]; ok {
				keyPath = caCfg.Key
			}
		}
		if keyPath == "" {
			return ef("cli.err_parent_key", *parentName)
		}

		createCfg.ParentKey, err = ca.LoadPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("load parent key: %w", err)
		}
	}

	isRoot := ca.IsRootCAProfile(ca.Profile(*profileName))

	if isRoot && *password == "" && !*promptPwd {
		// Root CA key can be stored without encryption
		_ = isRoot
	}

	if *promptPwd {
		pwd, err := readPassword(bundle.T(curLang, "cli.prompt_password"))
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		confirm, err := readPassword(bundle.T(curLang, "cli.prompt_password_confirm"))
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if pwd != confirm {
			return errors.New(bundle.T(curLang, "cli.prompt_password_mismatch"))
		}
		password = &pwd
	}

	if *reuseKey != "" {
		reused, err := ca.LoadPrivateKey(*reuseKey)
		if err != nil {
			return fmt.Errorf("load reuse key: %w", err)
		}
		createCfg.ReuseKey = reused
	}
	if *reuseKey != "" {
		reused, err := ca.LoadPrivateKey(*reuseKey)
		if err != nil {
			return fmt.Errorf("load reuse key: %w", err)
		}
		createCfg.ReuseKey = reused
	}
	if *reuseKey != "" {
		reused, err := ca.LoadPrivateKey(*reuseKey)
		if err != nil {
			return fmt.Errorf("load reuse key: %w", err)
		}
		createCfg.ReuseKey = reused
	}
	result, err := ca.CreateCA(createCfg)
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}

	fmt.Println(bundle.T(curLang, "cli.created_ca", *name, result.SerialHex, result.Cert.Subject))

	if *outCert != "" {
		if err := os.WriteFile(*outCert, ca.CertToPEM(result.CertDER), 0644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		fmt.Println(bundle.T(curLang, "cli.cert_written", *outCert))
	}

	keyPEM, err := ca.KeyToPEM(result.Signer)
	if err != nil {
		return fmt.Errorf("key to pem: %w", err)
	}

	if *password != "" {
		encDER, err := ca.EncryptKeyPKCS8(result.Signer, *password)
		if err != nil {
			return fmt.Errorf("encrypt key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})
	}

	if *outKey != "" {
		if err := os.WriteFile(*outKey, keyPEM, 0700); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		fmt.Println(bundle.T(curLang, "cli.key_written", *outKey))

		if isRoot {
			fmt.Fprint(os.Stderr, bundle.T(curLang, "cli.root_key_offline_header", *outKey))
			fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.root_key_offline_detail"))
			fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.root_key_offline_steps", *outKey, *outKey))
		}
	}

	if *noStoreKey {
		fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.no_store_key_warning"))
		fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.no_store_key_show"))
		os.Stderr.Write(keyPEM)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.no_store_key_loss"))
	}

	if *outKey == "" && !*noStoreKey {
		fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.no_key_warning"))
	}

	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(b)), nil
}

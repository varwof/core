package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/secrets"
	"github.com/varwof/engine/db"
)

func cmdSubCACreate(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("sub-ca create", flag.ExitOnError)
	name := fs.String("name", "", bundle.T(curLang, "cli.flag_name"))
	parentCA := fs.String("parent", "", bundle.T(curLang, "cli.flag_parent"))
	keyType := fs.String("key-type", "ecdsa-p256", bundle.T(curLang, "cli.flag_key_type"))
	validity := fs.Int("validity", 3650, bundle.T(curLang, "cli.flag_validity"))
	maxPathLen := fs.Int("max-path-len", 0, "path length constraint (0 = end-entity only)")
	protocol := fs.String("protocol", "", "protocol identifier (scep/cmp/acme/est)")
	out := fs.String("out", "", "output directory for cert+key files")
	fs.Parse(args)

	if *name == "" || *parentCA == "" {
		return ef("cli.err_subca_name_parent")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	parentMeta, err := database.GetCAMeta(*parentCA)
	if err != nil {
		return fmt.Errorf("parent CA %q not found in database: %w", *parentCA, err)
	}
	parentCert, err := x509.ParseCertificate(parentMeta.CertDER)
	if err != nil {
		return fmt.Errorf("parse parent cert: %w", err)
	}

	caCfg, ok := cfg.CAs[*parentCA]
	if !ok {
		return fmt.Errorf("parent CA %q not found in config", *parentCA)
	}
	_, parentKey, err := ca.LoadSigner(caCfg.Cert, caCfg.Key, secrets.ResolveCAKeyPassword(*parentCA, caCfg.Password))
	if err != nil {
		return fmt.Errorf("load parent CA %q: %w", *parentCA, err)
	}

	subCfg := &ca.SubCAConfig{
		Name:       *name,
		ParentCA:   *parentCA,
		KeyType:    *keyType,
		Validity:   time.Duration(*validity) * 24 * time.Hour,
		MaxPathLen: *maxPathLen,
		Protocol:   *protocol,
		CRLBaseURL: cfg.CRL.CRLBaseURL,
	}

	result, err := ca.IssueSubCA(database, subCfg, parentCert, parentKey)
	if err != nil {
		return fmt.Errorf("create sub-CA: %w", err)
	}

	if out, ok := *out, *out != ""; ok {
		certPath := strings.TrimSuffix(out, "/") + "/" + *name + ".pem"
		if err := os.MkdirAll(out, 0755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
		if err := os.WriteFile(certPath, result.CertPEM, 0644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		keyPath := strings.TrimSuffix(out, "/") + "/" + *name + ".key"
		if err := os.WriteFile(keyPath, result.KeyPEM, 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		fmt.Printf("Sub-CA %s created (serial %s)\n  Cert: %s\n  Key:  %s\n", result.Name, result.SerialHex, certPath, keyPath)
		return nil
	}

	fmt.Printf("Sub-CA %s created (serial %s, fingerprint %s)\n", result.Name, result.SerialHex, result.Fingerprint)
	os.Stdout.Write(result.CertPEM)
	return nil
}

func cmdSubCAList(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("sub-ca list", flag.ExitOnError)
	protocol := fs.String("protocol", "", "filter by protocol")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	subCAs, err := ca.ListSubCAs(database, *protocol)
	if err != nil {
		return fmt.Errorf("list sub-CAs: %w", err)
	}
	if len(subCAs) == 0 {
		fmt.Println("No sub-CAs found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tPARENT\tSTATUS\tPROTOCOL\tNOT AFTER")
	for _, s := range subCAs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.ParentCA, s.Status, s.Protocol, s.NotAfter.Format("2006-01-02"))
	}
	w.Flush()
	return nil
}

func cmdSubCAInfo(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("sub-ca info", flag.ExitOnError)
	name := fs.String("name", "", bundle.T(curLang, "cli.flag_name"))
	fs.Parse(args)
	if *name == "" {
		return ef("cli.err_name_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	meta, err := ca.GetSubCA(database, *name)
	if err != nil {
		return fmt.Errorf("get sub-CA %q: %w", *name, err)
	}

	fmt.Printf("Name:          %s\n", meta.Name)
	fmt.Printf("Parent CA:     %s\n", meta.ParentCA)
	fmt.Printf("Status:        %s\n", meta.Status)
	fmt.Printf("Protocol:      %s\n", meta.Protocol)
	fmt.Printf("Key Algorithm: %s\n", meta.KeyAlgorithm)
	fmt.Printf("Subject:       %s\n", meta.Subject)
	fmt.Printf("Not Before:    %s\n", meta.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:     %s\n", meta.NotAfter.Format(time.RFC3339))
	fmt.Printf("Fingerprint:   %s\n", meta.Fingerprint)
	if meta.RevokedAt != nil {
		fmt.Printf("Revoked At:    %s\n", meta.RevokedAt.Format(time.RFC3339))
	}
	return nil
}

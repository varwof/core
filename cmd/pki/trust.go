package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdTrust(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("trust requires a subcommand: import, list, info, trust, untrust, remove, stats")
	}

	switch args[0] {
	case "import":
		return cmdTrustImport(cfg, args[1:])
	case "list":
		return cmdTrustList(cfg, args[1:])
	case "info", "show":
		return cmdTrustInfo(cfg, args[1:])
	case "trust":
		return cmdTrustSet(cfg, args[1:], true)
	case "untrust":
		return cmdTrustSet(cfg, args[1:], false)
	case "remove", "rm":
		return cmdTrustRemove(cfg, args[1:])
	case "stats":
		return cmdTrustStats(cfg, args[1:])
	default:
		return fmt.Errorf("unknown trust subcommand: %s", args[0])
	}
}

func cmdTrustImport(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("trust import", flag.ExitOnError)
	url := fs.String("url", "", "URL to download CA cert bundle (default: curl.se/ca/cacert.pem)")
	filePath := fs.String("file", "", "Local PEM file path")
	rebase := fs.Bool("rebase", false, "Clear existing trust anchors before import")
	trusted := fs.Bool("trusted", true, "Mark imported anchors as trusted")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	var pemData []byte
	source := ""

	if *filePath != "" {
		pemData, err = os.ReadFile(*filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		source = "file"
	} else {
		u := *url
		if u == "" {
			u = ca.DefaultCACertURL
		}
		source = "curl"
		fmt.Printf("Downloading from %s ...\n", u)
		pemData, err = ca.FetchCACertBundle(u)
		if err != nil {
			return fmt.Errorf("download: %w", err)
		}
	}

	if *rebase {
		if err := database.DeleteTrustAnchorsBySource(source); err != nil {
			return fmt.Errorf("rebase: %w", err)
		}
		fmt.Printf("Cleared existing %s trust anchors\n", source)
	}

	result, err := ca.ImportTrustBundle(database, pemData, source)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	fmt.Printf("Trust anchors imported: %d new, %d skipped (of %d total certificates)\n",
		result.Imported, result.Skipped, result.Total)

	if !*trusted {
		anchors, err := database.ListTrustAnchors(&db.TrustAnchorFilter{Trusted: &[]bool{true}[0]})
		if err == nil {
			for _, a := range anchors {
				database.UpdateTrustAnchorTrusted(a.HashID, false)
			}
		}
	}

	return nil
}

func cmdTrustList(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("trust list", flag.ExitOnError)
	trustedStr := fs.String("trusted", "", "Filter: true/false")
	source := fs.String("source", "", "Filter by source")
	orgFilter := fs.String("org", "", "Filter by organization (subject O)")
	countryFilter := fs.String("country", "", "Filter by country (subject C)")
	algoFilter := fs.String("algo", "", "Filter by key algorithm (RSA/ECDSA/Ed25519)")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	filter := &db.TrustAnchorFilter{}
	if *trustedStr != "" {
		v := *trustedStr == "true" || *trustedStr == "1"
		filter.Trusted = &v
	}
	if *source != "" {
		filter.Source = *source
	}
	if *orgFilter != "" {
		filter.SubjectO = *orgFilter
	}
	if *countryFilter != "" {
		filter.SubjectC = *countryFilter
	}
	if *algoFilter != "" {
		filter.KeyAlgo = *algoFilter
	}

	anchors, err := database.ListTrustAnchors(filter)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "hash_id\tname\torg\tcountry\talgo\tsource\ttrusted\tnot_after")
	fmt.Fprintln(w, "-------\t----\t---\t-------\t----\t------\t-------\t---------")
	for _, a := range anchors {
		trusted := "N"
		if a.Trusted {
			trusted = "Y"
		}
		o := a.SubjectO
		if o == "" {
			o = "-"
		}
		c := a.SubjectC
		if c == "" {
			c = "-"
		}
		algo := a.KeyAlgo
		if a.KeySize > 0 {
			algo = fmt.Sprintf("%s-%d", algo, a.KeySize)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.HashID, a.Name, o, c, algo,
			a.Source, trusted, a.NotAfter.Format("2006-01-02"))
	}
	w.Flush()
	fmt.Printf("\nTotal: %d trust anchors\n", len(anchors))

	return nil
}

func cmdTrustInfo(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("trust info", flag.ExitOnError)
	hash := fs.String("hash", "", "Certificate hash ID")
	fs.Parse(args)

	if *hash == "" {
		if fs.NArg() > 0 {
			*hash = fs.Arg(0)
		}
	}
	if *hash == "" {
		return fmt.Errorf("--hash is required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	anchor, err := database.GetTrustAnchor(*hash)
	if err != nil {
		return fmt.Errorf("get trust anchor: %w", err)
	}

	fmt.Printf("Name:            %s\n", anchor.Name)
	fmt.Printf("Hash ID:         %s\n", anchor.HashID)
	fmt.Printf("Subject:         %s\n", anchor.Subject)
	fmt.Printf("Organization:    %s\n", anchor.SubjectO)
	fmt.Printf("Country:         %s\n", anchor.SubjectC)
	fmt.Printf("Issuer:          %s\n", anchor.Issuer)
	fmt.Printf("Not Before:      %s\n", anchor.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:       %s\n", anchor.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Key Algorithm:   %s", anchor.KeyAlgo)
	if anchor.KeySize > 0 {
		fmt.Printf("-%d", anchor.KeySize)
	}
	fmt.Println()
	fmt.Printf("SHA-1 Fingerprint: %s\n", anchor.SHA1Fingerprint)
	fmt.Printf("Path Length:     %d\n", anchor.PathLen)
	fmt.Printf("Trusted:         %v\n", anchor.Trusted)
	fmt.Printf("Source:          %s\n", anchor.Source)
	fmt.Printf("Imported At:     %s\n", anchor.ImportedAt.Format("2006-01-02 15:04:05"))

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.CertDER})
	fmt.Printf("\n%s", cert)

	return nil
}

func cmdTrustSet(cfg *internal.Config, args []string, trusted bool) error {
	fs := flag.NewFlagSet("trust set", flag.ExitOnError)
	hash := fs.String("hash", "", "Certificate hash ID")
	fs.Parse(args)

	if *hash == "" && fs.NArg() > 0 {
		*hash = fs.Arg(0)
	}
	if *hash == "" {
		return fmt.Errorf("--hash is required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if err := database.UpdateTrustAnchorTrusted(*hash, trusted); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	status := "trusted"
	if !trusted {
		status = "untrusted"
	}
	fmt.Printf("Trust anchor %s marked as %s\n", *hash, status)
	return nil
}

func cmdTrustRemove(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("trust remove", flag.ExitOnError)
	hash := fs.String("hash", "", "Certificate hash ID")
	fs.Parse(args)

	if *hash == "" && fs.NArg() > 0 {
		*hash = fs.Arg(0)
	}
	if *hash == "" {
		return fmt.Errorf("--hash is required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if err := database.DeleteTrustAnchor(*hash); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	fmt.Printf("Trust anchor %s removed\n", *hash)
	return nil
}

func cmdTrustStats(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("trust stats", flag.ExitOnError)
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	total, trusted, untrusted, err := database.TrustAnchorStats()
	if err != nil {
		return fmt.Errorf("stats: %w", err)
	}

	sources := make(map[string]int)
	filter := &db.TrustAnchorFilter{}
	all, err := database.ListTrustAnchors(filter)
	if err == nil {
		for _, a := range all {
			sources[a.Source]++
		}
	}

	fmt.Printf("Trust anchor statistics:\n")
	fmt.Printf("  Total:     %d\n", total)
	fmt.Printf("  Trusted:   %d\n", trusted)
	fmt.Printf("  Untrusted: %d\n", untrusted)
	if len(sources) > 0 {
		fmt.Printf("  Sources:\n")
		for s, c := range sources {
			fmt.Printf("    %s: %d\n", s, c)
		}
	}
	return nil
}

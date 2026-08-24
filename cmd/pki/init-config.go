package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/varwof/core/internal"
)

func cmdInitConfig(cfg *internal.Config, args []string) error {
	def := internal.DefaultConfig()

	cas := make(map[string]internal.CAConfig)
	for name, ca := range def.CAs {
		cas[name] = ca
	}
	cas["codesign"] = internal.CAConfig{
		Cert:  "/etc/varwof/core/keys/codesign/certs/ca.pem",
		Key:   "/etc/varwof/core/keys/codesign/private/ca.key",
		Chain: "",
	}

	sample := def
	sample.CAs = cas
	sample.Serve.AuthUsername = "admin"
	sample.Serve.AuthPassword = "changeme"
	if sample.Serve.TLSAddr == "" {
		sample.Serve.TLSAddr = ":4433"
	}
	if sample.Serve.TLSCert == "" {
		sample.Serve.TLSCert = "/etc/varwof/core/keys/server.pem"
	}
	if sample.Serve.TLSKey == "" {
		sample.Serve.TLSKey = "/etc/varwof/core/keys/server.key"
	}
	if sample.CRL.OutputDir == "" {
		sample.CRL.OutputDir = "/etc/varwof/core/crl"
	}
	if sample.CRL.CRLBaseURL == "" {
		sample.CRL.CRLBaseURL = "http://pki.example.com/crl"
	}
	if sample.CRL.RenewInterval == "" && sample.CRL.AutoRenew == "" {
		sample.CRL.RenewInterval = "24h"
	}
	if sample.OCSP.NextUpdate == "" {
		sample.OCSP.NextUpdate = "4h"
	}

	fmt.Fprint(os.Stderr, bundle.T(curLang, "cli.init_config_header", sampleConfigPath(), sampleConfigPath(), sampleConfigPath()))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sample); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	fmt.Fprint(os.Stderr, bundle.T(curLang, "cli.init_config_footer", sampleConfigPath()))
	return nil
}

func sampleConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		if pg := os.Getenv("PROGRAMDATA"); pg != "" {
			return filepath.Join(pg, "varwof", "core", "pki.json")
		}
		return filepath.Join(os.Getenv("APPDATA"), "varwof", "core", "pki.json")
	default:
		return "/etc/varwof/core/pki.json"
	}
}

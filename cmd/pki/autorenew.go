// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdAutoRenew(cfg *internal.Config, args []string) error {
	if len(args) > 0 && (args[0] == "daemon" || args[0] == "--daemon") {
		return autoRenewDaemon(cfg, args[1:])
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		return cmdAutoRenewHelp()
	}
	return autoRenewOnce(cfg, args)
}

func cmdAutoRenewHelp() error {
	fmt.Println("Usage: auto-renew [daemon]")
	fmt.Println("  (no args)  Run auto-renew once")
	fmt.Println("  daemon     Run auto-renew as a daemon on an interval")
	return nil
}

func autoRenewOnce(cfg *internal.Config, args []string) error {
	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	policy := &ca.AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      cfg.AutoRenew.WindowDays,
		DefaultValidity: cfg.AutoRenew.DefaultValidity,
		Profiles:        cfg.AutoRenew.Profiles,
		ExcludeCAs:      cfg.AutoRenew.ExcludeCAs,
		NotifyOnly:      internal.BoolOr(cfg.AutoRenew.NotifyOnly, false),
		MaxRenewals:     cfg.AutoRenew.MaxRenewals,
	}
	if policy.WindowDays <= 0 {
		policy.WindowDays = 30
	}
	if policy.DefaultValidity <= 0 {
		policy.DefaultValidity = 365
	}

	results := ca.AutoRenew(database, policy, func(caName, serial string, validityDays int) (string, error) {
		return renewCert(database, cfg, caName, serial, validityDays)
	}, func(event, caName, serial, cn, msg string) {
		notifyEvent(cfg, database, event, caName, serial, cn, msg)
	})
	if results == nil {
		results = []ca.AutoRenewResult{}
	}

	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))

	var renewed, errors int
	for _, r := range results {
		switch r.Action {
		case "renewed":
			renewed++
		case "error":
			errors++
		}
	}
	slog.Info("auto-renew complete", "checked", len(results), "renewed", renewed, "errors", errors)
	return nil
}

func autoRenewDaemon(cfg *internal.Config, args []string) error {
	interval := 24 * time.Hour
	if cfg.AutoRenew.Interval != "" {
		if d, err := time.ParseDuration(cfg.AutoRenew.Interval); err == nil {
			interval = d
		}
	}
	slog.Info("auto-renew daemon started", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		database, err := db.Open(cfg.DB)
		if err != nil {
			slog.Error("auto-renew: open db", "error", err)
			continue
		}
		_ = autoRenewOnce(cfg, nil)
		database.Close()
	}
	return nil
}

func renewCert(database *db.DB, cfg *internal.Config, caName, serial string, validityDays int) (string, error) {
	rec, err := database.GetCert(caName, serial)
	if err != nil {
		return "", fmt.Errorf("get cert: %w", err)
	}
	oldCert, err := x509.ParseCertificate(rec.CertDER)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}

	caInfo, ok := cfg.CAs[caName]
	if !ok {
		return "", fmt.Errorf("CA %q not configured", caName)
	}
	issuerCert, issuerKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
	if err != nil {
		return "", fmt.Errorf("load CA: %w", err)
	}

	privKey, err := ca.GenerateKey(cfg.Defaults.KeyType)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	profile := detectProfile(oldCert)
	signCfg := &ca.SignConfig{
		DB:                    database,
		CAKey:                 issuerKey,
		CACert:                issuerCert,
		CAName:                caName,
		Profile:               profile,
		CommonName:            oldCert.Subject.CommonName,
		Subject:               &oldCert.Subject,
		SubjectPubKey:         privKey.Public(),
		Hash:                  cfg.Defaults.Hash,
		Validity:              time.Duration(validityDays) * 24 * time.Hour,
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
		return "", fmt.Errorf("sign: %w", err)
	}
	return result.SerialHex, nil
}

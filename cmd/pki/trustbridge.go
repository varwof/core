// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdTrustBridge(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trust-bridge {issue|list|federate}")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	switch args[0] {
	case "issue":
		return trustBridgeIssue(cfg, database, args[1:])
	case "list":
		return trustBridgeList(cfg, database, args[1:])
	case "federate":
		return trustBridgeFederate(cfg, database, args[1:])
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func trustBridgeIssue(cfg *internal.Config, database *db.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: trust-bridge issue <issuer_ca> <subject_ca> [validity_days]")
	}
	issuerCA := args[0]
	subjectCA := args[1]
	validity := 3650
	if len(args) > 2 {
		fmt.Sscanf(args[2], "%d", &validity)
	}

	bridges := []ca.TrustBridgePolicy{{
		IssuerCA:  issuerCA,
		SubjectCA: subjectCA,
		Validity:  validity,
	}}

	results, err := ca.BridgeTrustPEMs(database, bridges, map[string]struct {
		Cert string
		Key  string
	}{
		issuerCA: {Cert: cfg.CAs[issuerCA].Cert, Key: cfg.CAs[issuerCA].Key},
	})
	if err != nil {
		return fmt.Errorf("trust bridge: %w", err)
	}
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
	slog.Info("trust bridge established", "count", len(results))
	return nil
}

func trustBridgeList(cfg *internal.Config, database *db.DB, args []string) error {
	records, err := database.ListCrossCertsAll()
	if err != nil {
		return fmt.Errorf("list cross certs: %w", err)
	}
	data, _ := json.MarshalIndent(records, "", "  ")
	fmt.Println(string(data))
	return nil
}

func trustBridgeFederate(cfg *internal.Config, database *db.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: trust-bridge federate <url>")
	}
	remoteURL := args[0]
	n, err := ca.TrustAnchorFederate(database, remoteURL)
	if err != nil {
		return fmt.Errorf("federate: %w", err)
	}
	slog.Info("trust anchors federated", "imported", n, "source", remoteURL)
	return nil
}

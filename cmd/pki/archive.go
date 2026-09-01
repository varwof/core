// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdArchive(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	caName := fs.String("ca", "", "Filter by CA")
	listMode := fs.Bool("list", false, "List archived certificates")
	expired := fs.Bool("expired", true, "Archive expired certificates")
	revoked := fs.Bool("revoked", false, "Archive revoked certificates")
	retention := fs.Int("retention", 365, "Archive after N days from expiry/revocation")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if *listMode {
		archived, err := database.ListArchivedCerts(*caName, 100)
		if err != nil {
			return fmt.Errorf("list archived: %w", err)
		}
		if archived == nil {
			archived = []*db.CertRecord{}
		}
		data, _ := json.MarshalIndent(archived, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	policy := &ca.ArchivePolicy{
		Enabled:        true,
		RetentionDays:  *retention,
		IncludeCA:      *caName,
		ArchiveExpired: *expired,
		ArchiveRevoked: *revoked,
	}
	result, err := ca.ArchiveCerts(database, policy)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
	return nil
}

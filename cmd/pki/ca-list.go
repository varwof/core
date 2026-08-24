// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdCAList(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ca-list", flag.ExitOnError)
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	list, err := database.ListCAMetas()
	if err != nil {
		return fmt.Errorf("list ca_meta: %w", err)
	}

	if len(list) == 0 {
		fmt.Println("no CAs found in database")
		return nil
	}

	fmt.Printf("%-16s %-40s %-20s %-10s\n", "NAME", "SUBJECT", "EXPIRY", "ALGORITHM")
	for _, ca := range list {
		expiry := "expired"
		if ca.NotAfter.After(time.Now()) {
			remaining := time.Until(ca.NotAfter)
			days := int(remaining.Hours() / 24)
			expiry = fmt.Sprintf("%dd", days)
		}
		fmt.Printf("%-16s %-40s %-20s %-10s\n",
			ca.Name, ca.Subject, expiry, ca.KeyAlgorithm)
	}
	return nil
}

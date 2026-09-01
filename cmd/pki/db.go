// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdDBBackup(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("db backup", flag.ExitOnError)
	out := fs.String("out", "", bundle.T(curLang, "cli.flag_out_path"))
	fs.Parse(args)

	dbPath := cfg.DB
	if dbPath == "" {
		return fmt.Errorf("no db path configured")
	}

	backupPath := *out
	if backupPath == "" {
		backupPath = dbPath + ".backup"
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if err := database.BackupTo(backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	abs, _ := filepath.Abs(backupPath)
	fmt.Println(abs)
	return nil
}

func cmdDBMigrate(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("db migrate", flag.ExitOnError)
	toVersion := fs.Int("to", -1, bundle.T(curLang, "cli.flag_to_version"))
	force := fs.Bool("force", false, bundle.T(curLang, "cli.flag_force"))
	dryRun := fs.Bool("dry-run", false, bundle.T(curLang, "cli.flag_dry_run"))
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	current, err := database.CurrentVersion()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}

	if *toVersion == -1 {
		*toVersion = db.SchemaVersion()
	}

	if *toVersion == current {
		pf("cli.db_already_at", current, db.SchemaVersion())
		return nil
	}

	if *dryRun {
		if *toVersion > current {
			pf("cli.db_would_upgrade", current, *toVersion)
		} else {
			pf("cli.db_would_rollback", current, *toVersion)
		}
		return nil
	}

	if *toVersion < current && !*force {
		slog.Warn("db migrate: rolling back is destructive and may cause data loss",
			"from", current, "to", *toVersion)
		slog.Warn("use --force to confirm")
		return ef("cli.db_aborted_rollback")
	}

	if err := database.MigrateTo(*toVersion); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	pf("cli.db_migrated", current, *toVersion)
	return nil
}

func cmdDBTransfer(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("db transfer", flag.ExitOnError)
	from := fs.String("from", "", bundle.T(curLang, "cli.flag_db_from"))
	to := fs.String("to", "", bundle.T(curLang, "cli.flag_db_to"))
	fs.Parse(args)

	if *from == "" || *to == "" {
		return fmt.Errorf("usage: pki db transfer --from <source-dsn> --to <target-dsn>\n" +
			"  --from sqlite:///path/to/source.db\n" +
			"  --to   postgres://user:pass@host/db  or  mysql://user:pass@host/db")
	}

	slog.Info("db transfer: opening target and running migrations", "target", *to)
	target, err := db.OpenWithDialect(*to, db.DialectForDSN(*to))
	if err != nil {
		return fmt.Errorf("open target: %w", err)
	}
	defer target.Close()

	if err := db.TransferTo(target, *from); err != nil {
		return fmt.Errorf("transfer failed: %w", err)
	}
	fmt.Println("transfer complete")
	return nil
}

func cmdDBInit(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("db init", flag.ExitOnError)
	dsn := fs.String("dsn", cfg.DB, bundle.T(curLang, "cli.flag_db_dsn"))
	fs.Parse(args)

	if *dsn == "" {
		return ef("cli.err_no_db_path")
	}

	res, err := db.CreateDatabaseIfNotExists(*dsn)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	if res.Driver != "sqlite" {
		if res.Created {
			pfln("cli.db_init_created", res.Database)
		} else {
			pfln("cli.db_init_exists", res.Database)
		}
	} else {
		pfln("cli.db_init_sqlite")
	}

	database, err := db.Open(*dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	current, err := database.CurrentVersion()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	pf("cli.db_ready", res.Driver, current)
	return nil
}

func cmdDB(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		return ef("cli.err_subcmd_required")
	}
	switch args[0] {
	case "backup":
		return cmdDBBackup(cfg, args[1:])
	case "migrate":
		return cmdDBMigrate(cfg, args[1:])
	case "transfer":
		return cmdDBTransfer(cfg, args[1:])
	case "init":
		return cmdDBInit(cfg, args[1:])
	default:
		return ef("cli.err_unknown_subcmd", "db", args[0])
	}
}

func cmdKey(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		return ef("cli.err_subcmd_required")
	}
	switch args[0] {
	case "encrypt":
		return cmdKeyEncrypt(cfg, args[1:])
	case "decrypt":
		return cmdKeyDecrypt(cfg, args[1:])
	default:
		return ef("cli.err_unknown_subcmd", "key", args[0])
	}
}

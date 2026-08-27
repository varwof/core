// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/i18n"
)

var bundle = i18n.NewBundle()
var curLang string

func main() {
	os.Exit(runCmd(os.Args[1:]))
}

func runCmd(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 1
	}

	baseCfg := internal.DefaultConfig()

	// Manual --config scan.
	hasConfig := false
	explicitPath := ""
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			hasConfig = true
			explicitPath = args[i+1]
			if loaded, err := internal.LoadConfig(explicitPath); err == nil {
				baseCfg = *internal.MergeConfig(&baseCfg, loaded)
			} else {
				slog.Warn("config: failed to load", "path", explicitPath, "error", err)
			}
			break
		}
		if len(arg) > 9 && arg[:9] == "--config=" {
			hasConfig = true
			explicitPath = arg[9:]
			if loaded, err := internal.LoadConfig(explicitPath); err == nil {
				baseCfg = *internal.MergeConfig(&baseCfg, loaded)
			} else {
				slog.Warn("config: failed to load", "path", explicitPath, "error", err)
			}
			break
		}
	}

	// Resolve and store the config path for subcommands.
	configPath = resolveConfigPath(explicitPath)
	if configPath != "" && hasConfig {
		// Already loaded above.
	} else if configPath != "" {
		if loaded, err := internal.LoadConfig(configPath); err == nil {
			baseCfg = *internal.MergeConfig(&baseCfg, loaded)
		} else {
			slog.Warn("config: ignoring auto-discovered config", "path", configPath, "error", err)
		}
	}

	curLang = i18n.DetectLang(baseCfg.Locale, "")

	// Scan for -v / --verbose before command resolution
	verbose := false
	for _, arg := range args {
		if arg == "-v" || arg == "--verbose" {
			verbose = true
			break
		}
	}

	initLogFormat(baseCfg.Serve.LogFormat, baseCfg.Serve.LogDest, verbose)

	// Load authorization policy if configured (for CLI commands like issue).
	if baseCfg.AuthorizationFile != "" {
		if p, err := auth.LoadPolicy(baseCfg.AuthorizationFile); err != nil {
			slog.Warn("authz: failed to load policy", "path", baseCfg.AuthorizationFile, "error", err)
		} else {
			auth.SetPolicy(p)
		}
	}

	// Find first non-flag argument(s) as the command name.
	cmdArgs := args
	var cmd, sub string
	cmdIdx := -1
	skipNext := false
	for i, arg := range cmdArgs {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--config" && i+1 < len(cmdArgs) {
			skipNext = true
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			cmd = arg
			cmdIdx = i + 1
			// Check for two-level command
			if i+1 < len(cmdArgs) && !strings.HasPrefix(cmdArgs[i+1], "-") {
				sub = cmdArgs[i+1]
			}
			break
		}
	}
	if cmd == "" || cmd == "help" || cmd == "-h" || cmd == "--help" {
		printUsage()
		return 0
	}

	var fn func(cfg *internal.Config, args []string) error
	var fnArgs []string

	resolve := func(c, s string) func(cfg *internal.Config, args []string) error {
		// Two-level commands: require a valid sub.
		if c == "ca" {
			switch s {
			case "list":
				return cmdCAList
			case "info":
				return cmdCAInfo
			case "init":
				return cmdInitCA
			case "offline-sign":
				return cmdCAOfflineSign
			case "cold-backup":
				return cmdCAColdBackup
			case "encrypt-key":
				return cmdCAEncryptKey
			}
			return nil
		}
		if c == "ct" {
			switch s {
			case "submit":
				return cmdCTSubmit
			}
			return nil
		}
		if c == "sub-ca" {
			switch s {
			case "create":
				return cmdSubCACreate
			case "list":
				return cmdSubCAList
			case "info":
				return cmdSubCAInfo
			}
			return nil
		}
		if c == "cross-cert" {
			// cross-cert is also a single-level command; pass s as first arg
			return cmdCrossCert
		}
		// Single-level commands: only match when s is empty
		// (i.e. not consumed as a two-level sub).
		if s != "" {
			return nil
		}
		switch c {
		case "cross-cert":
			return cmdCrossCert
		case "serve":
			return serveCmd
		case "issue":
			return cmdIssue
		case "renew":
			return cmdRenew
		case "revoke":
			return cmdRevoke
		case "crl":
			return cmdCRL
		case "crl-verify":
			return cmdCRLVerify
		case "import":
			return cmdImport
		case "sign":
			return cmdSign
		case "verify":
			return cmdVerify
		case "verify-path":
			return cmdVerifyPath
		case "run":
			return cmdRun
		case "export":
			return cmdExport
		case "list":
			return cmdListCert
		case "version":
			return cmdVersion
		case "init-config":
			return cmdInitConfig
		case "init-full":
			return cmdInitFull
		case "completion":
			return cmdCompletion
		case "batch":
			return cmdBatch
		case "recover":
			return cmdRecover
		case "user":
			return cmdUser
		case "token":
			return cmdToken
		case "audit":
			return cmdAudit
		case "ra":
			return cmdRA
		case "rbac":
			return cmdRBAC
		case "key":
			return cmdKey
		case "db":
			return cmdDB
		case "trust":
			return cmdTrust
		case "auto-renew":
			return cmdAutoRenew
		case "archive":
			return cmdArchive
		case "trust-bridge":
			return cmdTrustBridge
		case "notify":
			return cmdNotify
		case "report":
			return cmdReport
		case "cpcps":
			return cmdCPCPS
		case "benchmark":
			return cmdBenchmark
		case "policy":
			return cmdPolicy
		}
		return nil
	}

	// Try two-level first: "ca list", "ct submit", etc.
	fn = resolve(cmd, sub)
	if fn != nil {
		if sub != "" {
			// cross-cert passes sub as first arg
			if cmd == "cross-cert" {
				fnArgs = append([]string{sub}, args[cmdIdx+1:]...)
			} else {
				fnArgs = args[cmdIdx+1:] // skip cmd + sub
			}
		} else {
			fnArgs = args[cmdIdx:] // skip cmd only
		}
	} else {
		// Not a two-level command; sub (if any) is part of args.
		fn = resolve(cmd, "")
		fnArgs = args[cmdIdx:]
	}

	// Backward compat aliases: init-ca, ca-list, ca-info, ct-submit.
	if fn == nil {
		switch cmd {
		case "init-ca":
			fn = cmdInitCA
			fnArgs = args[cmdIdx:]
		case "ca-list":
			fn = cmdCAList
			fnArgs = args[cmdIdx:]
		case "ca-info":
			fn = cmdCAInfo
			fnArgs = args[cmdIdx:]
		case "ct-submit":
			fn = cmdCTSubmit
			fnArgs = args[cmdIdx:]
		}
	}

	if fn == nil {
		slog.Error(bundle.T(curLang, "cli.unknown_cmd"), "command", cmd)
		printUsage()
		return 1
	}

	fnArgs = stripConfigFlag(fnArgs)
	if err := fn(&baseCfg, fnArgs); err != nil {
		slog.Error(bundle.T(curLang, "cli.cmd_failed"), "command", cmd, "error", err)
		return 1
	}
	return 0
}

// stripConfigFlag removes "--config <path>" and "--config=<path>" from the
// subcommand argument list; it is consumed globally in runCmd before dispatch.
func stripConfigFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "-config":
			i++ // skip the value
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-config="):
			// skip
		default:
			out = append(out, a)
		}
	}
	return out
}

var logFile *os.File

func initLogFormat(format, dest string, verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	// Close any previously opened log file to release the handle (matters on Windows).
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}

	// Resolve the output writer. Defaults to stderr; supports file: and syslog.
	w := io.Writer(os.Stderr)
	switch {
	case dest == "" || dest == "stderr":
		// default
	case dest == "syslog":
		sw, err := openSyslogWriter()
		if err != nil {
			slog.Warn("log: syslog unavailable, falling back to stderr", "error", err)
		} else {
			w = sw
		}
	case strings.HasPrefix(dest, "file:"):
		path := strings.TrimPrefix(dest, "file:")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			slog.Warn("log: cannot open log file, falling back to stderr", "path", path, "error", err)
		} else {
			w = f
			logFile = f
		}
	default:
		slog.Warn("log: unknown log_dest, falling back to stderr", "dest", dest)
	}

	switch format {
	case "json", "json-flag":
		slog.SetDefault(slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
	default:
		slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
	}
}

func cmdVersion(cfg *internal.Config, args []string) error {
	fmt.Println(versionString())
	return nil
}

func printUsage() {
	lang := curLang
	t := func(key string, args ...any) string { return bundle.T(lang, key, args...) }
	fmt.Println(t("cli.usage_title") + `

` + t("cli.section_ca") + `
  ca init         ` + t("cli.desc_ca_init") + `
  ca list         ` + t("cli.desc_ca_list") + `
  ca info         ` + t("cli.desc_ca_info") + `
  ca offline-sign ` + t("cli.desc_ca_offline_sign") + `

` + t("cli.section_cert") + `
  issue         ` + t("cli.desc_issue") + `
  renew         ` + t("cli.desc_renew") + `
  revoke        ` + t("cli.desc_revoke") + `
  crl           ` + t("cli.desc_crl") + `
  crl-verify    ` + t("cli.desc_crl_verify") + `
  list          ` + t("cli.desc_list") + `
  import        ` + t("cli.desc_import") + `
  export        ` + t("cli.desc_export") + `

` + t("cli.section_cross") + `
  cross-cert issue   ` + t("cli.desc_cross_issue") + `
  cross-cert list    ` + t("cli.desc_cross_list") + `
  cross-cert revoke  ` + t("cli.desc_cross_revoke") + `
  sub-ca create      ` + t("cli.desc_subca_create") + `
  sub-ca list        ` + t("cli.desc_subca_list") + `
  sub-ca info        ` + t("cli.desc_subca_info") + `

` + t("cli.section_sign") + `
  sign          ` + t("cli.desc_sign") + `
  verify        ` + t("cli.desc_verify") + `
  run           ` + t("cli.desc_run") + `
  batch         ` + t("cli.desc_batch") + `
  benchmark     ` + t("cli.desc_benchmark") + `
  report        ` + t("cli.desc_report") + `

` + t("cli.section_server") + `
  serve         ` + t("cli.desc_serve") + `
  serve tsa     ` + t("cli.desc_serve_tsa") + `
  serve ocsp    ` + t("cli.desc_serve_ocsp") + `
  serve crl     ` + t("cli.desc_serve_crl") + `
  serve api     ` + t("cli.desc_serve_api") + `
  serve dns     ` + t("cli.desc_serve_dns") + `

` + t("cli.section_key") + `
  key encrypt   ` + t("cli.desc_key_encrypt") + `
  key decrypt   ` + t("cli.desc_key_decrypt") + `
  recover       ` + t("cli.desc_recover") + `

` + t("cli.section_admin") + `
  user          ` + t("cli.desc_user") + `
  token         ` + t("cli.desc_token") + `
  audit         ` + t("cli.desc_audit") + `
  ra            ` + t("cli.desc_ra") + `

` + t("cli.section_ct") + `
  ct submit     ` + t("cli.desc_ct_submit") + `

` + t("cli.section_util") + `
  version       ` + t("cli.desc_version") + `
  init-full     ` + t("cli.desc_init_full") + `
  init-config   ` + t("cli.desc_init_config") + `
  completion    ` + t("cli.desc_completion") + `
  db backup     ` + t("cli.desc_db_backup") + `
  db init       ` + t("cli.desc_db_init") + `
  db migrate    ` + t("cli.desc_db_migrate") + `
  help          ` + t("cli.desc_help") + `

` + t("cli.section_automation") + `
  auto-renew    ` + t("cli.desc_auto_renew") + `
  archive       ` + t("cli.desc_archive") + `
  notify test-smtp ` + t("cli.desc_notify_test_smtp") + `

` + t("cli.section_federation") + `
  trust-bridge issue    ` + t("cli.desc_trust_bridge_issue") + `
  trust-bridge list     ` + t("cli.desc_trust_bridge_list") + `
  trust-bridge federate ` + t("cli.desc_trust_bridge_federate") + ``)
}

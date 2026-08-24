// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"os"

	"github.com/varwof/core/internal"
)

var commands = []string{
	"ca", "issue", "renew", "revoke", "crl",
	"import", "sign", "verify", "verify-path", "export", "batch",
	"serve", "key", "db", "ct",
	"user", "token", "audit", "ra",
	"recover",
	"version", "init-config", "completion", "help",
}

var caSubCommands = []string{"init", "list", "info", "offline-sign"}
var keySubCommands = []string{"encrypt", "decrypt"}
var dbSubCommands = []string{"backup"}
var ctSubCommands = []string{"submit"}

func cmdCompletion(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		printCompletionUsage()
		return nil
	}
	shell := args[0]
	switch shell {
	case "bash":
		return printBashCompletion()
	case "zsh":
		return printZshCompletion()
	case "fish":
		return printFishCompletion()
	default:
		printCompletionUsage()
		return ef("cli.completion_shell", shell)
	}
}

func printCompletionUsage() {
	fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.completion_usage"))
}

func printBashCompletion() error {
	fmt.Print(`# goca bash completion
_goca_completions() {
	local cur="${COMP_WORDS[COMP_CWORD]}"
	local prev="${COMP_WORDS[COMP_CWORD-1]}"

	# --config takes a file path
	if [[ "$prev" == "--config" ]]; then
		COMPREPLY=($(compgen -f -- "$cur"))
		return 0
	fi

	# Top-level commands
	if [[ "$COMP_CWORD" -eq 1 ]]; then
		COMPREPLY=($(compgen -W "ca issue renew revoke crl import sign verify verify-path export batch serve key db ct user token audit ra recover version init-config completion help" -- "$cur"))
		return 0
	fi

	# Two-level command completion
	if [[ "$COMP_CWORD" -eq 2 ]]; then
		local cmd="${COMP_WORDS[1]}"
		case "$cmd" in
			ca)
				COMPREPLY=($(compgen -W "init list info" -- "$cur"))
				return 0
				;;
			key)
				COMPREPLY=($(compgen -W "encrypt decrypt" -- "$cur"))
				return 0
				;;
			db)
				COMPREPLY=($(compgen -W "backup migrate" -- "$cur"))
				return 0
				;;
			ct)
				COMPREPLY=($(compgen -W "submit" -- "$cur"))
				return 0
				;;
		esac
	fi

	# Subcommand-specific flags
	local cmd="${COMP_WORDS[1]}"
	local sub="${COMP_WORDS[2]}"
	case "$cmd" in
		serve)
			COMPREPLY=($(compgen -W "--config --install --uninstall" -- "$cur"))
			;;
		issue)
			COMPREPLY=($(compgen -W "--config --ca --cn --san --profile --key-type --validity --csr --out --out-dir --out-name --out-key" -- "$cur"))
			;;
		renew)
			COMPREPLY=($(compgen -W "--config --serial --cert --ca --validity --out-dir --out-name --keep-key" -- "$cur"))
			;;
		revoke)
			COMPREPLY=($(compgen -W "--config --serial --cert --ca --reason" -- "$cur"))
			;;
		crl)
			COMPREPLY=($(compgen -W "--config --ca --out --partition --total" -- "$cur"))
			;;
		sign)
			COMPREPLY=($(compgen -W "--config --ca --cert --key --chain --verify --embed --cades --sig --cn --profile" -- "$cur"))
			;;
		verify)
			COMPREPLY=($(compgen -W "--config --sig --embed" -- "$cur"))
			;;
		export)
			COMPREPLY=($(compgen -W "--config --cert --key --chain --password --out --pfx" -- "$cur"))
			;;
			ca)
				case "$sub" in
					init)
						COMPREPLY=($(compgen -W "--config --name --profile --parent --parent-key --key-type --validity --out-cert --out-key --password --prompt --no-store-key --permitted-dns --excluded-dns" -- "$cur"))
						;;
					info)
						COMPREPLY=($(compgen -W "--config --name" -- "$cur"))
						;;
					offline-sign)
						COMPREPLY=($(compgen -W "--config --ca-cert --ca-key --ca-key-password --csr --out --validity --pathlen --hash" -- "$cur"))
						;;
				esac
				;;
		import)
			COMPREPLY=($(compgen -W "--config --ca --index --cert-dir --ca-cert" -- "$cur"))
			;;
		batch)
			COMPREPLY=($(compgen -W "--config --ca --csv --out-dir" -- "$cur"))
			;;
		key)
			case "$sub" in
				encrypt|decrypt)
					COMPREPLY=($(compgen -W "--config --in --out --password" -- "$cur"))
					;;
			esac
			;;
		db)
			case "$sub" in
				backup)
					COMPREPLY=($(compgen -W "--config --out" -- "$cur"))
					;;
				migrate)
					COMPREPLY=($(compgen -W "--config --to --force --dry-run" -- "$cur"))
					;;
			esac
			;;
		ct)
			case "$sub" in
				submit)
					COMPREPLY=($(compgen -W "--config --cert --chain --url --api-key --ca --serial" -- "$cur"))
					;;
			esac
			;;
		user)
			COMPREPLY=($(compgen -W "--config --username --password --role" -- "$cur"))
			;;
		token)
			COMPREPLY=($(compgen -W "--config --username --description --id" -- "$cur"))
			;;
		audit)
			COMPREPLY=($(compgen -W "--config --limit --offset verify" -- "$cur"))
			;;
		ra)
			COMPREPLY=($(compgen -W "--config submit list approve reject show --csr --cn --san --profile --ca --id --comment --reason" -- "$cur"))
			;;
		recover)
			COMPREPLY=($(compgen -W "--config --serial --ca --out --admin-key" -- "$cur"))
			;;
		completion)
			COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
			;;
	esac
}
complete -F _goca_completions goca
`)
	return nil
}

func printZshCompletion() error {
	fmt.Print(`#compdef goca

_goca_commands() {
  local -a commands
  commands=(
    'ca:CA management (init|list|info)'
    'issue:Issue a certificate'
    'renew:Renew a certificate'
    'revoke:Revoke a certificate'
    'crl:Generate CRL for a CA'
    'import:Import from OpenSSL index.txt'
    'sign:Sign a file (PKCS#7)'
    'verify:Verify a PKCS#7 signature'
    'verify-path:Verify a certificate path with policy processing'
    'export:Export as PFX/PKCS#12'
    'batch:Batch-issue from CSV'
    'serve:Start unified PKI server'
    'key:Key management (encrypt|decrypt)'
    'recover:Recover escrowed key'
    'db:Database operations (backup)'
    'ct:Certificate Transparency (submit)'
    'user:Manage RBAC users'
    'token:Manage API tokens'
    'audit:Query audit log'
    'ra:Registration Authority'
    'version:Print version'
    'init-config:Print sample config'
    'completion:Generate shell completion'
    'help:Show help'
  )
  _describe -t commands 'goca commands' commands
}

_goca_ca_commands() {
  local -a subcmds
  subcmds=(
    'init:Initialize a new CA'
    'list:List CAs in database'
    'info:Show CA details by name'
    'offline-sign:Offline sign a sub-CA certificate'
  )
  _describe -t ca-commands 'ca commands' subcmds
}

_goca() {
  local context state state_descr line
  typeset -A opt_args

  _arguments -C \
    '--config[config file path]:file:_files' \
    '1: :->cmds' \
    '*:: :->args'

  case "$state" in
    cmds) _goca_commands ;;
    args)
      case "$line[1]" in
        serve) _arguments '--install[install as service]' '--uninstall[uninstall service]' ;;
        issue) _arguments '--ca[CA name]' '--cn[common name]' '--san[SAN list]' '--profile[profile name]' '--key-type[key type]' '--validity[validity days]' '--csr[CSR file]:file:_files' '--out[output file]:file:_files' '--out-dir[output dir]:file:_directories' '--out-key[key output]:file:_files' '--encrypt' '--encrypt-password[password]' ;;
        renew) _arguments '--serial[serial number]' '--cert[cert file]:file:_files' '--ca[CA name]' '--validity[validity days]' '--key-type[key type]' '--keep-key' '--key[key file]:file:_files' '--out-dir[output dir]:file:_directories' '--out-name[filename stem]' ;;
        revoke) _arguments '--serial[serial number]' '--cert[cert file]:file:_files' '--ca[CA name]' '--reason[revocation reason]' ;;
        crl) _arguments '--ca[CA name]' '--out[output file]:file:_files' ;;
        sign) _arguments '--ca[CA name]' '--cert[cert file]:file:_files' '--key[key file]:file:_files' '--chain[chain file]:file:_files' '--verify' '--embed' '--cades[add CAdES-T timestamp]' '--cn[common name]' '--profile[signer profile]' '--sig[signature file]:file:_files' ;;
        verify) _arguments '--sig[signature file]:file:_files' '--embed' ;;
        export) _arguments '--cert[cert file]:file:_files' '--key[key file]:file:_files' '--chain[chain file]:file:_files' '--password[PFX password]' '--out[output]:file:_files' '--pfx' ;;
        batch) _arguments '--ca[CA name]' '--csv[CSV file]:file:_files' '--out-dir[output dir]:file:_directories' ;;
        ca) _arguments '2: :->ca-sub'
          case "$line[2]" in
            offline-sign) _arguments '--ca-cert[root CA cert]:file:_files' '--ca-key[root CA key]:file:_files' '--ca-key-password[key password]' '--csr[CSR file]:file:_files' '--out[output cert]:file:_files' '--validity[validity days]' '--pathlen[path length]' '--hash[hash algorithm]' ;;
          esac
          ;;
        import) _arguments '--ca[CA name]' '--index[index file]:file:_files' '--cert-dir[certs dir]:file:_directories' '--ca-cert[CA cert file]:file:_files' ;;
        key) _arguments '2: :->key-sub' ;;
        db) _arguments '2: :->db-sub' ;;
        ct) _arguments '2: :->ct-sub' ;;
        user) _arguments '--username[username]' '--password[password]' '--role[role]' ;;
        token) _arguments '--username[username]' '--description[description]' '--id[token ID]' ;;
        audit) _arguments '--limit[max entries]' '--offset[offset]' 'verify[verify audit hash chain]' ;;
        ra) _arguments '--csr[CSR file]:file:_files' '--cn[common name]' '--san[SAN list]' '--profile[profile]' '--ca[CA name]' '--approvals[required approvals]' '--id[request ID]' '--comment[approval comment]' '--reason[rejection reason]' ;;
        recover) _arguments '--serial[serial number]' '--ca[CA name]' '--out[output key path]:file:_files' '--admin-key[admin key path]:file:_files' ;;
        completion) _arguments '1:shell:(bash zsh fish)' ;;
      esac
      ;;
  esac
}

function _goca "$@"

_goca "$@"
`)
	return nil
}

func printFishCompletion() error {
	fmt.Print(`# goca fish completion
function __goca_complete_commands
    set -l commands ca issue renew revoke crl import sign verify verify-path export batch serve key db ct user token audit ra recover version init-config completion help
    for cmd in $commands
        echo "$cmd"
    end
end

function __goca_complete_ca
    set -l sub init list info offline-sign
    for s in $sub; echo "$s"; end
end

function __goca_is_ca_subcommand
    for sub in init list info offline-sign
        if test "$sub" = (commandline -opc)[2]
            return 0
        end
    end
    return 1
end

complete -c goca -f -n "test (count (commandline -opc)) -eq 1" -a "(__goca_complete_commands)"

# CA subcommands
complete -c goca -f -n "test (count (commandline -opc)) -eq 2; and __fish_seen_subcommand_from ca" -a "(__goca_complete_ca)"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l name -d "CA name" -r
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l profile -d "CA profile"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l parent -d "Parent CA name"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l parent-key -d "Parent key file" -r
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l key-type -d "Key type"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l validity -d "Validity days"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l out-cert -d "Output cert path" -r
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l out-key -d "Output key path" -r
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l password -d "Encrypt private key"
complete -c goca -f -n "__fish_seen_subcommand_from init; and __fish_seen_subcommand_from ca" -l no-store-key -d "Do not store key"
complete -c goca -f -n "__fish_seen_subcommand_from info; and __fish_seen_subcommand_from ca" -l name -d "CA name" -r
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l ca-cert -r -d "Root CA cert PEM"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l ca-key -r -d "Root CA key PEM"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l ca-key-password -d "Key decryption password"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l csr -r -d "Sub-CA CSR file"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l out -r -d "Output cert path"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l validity -d "Validity days"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l pathlen -d "Path length constraint"
complete -c goca -f -n "__fish_seen_subcommand_from offline-sign; and __fish_seen_subcommand_from ca" -l hash -d "Hash algorithm (sha256/sha384/sha512)"

# serve
complete -c goca -n "__fish_seen_subcommand_from serve" -l install -d "Install as service"
complete -c goca -n "__fish_seen_subcommand_from serve" -l uninstall -d "Uninstall service"

# issue
complete -c goca -n "__fish_seen_subcommand_from issue" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from issue" -l cn -d "Common name"
complete -c goca -n "__fish_seen_subcommand_from issue" -l san -d "SAN list"
complete -c goca -n "__fish_seen_subcommand_from issue" -l profile -d "Profile"
complete -c goca -n "__fish_seen_subcommand_from issue" -l key-type -d "Key type"
complete -c goca -n "__fish_seen_subcommand_from issue" -l validity -d "Validity days"
complete -c goca -n "__fish_seen_subcommand_from issue" -l csr -r -d "CSR file"
complete -c goca -n "__fish_seen_subcommand_from issue" -l out -r -d "Output cert path"
complete -c goca -n "__fish_seen_subcommand_from issue" -l out-key -r -d "Output key path"
complete -c goca -n "__fish_seen_subcommand_from issue" -l encrypt -d "Encrypt key"
complete -c goca -n "__fish_seen_subcommand_from issue" -l encrypt-password -d "Encryption password"

# renew
complete -c goca -n "__fish_seen_subcommand_from renew" -l serial -d "Serial number"
complete -c goca -n "__fish_seen_subcommand_from renew" -l cert -r -d "Cert file"
complete -c goca -n "__fish_seen_subcommand_from renew" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from renew" -l validity -d "Validity days"
complete -c goca -n "__fish_seen_subcommand_from renew" -l key-type -d "Key type"
complete -c goca -n "__fish_seen_subcommand_from renew" -l keep-key -d "Keep existing key"
complete -c goca -n "__fish_seen_subcommand_from renew" -l key -r -d "Key file (with --keep-key)"

# revoke
complete -c goca -n "__fish_seen_subcommand_from revoke" -l serial -d "Serial number"
complete -c goca -n "__fish_seen_subcommand_from revoke" -l cert -r -d "Cert file"
complete -c goca -n "__fish_seen_subcommand_from revoke" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from revoke" -l reason -d "Revocation reason"

# crl
complete -c goca -n "__fish_seen_subcommand_from crl" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from crl" -l out -r -d "Output CRL path"
complete -c goca -n "__fish_seen_subcommand_from crl" -l partition -d "Partition index (0-based)"
complete -c goca -n "__fish_seen_subcommand_from crl" -l total -d "Total partitions"

# sign
complete -c goca -n "__fish_seen_subcommand_from sign" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from sign" -l cert -r -d "Cert file"
complete -c goca -n "__fish_seen_subcommand_from sign" -l key -r -d "Key file"
complete -c goca -n "__fish_seen_subcommand_from sign" -l chain -r -d "Chain file"
complete -c goca -n "__fish_seen_subcommand_from sign" -l embed -d "Embedded signature"
complete -c goca -n "__fish_seen_subcommand_from sign" -l cades -d "Add CAdES-T timestamp"
complete -c goca -n "__fish_seen_subcommand_from sign" -l verify -d "Verify only"

# verify
complete -c goca -n "__fish_seen_subcommand_from verify" -l sig -r -d "Signature file"
complete -c goca -n "__fish_seen_subcommand_from verify" -l embed -d "Embedded signature"

# export
complete -c goca -n "__fish_seen_subcommand_from export" -l cert -r -d "Cert file"
complete -c goca -n "__fish_seen_subcommand_from export" -l key -r -d "Key file"
complete -c goca -n "__fish_seen_subcommand_from export" -l chain -r -d "Chain file"
complete -c goca -n "__fish_seen_subcommand_from export" -l password -d "PFX password"
complete -c goca -n "__fish_seen_subcommand_from export" -l out -r -d "Output path"
complete -c goca -n "__fish_seen_subcommand_from export" -l pfx -d "Export as PFX"

# batch
complete -c goca -n "__fish_seen_subcommand_from batch" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from batch" -l csv -r -d "CSV file"
complete -c goca -n "__fish_seen_subcommand_from batch" -l out-dir -r -d "Output dir"

# import
complete -c goca -n "__fish_seen_subcommand_from import" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from import" -l index -r -d "index.txt file"
complete -c goca -n "__fish_seen_subcommand_from import" -l cert-dir -r -d "Certs directory"

# key
complete -c goca -f -n "test (count (commandline -opc)) -eq 2; and __fish_seen_subcommand_from key" -a "encrypt decrypt"
complete -c goca -n "__fish_seen_subcommand_from encrypt; and __fish_seen_subcommand_from key" -l in -r -d "Input key file"
complete -c goca -n "__fish_seen_subcommand_from encrypt; and __fish_seen_subcommand_from key" -l out -r -d "Output key file"
complete -c goca -n "__fish_seen_subcommand_from encrypt; and __fish_seen_subcommand_from key" -l password -d "Password"
complete -c goca -n "__fish_seen_subcommand_from decrypt; and __fish_seen_subcommand_from key" -l in -r -d "Input key file"
complete -c goca -n "__fish_seen_subcommand_from decrypt; and __fish_seen_subcommand_from key" -l out -r -d "Output key file"
complete -c goca -n "__fish_seen_subcommand_from decrypt; and __fish_seen_subcommand_from key" -l password -d "Password"

# db
complete -c goca -f -n "test (count (commandline -opc)) -eq 2; and __fish_seen_subcommand_from db" -a "backup migrate"
complete -c goca -n "__fish_seen_subcommand_from backup; and __fish_seen_subcommand_from db" -l out -r -d "Backup output path"
complete -c goca -n "__fish_seen_subcommand_from migrate; and __fish_seen_subcommand_from db" -l to -r -d "Target migration version"
complete -c goca -n "__fish_seen_subcommand_from migrate; and __fish_seen_subcommand_from db" -l force -d "Skip safety warning"
complete -c goca -n "__fish_seen_subcommand_from migrate; and __fish_seen_subcommand_from db" -l dry-run -d "Show what would be done"

# ct
complete -c goca -f -n "test (count (commandline -opc)) -eq 2; and __fish_seen_subcommand_from ct" -a "submit"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l cert -r -d "Cert file"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l chain -r -d "Chain file"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l url -d "CT log URL"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l api-key -d "CT log API key"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from submit; and __fish_seen_subcommand_from ct" -l serial -d "Serial number"

# recover
complete -c goca -n "__fish_seen_subcommand_from recover" -l serial -d "Serial number"
complete -c goca -n "__fish_seen_subcommand_from recover" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from recover" -l out -r -d "Output key path"
complete -c goca -n "__fish_seen_subcommand_from recover" -l admin-key -r -d "Admin key path"

# user
complete -c goca -n "__fish_seen_subcommand_from user" -l username -d "Username"
complete -c goca -n "__fish_seen_subcommand_from user" -l password -d "Password"
complete -c goca -n "__fish_seen_subcommand_from user" -l role -d "Role"

# token
complete -c goca -n "__fish_seen_subcommand_from token" -l username -d "Username"
complete -c goca -n "__fish_seen_subcommand_from token" -l description -d "Description"
complete -c goca -n "__fish_seen_subcommand_from token" -l id -d "Token ID"

# audit
complete -c goca -n "__fish_seen_subcommand_from audit" -l limit -d "Max entries"
complete -c goca -n "__fish_seen_subcommand_from audit" -l offset -d "Offset"

# ra
complete -c goca -n "__fish_seen_subcommand_from ra" -l csr -r -d "CSR file"
complete -c goca -n "__fish_seen_subcommand_from ra" -l cn -d "Common name"
complete -c goca -n "__fish_seen_subcommand_from ra" -l san -d "SAN list"
complete -c goca -n "__fish_seen_subcommand_from ra" -l profile -d "Profile"
complete -c goca -n "__fish_seen_subcommand_from ra" -l ca -d "CA name"
complete -c goca -n "__fish_seen_subcommand_from ra" -l approvals -d "Required approvals"
complete -c goca -n "__fish_seen_subcommand_from ra" -l id -d "Request ID"
complete -c goca -n "__fish_seen_subcommand_from ra" -l comment -d "Comment"
complete -c goca -n "__fish_seen_subcommand_from ra" -l reason -d "Reason"

# version
complete -c goca -n "__fish_seen_subcommand_from version" -l config -r -d "Config file path"

# completion
complete -c goca -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
`)
	return nil
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

func cmdCAColdBackup(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ca cold-backup", flag.ExitOnError)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "backup":
		return caColdBackupCreate(fs, args)
	case "verify":
		return caColdBackupVerify(fs, args)
	case "":
		return fmt.Errorf("usage: pki ca cold-backup <backup|verify>")
	default:
		return fmt.Errorf("unknown subcommand %q (want backup|verify)", sub)
	}
}

func caColdBackupCreate(fs *flag.FlagSet, args []string) error {
	caName := fs.String("ca-name", "root", "name of the CA being backed up (metadata only)")
	caCert := fs.String("ca-cert", "", "path to the CA certificate PEM")
	caKey := fs.String("ca-key", "", "path to the CA private key PEM")
	keyPassword := fs.String("ca-key-password", "", "CA key decryption password (default: PKI_KEY_PASSWORD env)")
	password := fs.String("password", "", "backup encryption password (use --password-file or PKI_BACKUP_PASSWORD)")
	passwordFile := fs.String("password-file", "", "read backup password from file")
	out := fs.String("out", "root-ca-cold-backup.json", "output backup file path")
	shred := fs.Bool("shred", false, "securely delete the source key after a successful backup")
	fs.Parse(args)

	pwd, err := resolveBackupPassword(*password, *passwordFile)
	if err != nil {
		return err
	}

	if err := ca.ColdBackupCA(*caName, *caCert, *caKey, pwd, *keyPassword, *out); err != nil {
		return err
	}
	fmt.Printf("cold backup written: %s (ca=%s)\n", *out, *caName)

	if *shred {
		if *caKey == "" {
			return fmt.Errorf("--shred requires --ca-key")
		}
		if err := shredFile(*caKey); err != nil {
			return fmt.Errorf("shred source key: %w", err)
		}
		fmt.Printf("source key shredded: %s\n", *caKey)
	}
	return nil
}

func caColdBackupVerify(fs *flag.FlagSet, args []string) error {
	in := fs.String("in", "", "path to the cold backup file")
	password := fs.String("password", "", "backup encryption password (use --password-file or PKI_BACKUP_PASSWORD)")
	passwordFile := fs.String("password-file", "", "read backup password from file")
	fs.Parse(args)

	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	pwd, err := resolveBackupPassword(*password, *passwordFile)
	if err != nil {
		return err
	}
	summary, err := ca.VerifyColdBackup(*in, pwd)
	if err != nil {
		return err
	}
	fmt.Println(summary)
	return nil
}

func resolveBackupPassword(password, passwordFile string) (string, error) {
	if password != "" {
		return password, nil
	}
	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if env := os.Getenv("PKI_BACKUP_PASSWORD"); env != "" {
		return env, nil
	}
	p, err := readPassword("Backup password: ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", fmt.Errorf("empty backup password")
	}
	return p, nil
}

// shredFile overwrites the file with zeros then ones before unlinking, to make
// recovery of the offline Root CA key from storage impractical.
func shredFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	patterns := [][]byte{{0x00}, {0xff}, {0x00}}
	for _, pat := range patterns {
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
		buf := make([]byte, 4096)
		for written := int64(0); written < size; {
			n := copy(buf, pat)
			if n > int(size-written) {
				n = int(size - written)
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			written += int64(n)
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

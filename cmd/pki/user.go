// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdUser(cfg *internal.Config, args []string) error {
	if len(args) < 1 {
		return ef("cli.err_subcmd_required")
	}
	database, err := db.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer database.Close()
	switch args[0] {
	case "add":
		return cmdUserAdd(database, args[1:])
	case "delete":
		return cmdUserDelete(database, args[1:])
	case "list":
		return cmdUserList(database)
	case "passwd":
		return cmdUserPasswd(database, args[1:])
	case "bind-operator-cert":
		return cmdUserBindOperatorCert(database, args[1:])
	case "unbind-operator-cert":
		return cmdUserUnbindOperatorCert(database, args[1:])
	default:
		return ef("cli.err_unknown_subcmd", args[0])
	}
}

func cmdUserAdd(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	role := fs.String("role", "operator", bundle.T(curLang, "cli.flag_role"))
	fs.Parse(args)
	if *username == "" || *password == "" {
		return ef("cli.err_username_password")
	}
	if err := validatePasswordStrength(*password); err != nil {
		return err
	}
	salt, err := db.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hash := db.HashPassword(*password, salt)
	if err := d.CreateUser(*username, hash, salt, *role); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.user_created"), "username", *username, "role", *role)
	return nil
}

func cmdUserDelete(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("user delete", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	fs.Parse(args)
	if *username == "" {
		return ef("cli.err_username_required")
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	if err := d.DeleteUser(user.ID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.user_deleted"), "username", *username)
	return nil
}

func cmdUserList(d *db.DB) error {
	users, err := d.ListUsers()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	pfln("cli.table_header_user")
	for _, u := range users {
		fmt.Printf("%-5d %-20s %-12s %s\n", u.ID, u.Username, u.Role, u.CreatedAt)
	}
	return nil
}

func cmdUserPasswd(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	password := fs.String("password", "", bundle.T(curLang, "cli.flag_password"))
	fs.Parse(args)
	if *username == "" || *password == "" {
		return ef("cli.err_username_password")
	}
	if err := validatePasswordStrength(*password); err != nil {
		return err
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	salt, err := db.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hash := db.HashPassword(*password, salt)
	if err := d.UpdateUserPassword(user.ID, hash, salt); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.password_updated"), "username", *username)
	return nil
}

// validateOperatorCertPEM parses and validates a management certificate
// (entity cert, DigitalSignature KU) intended to proxy an account's CA scope,
// returning the parsed certificate and its extracted scope. Validation is
// fail-closed and mirrors the serve-layer check: valid OU, inside validity
// window, issued by this PKI (DB record present), and not revoked. This
// prevents binding a stale/revoked certificate via the CLI (which would be
// rejected at auth time anyway).
func validateOperatorCertPEM(d *db.DB, pemBytes []byte) (*x509.Certificate, string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", ef("cli.err_operator_cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse operator cert: %w", err)
	}
	if err := ca.ValidateAdminCert(cert); err != nil {
		return nil, "", fmt.Errorf("operator cert is not a management certificate: %w", err)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return nil, "", ef("cli.err_operator_cert_no_ou")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, "", fmt.Errorf("operator cert expired (not_after %s)",
			cert.NotAfter.Format(time.RFC3339))
	}
	serial := fmt.Sprintf("%040X", cert.SerialNumber)
	status, err := d.GetCertStatusByIssuer(cert.Issuer.String(), serial)
	if err != nil {
		return nil, "", fmt.Errorf("operator cert not issued by this PKI (issuer=%s serial=%s): %w",
			cert.Issuer.CommonName, serial, err)
	}
	if status.Status != "V" {
		return nil, "", fmt.Errorf("operator cert status %q (not valid)", status.Status)
	}
	return cert, ca.ExtractAdminScope(cert), nil
}

func cmdUserBindOperatorCert(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("user bind-operator-cert", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	certFile := fs.String("cert", "", "operator certificate PEM file")
	fs.Parse(args)
	if *username == "" || *certFile == "" {
		return ef("cli.err_username_cert_required")
	}
	pemBytes, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert file: %w", err)
	}
	cert, scope, err := validateOperatorCertPEM(d, pemBytes)
	if err != nil {
		return err
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	if err := d.UpdateUserOperatorCert(user.ID, string(pemBytes)); err != nil {
		return fmt.Errorf("bind operator cert: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.operator_cert_bound"),
		"username", *username, "cn", cert.Subject.CommonName, "scope", scope)
	return nil
}

func cmdUserUnbindOperatorCert(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("user unbind-operator-cert", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	fs.Parse(args)
	if *username == "" {
		return ef("cli.err_username_required")
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	if err := d.UpdateUserOperatorCert(user.ID, ""); err != nil {
		return fmt.Errorf("unbind operator cert: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.operator_cert_unbound"), "username", *username)
	return nil
}

func cmdToken(cfg *internal.Config, args []string) error {
	if len(args) < 1 {
		return ef("cli.err_subcmd_required")
	}
	database, err := db.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer database.Close()
	switch args[0] {
	case "create":
		return cmdTokenCreate(database, args[1:])
	case "list":
		return cmdTokenList(database, args[1:])
	case "revoke":
		return cmdTokenRevoke(database, args[1:])
	default:
		return ef("cli.err_unknown_subcmd", args[0])
	}
}

func cmdTokenCreate(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	description := fs.String("description", "", bundle.T(curLang, "cli.flag_description"))
	expires := fs.String("expires", "", bundle.T(curLang, "cli.flag_expires"))
	fs.Parse(args)
	if *username == "" {
		return ef("cli.err_username_required")
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	expiry := ""
	if *expires != "" {
		dur, err := time.ParseDuration(*expires)
		if err != nil {
			return fmt.Errorf("invalid --expires duration %q: %w", *expires, err)
		}
		expiry = time.Now().Add(dur).UTC().Format("2006-01-02 15:04:05")
	}
	t, err := d.CreateAPIToken(user.ID, *description, expiry)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	fmt.Println(t.Token)
	return nil
}

func cmdTokenList(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ExitOnError)
	username := fs.String("username", "", bundle.T(curLang, "cli.flag_username"))
	fs.Parse(args)
	if *username == "" {
		return ef("cli.err_username_required")
	}
	user, err := d.GetUserByUsername(*username)
	if err != nil {
		return ef("cli.err_user_not_found", *username)
	}
	tokens, err := d.ListTokens(user.ID)
	if err != nil {
		return fmt.Errorf("list tokens: %w", err)
	}
	pfln("cli.table_header_token")
	for _, t := range tokens {
		desc := t.Description
		exp := ""
		if t.ExpiresAt != nil {
			exp = " (expires: " + *t.ExpiresAt + ")"
		}
		fmt.Printf("%-5d %-64s %-20s %s%s\n", t.ID, t.Token, desc, t.CreatedAt, exp)
	}
	return nil
}

func cmdTokenRevoke(d *db.DB, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
	id := fs.Int("id", 0, bundle.T(curLang, "cli.flag_token_id"))
	fs.Parse(args)
	if *id == 0 {
		return ef("cli.err_id_required")
	}
	if err := d.DeleteToken(*id); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	slog.Info(bundle.T(curLang, "cli.token_revoked"), "id", *id)
	return nil
}

func cmdAudit(cfg *internal.Config, args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		database, err := db.Open(cfg.DB)
		if err != nil {
			return err
		}
		defer database.Close()
		return cmdAuditVerify(database)
	}
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	limit := fs.Int("limit", 50, bundle.T(curLang, "cli.flag_limit"))
	offset := fs.Int("offset", 0, bundle.T(curLang, "cli.flag_offset"))
	fs.Parse(args)
	database, err := db.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer database.Close()
	entries, err := database.QueryAudit(*limit, *offset)
	if err != nil {
		return fmt.Errorf("query audit: %w", err)
	}
	pfln("cli.table_header_audit")
	for _, e := range entries {
		fmt.Printf("%-5d %-22s %-16s %-6s %-30s %s\n", e.ID, e.Timestamp, e.Username, e.Method, e.Path, e.Detail)
	}
	return nil
}

func cmdAuditVerify(d *db.DB) error {
	count, err := d.VerifyAuditChain()
	if err != nil {
		return err
	}
	if count == 0 {
		pfln("cli.audit_log_empty")
		return nil
	}
	pf("cli.audit_verified", count)
	return nil
}

func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return ef("cli.err_password_strength")
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		}
	}
	if !hasUpper {
		return ef("cli.err_password_upper")
	}
	if !hasLower {
		return ef("cli.err_password_lower")
	}
	if !hasDigit {
		return ef("cli.err_password_digit")
	}
	return nil
}

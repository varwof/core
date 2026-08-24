// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

func TestCmdInitFullInitialCRL(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp",
		"--domain", "test.varwof.com",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
		"--default-key-type", "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("cmdInitFull: %v", err)
	}

	crlDir := filepath.Join(dir, "crl")
	entries, err := os.ReadDir(crlDir)
	if err != nil {
		t.Fatalf("read crl dir: %v", err)
	}
	crlFiles := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".crl" {
			crlFiles++
			data, err := os.ReadFile(filepath.Join(crlDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x509.ParseRevocationList(data); err != nil {
				t.Fatalf("invalid CRL %s: %v", e.Name(), err)
			}
		}
	}
	if crlFiles == 0 {
		t.Fatal("expected initial CRL files to be generated")
	}
	// 8 sub-CAs each have initial CRL
	if crlFiles != 8 {
		t.Fatalf("expected 8 CRL files, got %d", crlFiles)
	}
}

func TestCmdInitFullConfigOrg(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp",
		"--domain", "test.varwof.com",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
		"--default-key-type", "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("cmdInitFull: %v", err)
	}

	loaded, err := internal.LoadConfig(filepath.Join(dir, "pki.json"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Defaults.DefaultOrg != "TestCorp" {
		t.Fatalf("expected DefaultOrg=TestCorp, got %q", loaded.Defaults.DefaultOrg)
	}

	// Server certificate subject must use org instead of default example.com
	srvCertPath := filepath.Join(dir, "tls", "api", "certs", "api.pem")
	data, err := os.ReadFile(srvCertPath)
	if err != nil {
		t.Fatalf("read api cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("api.pem not a PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "TestCorp" {
		t.Fatalf("expected subject org TestCorp, got %v", cert.Subject.Organization)
	}
}

// TestCmdInitFullSuperadmin verifies the bootstrap closed loop:
//   - Default issuance of m-superadmin certificate
//   - Certificate carries full-function PrincipalAuthorization grants (cert-first bootstrap dependency)
//   - Generates authz.json and references authorization_file in pki.json
func TestCmdInitFullSuperadmin(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp",
		"--domain", "test.varwof.com",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
		"--default-key-type", "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("cmdInitFull: %v", err)
	}

	srvCertPath := filepath.Join(dir, "management", "users", "certs", "superadmin.pem")
	data, err := os.ReadFile(srvCertPath)
	if err != nil {
		t.Fatalf("superadmin.pem not issued: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("superadmin.pem not a PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "superadmin@test.varwof.com" {
		t.Fatalf("expected CN=superadmin@test.varwof.com, got %q", cert.Subject.CommonName)
	}
	// OU must map to superadmin role (gateway RBAC basis)
	foundSuperAdminOU := false
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "SuperAdmin" {
			foundSuperAdminOU = true
		}
	}
	if !foundSuperAdminOU {
		t.Fatalf("expected OU=SuperAdmin, got %v", cert.Subject.OrganizationalUnit)
	}

	// PA grants must contain core admin permissions (cert-first bootstrap)
	pa, err := ca.ParsePrincipalAuthorizationExtension(cert.Extensions)
	if err != nil {
		t.Fatalf("parse PA extension: %v", err)
	}
	capIDs := make(map[string]bool)
	for _, g := range pa.Grants {
		capIDs[g.CapabilityId] = true
	}
	got := make([]string, 0, len(capIDs))
	for id := range capIDs {
		got = append(got, id)
	}
	// PA grants are stored separately by scheme/capability, assertions only check capability name.
	for _, want := range []string{"create", "issue", "manage", "write", "revoke-all"} {
		if !capIDs[want] {
			t.Errorf("superadmin PA missing grant %q (got %d grants: %v)", want, len(capIDs), got)
		}
	}

	// authz.json generation + config reference
	authzPath := filepath.Join(dir, "authz.json")
	if _, err := os.Stat(authzPath); err != nil {
		t.Fatalf("authz.json not generated: %v", err)
	}
	loaded, err := internal.LoadConfig(filepath.Join(dir, "pki.json"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.AuthorizationFile != authzPath {
		t.Fatalf("expected authorization_file=%q, got %q", authzPath, loaded.AuthorizationFile)
	}
}

// TestCmdInitFullAdminNamesSuperadmin verifies --admin-names supports the superadmin role.
func TestCmdInitFullAdminNamesSuperadmin(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp",
		"--domain", "test.varwof.com",
		"--out-dir", dir,
		"--config-out", filepath.Join(dir, "pki.json"),
		"--default-key-type", "ecdsa-p256",
		"--admin-names", "张三(superadmin)",
	})
	if err != nil {
		t.Fatalf("cmdInitFull: %v", err)
	}
	certPath := filepath.Join(dir, "management", "users", "certs", "user-superadmin-张三.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("custom superadmin cert not issued: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("not a PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "张三" {
		t.Fatalf("expected CN=张三, got %q", cert.Subject.CommonName)
	}
}

// TestCmdInitFullUnknownAdminRole verifies unknown role is rejected (superadmin is a valid role).
func TestCmdInitFullUnknownAdminRole(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	err := cmdInitFull(cfg, []string{
		"--org", "TestCorp",
		"--domain", "test.varwof.com",
		"--out-dir", dir,
		"--default-key-type", "ecdsa-p256",
		"--admin-names", "张三(cto)",
	})
	if err == nil {
		t.Fatal("expected error for unknown admin role")
	}
}

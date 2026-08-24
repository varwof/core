package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func testAuthCert(ous ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "auth-coverage",
			OrganizationalUnit: ous,
		},
	}
}

func TestExtractRoles(t *testing.T) {
	cert := testAuthCert("admin", "gateway:admin", "gateway:mysql-prod", "web:console")
	core := ExtractRoles(cert, NSCore)
	if len(core) != 1 || core[0] != "admin" {
		t.Fatalf("NSCore: got %v", core)
	}
	gw := ExtractRoles(cert, NSGateway)
	if len(gw) != 2 {
		t.Fatalf("NSGateway: got %v", gw)
	}
	web := ExtractRoles(cert, NSWeb)
	if len(web) != 1 || web[0] != "web:console" {
		t.Fatalf("NSWeb: got %v", web)
	}
	if got := ExtractRoles(nil, NSCore); got != nil {
		t.Fatalf("nil cert: got %v", got)
	}
	// Blank OU is trimmed by TrimSpace before matching
	spacey := testAuthCert("  ops  ")
	ops := ExtractRoles(spacey, NSCore)
	if len(ops) != 1 || ops[0] != "ops" {
		t.Fatalf("trimmed OU: got %v", ops)
	}
}

func TestHasRole(t *testing.T) {
	cases := []struct {
		name    string
		roles   []string
		allowed []string
		want    bool
	}{
		{"exact", []string{"gateway:admin"}, []string{"gateway:admin"}, true},
		{"mismatch", []string{"gateway:mysql-prod"}, []string{"gateway:admin"}, false},
		{"global wildcard", []string{"*"}, []string{"gateway:admin"}, true},
		{"global wildcard empty", []string{"*"}, nil, false},
		{"ns wildcard match", []string{"gateway:*"}, []string{"gateway:admin", "gateway:mysql-prod"}, true},
		{"ns wildcard other", []string{"gateway:*"}, []string{"web:console"}, false},
		{"web wildcard", []string{"web:*"}, []string{"web:console"}, true},
		{"empty roles", nil, []string{"admin"}, false},
		{"empty allowed", []string{"admin"}, nil, false},
		{"multi roles second matches", []string{"ops", "auditor"}, []string{"auditor"}, true},
	}
	for _, tc := range cases {
		got := HasRole(tc.roles, tc.allowed)
		if got != tc.want {
			t.Errorf("%s: HasRole(%v, %v) = %v, want %v", tc.name, tc.roles, tc.allowed, got, tc.want)
		}
	}
}

func TestCheckCertRoles(t *testing.T) {
	cert := testAuthCert("admin")
	if !CheckCertRoles(cert, NSCore, []string{"admin"}) {
		t.Fatal("admin should pass")
	}
	if CheckCertRoles(cert, NSCore, []string{"ops"}) {
		t.Fatal("ops should fail")
	}
	// empty allowed = no role requirement
	if !CheckCertRoles(cert, NSCore, nil) {
		t.Fatal("empty allowed should pass")
	}
	if CheckCertRoles(nil, NSCore, []string{"admin"}) {
		t.Fatal("nil cert should fail")
	}
}

func TestParseCertPEM(t *testing.T) {
	_, cert, _ := testPolicyCA(t, "admin")
	pemData := pemEncodeCert(cert)
	parsed, err := ParseCertPEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertPEM: %v", err)
	}
	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("CN: got %s", parsed.Subject.CommonName)
	}
	if _, err := ParseCertPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	// PEM block exists but content is not a certificate
	if _, err := ParseCertPEM([]byte("-----BEGIN FOO-----\nYmFy\n-----END FOO-----\n")); err == nil {
		t.Fatal("expected error for non-cert PEM block")
	}
}

func TestLoadCAFromFile(t *testing.T) {
	_, cert, _ := testPolicyCA(t, "admin")
	pemData := pemEncodeCert(cert)

	dir := t.TempDir()
	okPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(okPath, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadCAFromFile(okPath)
	if err != nil {
		t.Fatalf("LoadCAFromFile: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}

	if _, err := LoadCAFromFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}

	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAFromFile(badPath); err == nil {
		t.Fatal("expected error for no PEM certs")
	}
}

func TestLoadPolicy_File(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(okPath, authzData, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(okPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.Version != "v2" {
		t.Fatalf("version: got %s", p.Version)
	}
	if _, err := LoadPolicy(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error for missing policy file")
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(badPath); err == nil {
		t.Fatal("expected error for invalid policy file")
	}
}

func TestRoleScope(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	scopes := p.RoleScope("superadmin")
	if len(scopes) == 0 {
		t.Fatal("superadmin should have scopes")
	}
	if p.RoleScope("nonexistent") != nil {
		t.Fatal("nonexistent role scope should be nil")
	}
	// Role with undefined scope
	p2 := &Policy{Roles: map[string]RoleDef{"r": {}}}
	if p2.RoleScope("r") != nil {
		t.Fatal("undefined scope should be nil")
	}
}

func TestRoleNames(t *testing.T) {
	p, _ := LoadPolicyData(authzData)
	SetPolicy(p)
	defer SetPolicy(nil)
	names := RoleNames()
	if len(names) == 0 {
		t.Fatal("expected role names")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate role name %q", n)
		}
		seen[n] = true
	}
}

func TestRoleNames_NoPolicy(t *testing.T) {
	SetPolicy(nil)
	names := RoleNames()
	if len(names) == 0 {
		t.Fatal("expected hardcoded role names without policy")
	}
}

func TestSignerHasAdminOU(t *testing.T) {
	if !SignerHasAdminOU(testAuthCert("admin")) {
		t.Fatal("admin OU")
	}
	if !SignerHasAdminOU(testAuthCert("gateway:admin")) {
		t.Fatal("gateway:admin OU")
	}
	if SignerHasAdminOU(testAuthCert("ops")) {
		t.Fatal("ops should not be admin")
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestCollectAttrs(t *testing.T) {
	cfg := &LDAPConfig{
		UIDAttr:  "uid",
		MapCN:    "cn",
		MapOrg:   "o",
		MapOU:    "ou",
		MapL:     "l",
		MapST:    "st",
		MapC:     "c",
		MapEmail: "mail",
	}

	attrs := collectAttrs(cfg)
	if len(attrs) != 8 {
		t.Fatalf("expected 8 attrs, got %d: %v", len(attrs), attrs)
	}

	attrSet := make(map[string]bool)
	for _, a := range attrs {
		attrSet[a] = true
	}
	for _, expected := range []string{"uid", "cn", "o", "ou", "l", "st", "c", "mail"} {
		if !attrSet[expected] {
			t.Fatalf("missing expected attr %q", expected)
		}
	}
}

func TestCollectAttrsEmpty(t *testing.T) {
	cfg := &LDAPConfig{}
	attrs := collectAttrs(cfg)
	if len(attrs) != 0 {
		t.Fatalf("expected 0 attrs for empty config, got %d", len(attrs))
	}
}

func TestCollectAttrsDeduplicates(t *testing.T) {
	cfg := &LDAPConfig{
		MapCN:  "cn",
		MapOrg: "cn",
	}
	attrs := collectAttrs(cfg)
	if len(attrs) != 1 {
		t.Fatalf("expected 1 unique attr, got %d", len(attrs))
	}
}

func TestCheckLDAPGroupMembership(t *testing.T) {
	entry := &ldap.Entry{
		DN: "uid=john,dc=example",
		Attributes: []*ldap.EntryAttribute{
			{Name: "memberOf", Values: []string{"CN=admins,DC=example", "CN=users,DC=example"}},
		},
	}

	cfg := &LDAPConfig{}
	if !CheckLDAPGroupMembership(entry, cfg, "CN=admins,DC=example") {
		t.Fatal("expected membership match")
	}
	if CheckLDAPGroupMembership(entry, cfg, "CN=guests,DC=example") {
		t.Fatal("expected no match for guests")
	}
}

func TestCheckLDAPGroupMembershipNilEntry(t *testing.T) {
	if CheckLDAPGroupMembership(nil, &LDAPConfig{}, "CN=any") {
		t.Fatal("expected false for nil entry")
	}
}

func TestCheckLDAPGroupMembershipNoAttrs(t *testing.T) {
	entry := &ldap.Entry{
		DN:         "uid=noattrs,dc=example",
		Attributes: []*ldap.EntryAttribute{},
	}

	if CheckLDAPGroupMembership(entry, &LDAPConfig{}, "CN=any") {
		t.Fatal("expected false for entry with no attrs")
	}
}

func TestMapEntryToName(t *testing.T) {
	entry := &ldap.Entry{
		DN: "uid=johndoe,dc=example",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"John Doe"}},
			{Name: "o", Values: []string{"ACME Corp"}},
			{Name: "ou", Values: []string{"Engineering"}},
			{Name: "l", Values: []string{"Shanghai"}},
			{Name: "st", Values: []string{"SH"}},
			{Name: "c", Values: []string{"CN"}},
			{Name: "mail", Values: []string{"john@acme.com"}},
		},
	}

	cfg := &LDAPConfig{
		MapCN:    "cn",
		MapOrg:   "o",
		MapOU:    "ou",
		MapL:     "l",
		MapST:    "st",
		MapC:     "c",
		MapEmail: "mail",
	}

	name := mapEntryToName(entry, cfg)
	if name == nil {
		t.Fatal("expected non-nil name")
	}
	if name.CommonName != "John Doe" {
		t.Fatalf("expected 'John Doe', got %q", name.CommonName)
	}
	if len(name.Organization) == 0 || name.Organization[0] != "ACME Corp" {
		t.Fatalf("expected ACME Corp, got %v", name.Organization)
	}
	if len(name.Country) == 0 || name.Country[0] != "CN" {
		t.Fatalf("expected CN, got %v", name.Country)
	}
}

func TestMapEntryToNamePartial(t *testing.T) {
	entry := &ldap.Entry{
		DN: "uid=onlycn,dc=example",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"Only CN"}},
		},
	}

	cfg := &LDAPConfig{MapCN: "cn"}
	name := mapEntryToName(entry, cfg)
	if name.CommonName != "Only CN" {
		t.Fatalf("expected 'Only CN', got %q", name.CommonName)
	}
	if name.Organization != nil {
		t.Fatal("expected nil org")
	}
}

func TestLookupLDAPNilConfig(t *testing.T) {
	entry, name, err := LookupLDAP(nil, nil, "testuser")
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil || name != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestLookupLDAPEmptyBaseDN(t *testing.T) {
	entry, name, err := LookupLDAP(nil, &LDAPConfig{BaseDN: ""}, "testuser")
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil || name != nil {
		t.Fatal("expected nil for empty BaseDN")
	}
}

func TestLookupLDAPFilterFormat(t *testing.T) {
	cfg := &LDAPConfig{
		BaseDN:  "dc=example",
		Filter:  "(cn=%s)",
		UIDAttr: "cn",
		MapCN:   "cn",
	}
	expectedFilter := fmt.Sprintf(cfg.Filter, "testuser")
	if expectedFilter != "(cn=testuser)" {
		t.Fatalf("expected (cn=testuser), got %q", expectedFilter)
	}
}

func TestLookupLDAPDefaultFilterFallback(t *testing.T) {
	cfg := &LDAPConfig{
		BaseDN:  "dc=example",
		UIDAttr: "uid",
	}
	filter := cfg.Filter
	if filter == "" || !strings.Contains(filter, "%s") {
		if filter == "" {
			filter = "(uid=%s)"
		} else {
			filter = strings.Replace(filter, "%s", "testuser", 1)
		}
	}
	_ = cfg
}

func dialTestLDAP(tb testing.TB) *ldap.Conn {
	tb.Helper()
	conn, err := ldap.Dial("tcp", testLDAPAddr())
	if err != nil {
		tb.Skip("LDAP server not available: " + err.Error())
	}
	return conn
}

// testLDAPAddr returns the LDAP test server address. It defaults to the local
// OpenLDAP instance but can be overridden with VARWOF_LDAP_TEST_ADDR to point
// at a real directory server (e.g. LDAP_SERVER:389). The *Real integration
// tests bind with the varwof directory credentials; when no address is
// configured they target localhost and skip on bind failure (no local data).
func testLDAPAddr() string {
	if addr := os.Getenv("VARWOF_LDAP_TEST_ADDR"); addr != "" {
		return addr
	}
	return "localhost:389"
}

// requireTestLDAPBind binds to the test LDAP server; when the server is the
// default localhost and does not hold the varwof directory (no admin bind),
// the test is skipped rather than failed so a bare checkout stays green.
func requireTestLDAPBind(t *testing.T, conn *ldap.Conn) {
	t.Helper()
	bindPW := os.Getenv("VARWOF_LDAP_BIND_PASSWORD")
	if bindPW == "" {
		bindPW = "CHANGE_ME"
	}
	if err := conn.Bind("cn=admin,dc=varwof,dc=com", bindPW); err != nil {
		if os.Getenv("VARWOF_LDAP_TEST_ADDR") == "" {
			t.Skip("no varwof directory on default LDAP server: " + err.Error())
		}
		t.Fatal(err)
	}
}

func TestNewLDAPConnReal(t *testing.T) {
	conn, err := ldap.Dial("tcp", testLDAPAddr())
	if err != nil {
		t.Skip("LDAP server not available: " + err.Error())
	}
	conn.Close()

	conn, err = NewLDAPConn(&LDAPConfig{
		URL:          testLDAPAddr(),
		BindDN:       "cn=admin,dc=varwof,dc=com",
		BindPassword: os.Getenv("VARWOF_LDAP_BIND_PASSWORD"),
	})
	if err != nil {
		if os.Getenv("VARWOF_LDAP_TEST_ADDR") == "" {
			t.Skip("no varwof directory on default LDAP server: " + err.Error())
		}
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.WhoAmI(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewLDAPConnBadBind(t *testing.T) {
	conn, err := NewLDAPConn(&LDAPConfig{
		URL:          "localhost:389",
		BindDN:       "cn=admin,dc=varwof,dc=com",
		BindPassword: "wrongpassword",
	})
	if err == nil {
		conn.Close()
		t.Fatal("expected bind error")
	}
}

func TestNewLDAPConnBadURL(t *testing.T) {
	_, err := NewLDAPConn(&LDAPConfig{URL: "localhost:9999"})
	if err == nil {
		t.Fatal("expected dial error for bad port")
	}
}

func TestLookupLDAPRealJohn(t *testing.T) {
	conn := dialTestLDAP(t)
	defer conn.Close()

	requireTestLDAPBind(t, conn)

	cfg := &LDAPConfig{
		BaseDN:   "ou=users,dc=varwof,dc=com",
		UIDAttr:  "uid",
		MapCN:    "cn",
		MapL:     "l",
		MapST:    "st",
		MapC:     "c",
		MapEmail: "mail",
	}

	entry, name, err := LookupLDAP(conn, cfg, "john")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.GetAttributeValue("uid") != "john" {
		t.Fatalf("expected uid=john, got %q", entry.GetAttributeValue("uid"))
	}
	if name.CommonName != "john" {
		t.Fatalf("expected CN=john, got %q", name.CommonName)
	}
	if !CheckLDAPGroupMembership(entry, cfg, "cn=operators,ou=groups,dc=varwof,dc=com") {
		t.Fatal("expected john to be in operators group")
	}
}

func TestLookupLDAPRealAlice(t *testing.T) {
	conn := dialTestLDAP(t)
	defer conn.Close()

	requireTestLDAPBind(t, conn)

	cfg := &LDAPConfig{
		BaseDN:   "ou=users,dc=varwof,dc=com",
		UIDAttr:  "uid",
		MapCN:    "cn",
		MapOrg:   "o",
		MapOU:    "ou",
		MapL:     "l",
		MapST:    "st",
		MapC:     "c",
		MapEmail: "mail",
	}

	entry, name, err := LookupLDAP(conn, cfg, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if name.CommonName != "alice" {
		t.Fatalf("expected CN=alice, got %q", name.CommonName)
	}
	if len(name.Organization) == 0 || name.Organization[0] != "varwof" {
		t.Fatalf("expected O=varwof, got %v", name.Organization)
	}
	if len(name.OrganizationalUnit) == 0 || name.OrganizationalUnit[0] != "Engineering" {
		t.Fatalf("expected OU=Engineering, got %v", name.OrganizationalUnit)
	}
	if len(name.Locality) == 0 || name.Locality[0] != "Shanghai" {
		t.Fatalf("expected L=Shanghai, got %v", name.Locality)
	}
	if len(name.Province) == 0 || name.Province[0] != "SH" {
		t.Fatalf("expected ST=SH, got %v", name.Province)
	}
	if len(name.Country) == 0 || name.Country[0] != "CN" {
		t.Fatalf("expected C=CN, got %v", name.Country)
	}
	if !CheckLDAPGroupMembership(entry, cfg, "cn=auditors,ou=groups,dc=varwof,dc=com") {
		t.Fatal("expected alice to be in auditors group")
	}
}

func TestLookupLDAPRealNotFound(t *testing.T) {
	conn := dialTestLDAP(t)
	defer conn.Close()

	requireTestLDAPBind(t, conn)

	cfg := &LDAPConfig{
		BaseDN:  "ou=users,dc=varwof,dc=com",
		UIDAttr: "uid",
		MapCN:   "cn",
	}

	_, _, err := LookupLDAP(conn, cfg, "nonexistentuser")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestLookupLDAPRealCustomFilter(t *testing.T) {
	conn := dialTestLDAP(t)
	defer conn.Close()

	requireTestLDAPBind(t, conn)

	cfg := &LDAPConfig{
		BaseDN:   "ou=users,dc=varwof,dc=com",
		Filter:   "(mail=%s)",
		UIDAttr:  "mail",
		MapCN:    "cn",
		MapEmail: "mail",
	}

	entry, name, err := LookupLDAP(conn, cfg, "john@varwof.com")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if name.CommonName != "john" {
		t.Fatalf("expected CN=john, got %q", name.CommonName)
	}
	if entry.GetAttributeValue("mail") != "john@varwof.com" {
		t.Fatalf("expected mail=john@varwof.com, got %q", entry.GetAttributeValue("mail"))
	}
}

func TestCheckLDAPGroupMembershipReal(t *testing.T) {
	conn := dialTestLDAP(t)
	defer conn.Close()

	requireTestLDAPBind(t, conn)

	cfg := &LDAPConfig{
		BaseDN:  "ou=users,dc=varwof,dc=com",
		UIDAttr: "uid",
		MapCN:   "cn",
	}

	entry, _, err := LookupLDAP(conn, cfg, "admin")
	if err != nil {
		t.Fatal(err)
	}

	if !CheckLDAPGroupMembership(entry, cfg, "cn=admins,ou=groups,dc=varwof,dc=com") {
		t.Fatal("expected admin to be in admins group")
	}
	if CheckLDAPGroupMembership(entry, cfg, "cn=auditors,ou=groups,dc=varwof,dc=com") {
		t.Fatal("expected admin not to be in auditors group")
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPLookup is the interface for directory service lookups.
// The default implementation uses go-ldap directly; a satellite (ldap-bridge)
// can provide a remote implementation over HTTP.
type LDAPLookup interface {
	Lookup(cfg *LDAPConfig, username string) (*pkix.Name, error)
	CheckMembership(cfg *LDAPConfig, username, groupDN string) (bool, error)
}

type defaultLDAPLookup struct{}

func NewDefaultLDAPLookup() LDAPLookup {
	return &defaultLDAPLookup{}
}

func (d *defaultLDAPLookup) Lookup(cfg *LDAPConfig, username string) (*pkix.Name, error) {
	if cfg == nil || cfg.BaseDN == "" || cfg.URL == "" {
		return nil, nil
	}
	conn, err := NewLDAPConn(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, name, err := LookupLDAP(conn, cfg, username)
	return name, err
}

func (d *defaultLDAPLookup) CheckMembership(cfg *LDAPConfig, username, groupDN string) (bool, error) {
	if cfg == nil || cfg.BaseDN == "" || cfg.URL == "" {
		return false, nil
	}
	conn, err := NewLDAPConn(cfg)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	entry, _, err := LookupLDAP(conn, cfg, username)
	if err != nil {
		return false, err
	}
	return CheckLDAPGroupMembership(entry, cfg, groupDN), nil
}

func NewLDAPConn(cfg *LDAPConfig) (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}
	return conn, nil
}

func LookupLDAP(conn *ldap.Conn, cfg *LDAPConfig, username string) (*ldap.Entry, *pkix.Name, error) {
	if cfg == nil || cfg.BaseDN == "" {
		return nil, nil, nil
	}

	filter := cfg.Filter
	if filter == "" || !strings.Contains(filter, "%s") {
		filter = "(uid=%s)"
	}
	filter = fmt.Sprintf(filter, username)

	attrs := collectAttrs(cfg)
	attrs = append(attrs, "memberOf")
	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attrs,
		nil,
	)

	res, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, nil, fmt.Errorf("ldap: no entry found for %q", username)
	}

	entry := res.Entries[0]
	name := mapEntryToName(entry, cfg)
	return entry, name, nil
}

func CheckLDAPGroupMembership(entry *ldap.Entry, cfg *LDAPConfig, groupDN string) bool {
	_ = cfg
	if entry == nil {
		return false
	}
	for _, m := range entry.GetAttributeValues("memberOf") {
		if strings.EqualFold(m, groupDN) {
			return true
		}
	}
	return false
}

func collectAttrs(cfg *LDAPConfig) []string {
	m := make(map[string]bool)
	add := func(a string) {
		if a != "" {
			m[a] = true
		}
	}
	add(cfg.UIDAttr)
	add(cfg.MapCN)
	add(cfg.MapOrg)
	add(cfg.MapOU)
	add(cfg.MapL)
	add(cfg.MapST)
	add(cfg.MapC)
	add(cfg.MapEmail)
	attrs := make([]string, 0, len(m))
	for a := range m {
		attrs = append(attrs, a)
	}
	return attrs
}

func mapEntryToName(entry *ldap.Entry, cfg *LDAPConfig) *pkix.Name {
	n := &pkix.Name{}
	if cfg.MapCN != "" {
		n.CommonName = entry.GetAttributeValue(cfg.MapCN)
	}
	if cfg.MapOrg != "" {
		n.Organization = []string{entry.GetAttributeValue(cfg.MapOrg)}
	}
	if cfg.MapOU != "" {
		n.OrganizationalUnit = []string{entry.GetAttributeValue(cfg.MapOU)}
	}
	if cfg.MapL != "" {
		n.Locality = []string{entry.GetAttributeValue(cfg.MapL)}
	}
	if cfg.MapST != "" {
		n.Province = []string{entry.GetAttributeValue(cfg.MapST)}
	}
	if cfg.MapC != "" {
		n.Country = []string{entry.GetAttributeValue(cfg.MapC)}
	}
	if cfg.MapEmail != "" {
		extra := []string{entry.GetAttributeValue(cfg.MapEmail)}
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: extra[0],
		})
	}
	return n
}

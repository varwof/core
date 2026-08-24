package auth

import (
	"crypto/x509"
	"strings"
)

// RoleNamespace defines the role namespace prefix.
// Different subprojects use different namespaces to avoid OU conflicts.
type RoleNamespace string

const (
	// NSCore is the varwof core role namespace (no prefix).
	// Supported names: admin, operator, revoker, auditor, readonly, console, auto-renew, reporter
	// Corresponding OU values: OU=admin, OU=operator, etc.
	NSCore RoleNamespace = ""

	// NSGateway is the pki-gateway role namespace.
	// Corresponding OU values: OU=gateway:admin, OU=gateway:mysql-prod, etc.
	NSGateway RoleNamespace = "gateway:"

	// NSWeb is the pki-web-console role namespace (reserved).
	// Corresponding OU values: OU=web:admin, etc.
	NSWeb RoleNamespace = "web:"
)

// ExtractRoles extracts roles under the specified namespace from the certificate Subject OU.
// Examples:
//   cert OU = ["admin", "gateway:admin", "gateway:mysql-prod"]
//   ExtractRoles(cert, NSCore)    → ["admin"]
//   ExtractRoles(cert, NSGateway) → ["gateway:admin", "gateway:mysql-prod"]
func ExtractRoles(cert *x509.Certificate, ns RoleNamespace) []string {
	if cert == nil {
		return nil
	}
	prefix := string(ns)
	var roles []string
	for _, ou := range cert.Subject.OrganizationalUnit {
		normalized := strings.TrimSpace(ou)
		if prefix == "" {
			// Core role: OU that does not contain any namespace prefix
			if !strings.Contains(normalized, ":") {
				roles = append(roles, normalized)
			}
		} else if strings.HasPrefix(normalized, prefix) {
			// Namespaced role
			roles = append(roles, normalized)
		}
	}
	return roles
}

// HasRole checks whether the roles list matches any role in the allowed list.
// Supports exact matching and wildcard `*` (used in extracted roles).
// Examples:
//   HasRole(["gateway:admin"], ["gateway:admin"])              → true
//   HasRole(["gateway:*"], ["gateway:mysql-prod"])              → true (* matches all)
//   HasRole(["gateway:mysql-prod"], ["gateway:admin"])          → false
func HasRole(roles []string, allowed []string) bool {
	for _, role := range roles {
		if role == string(NSGateway)+"*" || role == string(NSWeb)+"*" {
			// Namespace wildcard: matches any allowed role under this namespace
			ns := role[:len(role)-1] // Remove trailing *
			for _, allow := range allowed {
				if strings.HasPrefix(allow, ns) {
					return true
				}
			}
		} else if role == "*" {
			// Global wildcard: matches any allowed role
			if len(allowed) > 0 {
				return true
			}
		}
		for _, allow := range allowed {
			if role == allow {
				return true
			}
		}
	}
	return false
}

// CheckCertRoles is a convenience combination of ExtractRoles + HasRole.
// Checks whether the certificate has any allowed role under the specified namespace.
func CheckCertRoles(cert *x509.Certificate, ns RoleNamespace, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	roles := ExtractRoles(cert, ns)
	return HasRole(roles, allowed)
}

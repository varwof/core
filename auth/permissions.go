// Package auth defines the unified permission model for the Varwof PKI ecosystem.
//
// All sub-projects (varwof-core, pki-gateway, pki-web-console, etc.) share this package,
// ensuring a single source of truth for permission definitions and avoiding
// duplicated implementations across projects.
//
// Usage:
//   - Permission check: auth.HasPerm(role, auth.PermCertIssue)
//   - Certificate role extraction: auth.ExtractRoles(cert, auth.NSGateway)
//   - Role matching: auth.HasRole(extracted, allowed)
//
// Namespaces:
//   - Varwof core roles (no prefix): superadmin, admin, operator, revoker, auditor, readonly, console, auto-renew, reporter
//   - Gateway roles (gateway:): gateway:admin, gateway:mysql-prod
//   - Web Console roles (web:): web:admin (reserved)
package auth

// Permission defines a single permission string.
// Format: <resource>:<action>
type Permission string

const (
	PermCACreate  Permission = "ca:create"
	PermCADelete  Permission = "ca:delete"
	PermCAList    Permission = "ca:list"
	PermCAInfo    Permission = "ca:info"

	PermCertIssue  Permission = "cert:issue"
	PermCertRevoke Permission = "cert:revoke"
	PermCertRenew  Permission = "cert:renew"
	PermCertList   Permission = "cert:list"
	PermCertExport Permission = "cert:export"
	PermCertBatch  Permission = "cert:batch"

	PermCRLGenerate Permission = "crl:generate"

	PermUserManage Permission = "user:manage"
	PermUserList   Permission = "user:list"

	PermLogRead   Permission = "log:read"
	PermLogExport Permission = "log:export"

	PermReportView     Permission = "report:view"
	PermReportExport   Permission = "report:export"
	PermReportGenerate Permission = "report:generate"

	PermConfigRead  Permission = "config:read"
	PermConfigWrite Permission = "config:write"

	PermRAApprove  Permission = "ra:approve"
	PermRAReject   Permission = "ra:reject"

	PermCrossIssue  Permission = "cross-cert:issue"
	PermCrossRevoke Permission = "cross-cert:revoke"

	PermWebhookManage Permission = "webhook:manage"

	PermKeyRecover Permission = "key:recover"

	PermDNSManage Permission = "dns:manage"

	PermTrustImport Permission = "trust:import"
	PermTrustList   Permission = "trust:list"
	PermTrustDelete Permission = "trust:delete"

	PermAgentManage   Permission = "agent:manage"
	PermUserRevokeAll Permission = "user:revoke-all"

	PermSwaggerView Permission = "swagger:view"
	PermWebView     Permission = "web:view"
)

// RolePermissions is the single source of truth for varwof core role → permission mappings.
// Currently 9 roles: superadmin, admin, operator, revoker, auditor, readonly, console, auto-renew, reporter
// When adding new roles or permissions, RoleNames and tests must be updated accordingly.
var RolePermissions = map[string][]Permission{
	"superadmin": {
		PermCACreate, PermCADelete,
		PermCAList, PermCAInfo,
		PermCertIssue, PermCertRevoke, PermCertRenew, PermCertList, PermCertExport, PermCertBatch,
		PermCRLGenerate,
		PermUserManage, PermUserList, PermUserRevokeAll,
		PermLogRead, PermLogExport,
		PermConfigRead, PermConfigWrite,
		PermReportView, PermReportExport, PermReportGenerate,
		PermRAApprove, PermRAReject,
		PermCrossIssue, PermCrossRevoke,
		PermWebhookManage,
		PermKeyRecover,
		PermDNSManage,
		PermTrustImport, PermTrustList, PermTrustDelete,
		PermAgentManage,
		PermSwaggerView, PermWebView,
	},
	"admin": {
		PermCAList, PermCAInfo,
		PermCertIssue, PermCertRevoke, PermCertRenew, PermCertList, PermCertExport, PermCertBatch,
		PermCRLGenerate,
		PermLogRead, PermLogExport,
		PermReportView, PermReportExport, PermReportGenerate,
		PermRAApprove, PermRAReject,
		PermCrossIssue, PermCrossRevoke,
		PermWebhookManage,
		PermKeyRecover,
		PermDNSManage,
		PermTrustImport, PermTrustList, PermTrustDelete,
		PermAgentManage,
		PermSwaggerView, PermWebView,
	},
	"operator": {
		PermCAList, PermCAInfo,
		PermCertIssue, PermCertRevoke, PermCertRenew, PermCertList, PermCertExport, PermCertBatch,
		PermCRLGenerate,
		PermLogRead, PermLogExport,
		PermReportView, PermReportExport, PermReportGenerate,
		PermRAApprove, PermRAReject,
		PermCrossIssue, PermCrossRevoke,
		PermWebhookManage,
		PermKeyRecover,
		PermDNSManage,
		PermTrustImport, PermTrustList, PermTrustDelete,
		PermAgentManage,
		PermSwaggerView, PermWebView,
	},
	"revoker": {
		PermCAList, PermCAInfo,
		PermCertList, PermCertRevoke,
		PermLogRead,
		PermReportView,
		PermWebView,
	},
	"auditor": {
		PermCAList, PermCAInfo,
		PermCertList,
		PermLogRead, PermLogExport,
		PermReportView, PermReportExport,
		PermSwaggerView, PermWebView,
	},
	"readonly": {
		PermCAList, PermCAInfo,
		PermCertList,
		PermSwaggerView, PermWebView,
	},
	"console": {
		PermCAList, PermCAInfo,
		PermCertIssue, PermCertRevoke, PermCertRenew, PermCertList, PermCertExport,
		PermCRLGenerate,
		PermLogRead,
		PermReportView, PermReportGenerate,
		PermRAApprove, PermRAReject,
		PermTrustList,
		PermWebView, PermSwaggerView,
	},
	"auto-renew": {
		PermCAList, PermCAInfo,
		PermCertList, PermCertRenew, PermCertExport,
		PermLogRead,
		PermWebView,
	},
	"reporter": {
		PermCAList, PermCAInfo,
		PermCertList,
		PermLogRead,
		PermReportView, PermReportExport, PermReportGenerate,
		PermWebView,
	},
}

// RoleNames returns all defined varwof core role names.
func RoleNames() []string {
	if p := GetPolicy(); p != nil {
		var names []string
		for name := range p.Roles {
			names = append(names, name)
		}
		return names
	}
	var names []string
	for r := range RolePermissions {
		names = append(names, r)
	}
	return names
}

// HasPerm checks whether a role has the specified permission. Returns false if the role does not exist.
// Prefers Policy (authz.json); falls back to the hardcoded RolePermissions when no Policy is loaded.
func HasPerm(role string, perm Permission) bool {
	if p := GetPolicy(); p != nil {
		return p.HasGrant(role, string(perm))
	}
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

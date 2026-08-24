// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package serve — Permission matrix (re-exported from the auth package)
//
// The single source of truth is now located at github.com/varwof/core/auth.
// This file provides convenience re-exports for the internal/serve package only;
// new code should import "github.com/varwof/core/auth" directly.
//
// The content of both is kept in sync; tests cover both.

package serve

import "github.com/varwof/core/auth"

// Permission re-exports auth.Permission
type Permission = auth.Permission

// All 32 permission constants re-exported
const (
	PermCACreate = auth.PermCACreate
	PermCADelete = auth.PermCADelete
	PermCAList   = auth.PermCAList
	PermCAInfo   = auth.PermCAInfo

	PermCertIssue  = auth.PermCertIssue
	PermCertRevoke = auth.PermCertRevoke
	PermCertRenew  = auth.PermCertRenew
	PermCertList   = auth.PermCertList
	PermCertExport = auth.PermCertExport
	PermCertBatch  = auth.PermCertBatch

	PermCRLGenerate = auth.PermCRLGenerate

	PermUserManage = auth.PermUserManage
	PermUserList   = auth.PermUserList

	PermLogRead   = auth.PermLogRead
	PermLogExport = auth.PermLogExport

	PermReportView     = auth.PermReportView
	PermReportExport   = auth.PermReportExport
	PermReportGenerate = auth.PermReportGenerate

	PermConfigRead  = auth.PermConfigRead
	PermConfigWrite = auth.PermConfigWrite

	PermRAApprove = auth.PermRAApprove
	PermRAReject  = auth.PermRAReject

	PermCrossIssue  = auth.PermCrossIssue
	PermCrossRevoke = auth.PermCrossRevoke

	PermWebhookManage = auth.PermWebhookManage

	PermKeyRecover = auth.PermKeyRecover

	PermDNSManage = auth.PermDNSManage

	PermTrustImport = auth.PermTrustImport
	PermTrustList   = auth.PermTrustList
	PermTrustDelete = auth.PermTrustDelete

	PermAgentManage   = auth.PermAgentManage
	PermUserRevokeAll = auth.PermUserRevokeAll

	PermSwaggerView = auth.PermSwaggerView
	PermWebView     = auth.PermWebView
)

// RolePermissions re-exports auth.RolePermissions
var RolePermissions = auth.RolePermissions

// HasPerm re-exports auth.HasPerm
func HasPerm(role string, perm Permission) bool {
	return auth.HasPerm(role, perm)
}

// Roles re-exports auth.RoleNames
func Roles() []string {
	return auth.RoleNames()
}

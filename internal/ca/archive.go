// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/varwof/engine/db"
)

type ArchivePolicy struct {
	Enabled        bool     `json:"enabled"`
	RetentionDays  int      `json:"retention_days"` // archive certs after N days from expiry/revocation
	ExcludeCAs     []string `json:"exclude_cas,omitempty"`
	ArchiveExpired bool     `json:"archive_expired"`
	ArchiveRevoked bool     `json:"archive_revoked"`
}

type ArchiveResult struct {
	Archived     int `json:"archived"`
	ExpiredCount int `json:"expired_count"`
	RevokedCount int `json:"revoked_count"`
}

func ArchiveCerts(database *db.DB, policy *ArchivePolicy) (*ArchiveResult, error) {
	result := &ArchiveResult{}
	cutoff := time.Now().AddDate(0, 0, -policy.RetentionDays)

	if policy.ArchiveExpired {
		n, err := archiveExpiredCerts(database, cutoff, policy.ExcludeCAs)
		if err != nil {
			return nil, fmt.Errorf("archive expired: %w", err)
		}
		result.ExpiredCount = n
		result.Archived += n
	}

	if policy.ArchiveRevoked {
		n, err := archiveRevokedCerts(database, cutoff, policy.ExcludeCAs)
		if err != nil {
			return nil, fmt.Errorf("archive revoked: %w", err)
		}
		result.RevokedCount = n
		result.Archived += n
	}

	slog.Info("archive complete", "archived", result.Archived)
	return result, nil
}

func archiveExpiredCerts(database *db.DB, cutoff time.Time, excludeCAs []string) (int, error) {
	excludeClause := ""
	args := []any{cutoff.UTC().Format(time.RFC3339)}
	if len(excludeCAs) > 0 {
		excludeClause = " AND ca_name NOT IN ("
		for i, name := range excludeCAs {
			if i > 0 {
				excludeClause += ","
			}
			excludeClause += "?"
			args = append(args, name)
		}
		excludeClause += ")"
	}
	n, err := database.Exec(`
		INSERT OR IGNORE INTO cert_archive
			(serial_number, ca_name, status, subject, common_name,
			 not_before, not_after, revoked_at, revoke_reason, invalidity_date,
			 cert_der, fingerprint,
			 subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
			 archived_at)
		SELECT serial_number, ca_name, 'E', subject, common_name,
		       not_before, not_after, revoked_at, revoke_reason, invalidity_date,
		       cert_der, fingerprint,
		       subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
		       datetime('now')
		FROM certificates
		WHERE status = 'E' AND not_after < ?`+excludeClause, args...)
	if err != nil {
		return 0, err
	}
	affected, _ := n.RowsAffected()
	if affected > 0 {
		_, delErr := database.Exec(`
			DELETE FROM certificates
			WHERE status = 'E' AND not_after < ?`+excludeClause, args...)
		if delErr != nil {
			slog.Warn("archive: delete expired", "error", delErr)
		}
	}
	return int(affected), nil
}

func archiveRevokedCerts(database *db.DB, cutoff time.Time, excludeCAs []string) (int, error) {
	excludeClause := ""
	args := []any{cutoff.UTC().Format(time.RFC3339)}
	if len(excludeCAs) > 0 {
		excludeClause = " AND ca_name NOT IN ("
		for i, name := range excludeCAs {
			if i > 0 {
				excludeClause += ","
			}
			excludeClause += "?"
			args = append(args, name)
		}
		excludeClause += ")"
	}
	n, err := database.Exec(`
		INSERT OR IGNORE INTO cert_archive
			(serial_number, ca_name, status, subject, common_name,
			 not_before, not_after, revoked_at, revoke_reason, invalidity_date,
			 cert_der, fingerprint,
			 subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
			 archived_at)
		SELECT serial_number, ca_name, 'R', subject, common_name,
		       not_before, not_after, revoked_at, revoke_reason, invalidity_date,
		       cert_der, fingerprint,
		       subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
		       datetime('now')
		FROM certificates
		WHERE status = 'R' AND revoked_at < ?`+excludeClause, args...)
	if err != nil {
		return 0, err
	}
	affected, _ := n.RowsAffected()
	if affected > 0 {
		_, delErr := database.Exec(`
			DELETE FROM certificates
			WHERE status = 'R' AND revoked_at < ?`+excludeClause, args...)
		if delErr != nil {
			slog.Warn("archive: delete revoked", "error", delErr)
		}
	}
	return int(affected), nil
}

package ca

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"

	"github.com/varwof/engine/db"
)

// ErrNoAIC is returned when a certificate does not contain an AIC extension.
var ErrNoAIC = fmt.Errorf("certificate has no AIC extension")

// extractPrincipalUid parses the AIC extension from a DER-encoded certificate
// and returns the PrincipalUid in communication format.
func extractPrincipalUid(der []byte) (string, error) {
	return ExtractPrincipalUID(der)
}

// ExtractPrincipalUID parses the AIC PrincipalUid out of a certificate's DER.
// Returns ErrNoAIC when the cert carries no AIC or its PrincipalUid is empty.
func ExtractPrincipalUID(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse cert DER: %w", err)
	}
	aic, err := ParseAIC(cert)
	if err != nil {
		return "", fmt.Errorf("parse AIC: %w", err)
	}
	if aic == nil {
		return "", ErrNoAIC
	}
	uid := aic.PrincipalUid.String()
	if uid == ":" {
		return "", ErrNoAIC
	}
	return uid, nil
}

var RevokeReasons = map[string]int{
	"unspecified":             0,
	"keyCompromise":           1,
	"cACompromise":            2,
	"affiliationChanged":      3,
	"superseded":              4,
	"cessationOfOperation":    5,
	"certificateHold":         6,
}

func ParseRevokeReason(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if reason, ok := RevokeReasons[s]; ok {
		return reason, nil
	}
	return 0, fmt.Errorf("unknown revoke reason: %s", s)
}

func NormalizeSerial(serial string) (string, error) {
	serial = strings.TrimPrefix(serial, "0x")
	serial = strings.TrimPrefix(serial, "0X")

	bigN := new(big.Int)
	if _, ok := bigN.SetString(serial, 16); !ok {
		return "", fmt.Errorf("invalid serial number (not hex): %s", serial)
	}

	return fmt.Sprintf("%040X", bigN), nil
}

func Revoke(d *db.DB, caName, serial string, reason int) error {
	normalized, err := NormalizeSerial(serial)
	if err != nil {
		return err
	}
	return d.RevokeCert(caName, normalized, reason)
}

// RevokeByPrincipalUid revokes all valid certificates matching the given
// PrincipalUid. Uses SQL-based filter (fast path) when the principal_uid
// column is populated, falls back to DER scan for legacy data.
func RevokeByPrincipalUid(d *db.DB, principalUid string, reason int) (int, error) {
	// Fast path: use SQL when principal_uid column is populated
	count, err := d.RevokeCertsByPrincipalUid(principalUid, reason)
	if err != nil {
		return 0, err
	}
	if count > 0 {
		return count, nil
	}

	// Fallback: scan DER for certs that may not have principal_uid column populated
	refs, err := d.ListAllValidCertRefs()
	if err != nil {
		return 0, fmt.Errorf("list valid certs: %w", err)
	}
	var lastErr error
	for _, ref := range refs {
		uid, err := extractPrincipalUid(ref.CertDER)
		if err != nil {
			if err == ErrNoAIC {
				continue
			}
			lastErr = fmt.Errorf("extract uid for %s/%s: %w", ref.CAName, ref.SerialNumber, err)
			continue
		}
		if uid != principalUid {
			continue
		}
		if err := d.RevokeCert(ref.CAName, ref.SerialNumber, reason); err != nil {
			lastErr = err
			continue
		}
		count++
	}
	if count == 0 && lastErr != nil {
		return 0, lastErr
	}
	return count, nil
}

// RevokeWithCascade revokes a certificate and cascade-revokes all agent
// certificates with the same PrincipalUid.
func RevokeWithCascade(d *db.DB, caName, serial string, reason int) (int, error) {
	normalized, err := NormalizeSerial(serial)
	if err != nil {
		return 0, fmt.Errorf("normalize serial: %w", err)
	}

	// Look up principal_uid from DB first (fast path), fallback to DER scan
	rec, lookupErr := d.GetCert(caName, normalized)
	var principalUid string
	if lookupErr == nil && rec.PrincipalUid != "" {
		principalUid = rec.PrincipalUid
	} else if lookupErr == nil {
		// Fallback: parse DER
		if uid, extractErr := extractPrincipalUid(rec.CertDER); extractErr == nil {
			principalUid = uid
		}
	}

	if err := Revoke(d, caName, serial, reason); err != nil {
		return 0, err
	}

	if principalUid == "" {
		return 0, nil // no AIC on revoked cert, no cascade
	}

	cascaded, err := RevokeByPrincipalUid(d, principalUid, reason)
	if err != nil {
		return 0, err
	}
	return cascaded, nil
}

// RevokeBySubCA revokes all valid certificates under a given CA (sub-CA name).
// Returns the number of revoked certs.
func RevokeBySubCA(d *db.DB, caName string, reason int) (int, error) {
	return d.RevokeCertsBySubCA(caName, reason)
}

// BackfillAICFields scans all valid agent-proxy certificates that lack
// principal_uid/agent_id and backfills them from the AIC extension in cert_der.
// Idempotent — safe to call on every startup.
func BackfillAICFields(d *db.DB) error {
	rows, err := d.ListCertsNeedingAICBackfill()
	if err != nil {
		return fmt.Errorf("list certs for aic backfill: %w", err)
	}
	for _, r := range rows {
		pu, aid, extractErr := extractAICFields(r.CertDER)
		if extractErr != nil {
			continue
		}
		if pu == "" && aid == "" {
			continue
		}
		if err := d.BackfillAICFieldsFromDer(r.CAName, r.Serial, pu, aid); err != nil {
			return fmt.Errorf("backfill aic fields for %s/%s: %w", r.CAName, r.Serial, err)
		}
	}
	return nil
}

// extractAICFields parses a DER certificate and returns PrincipalUid + AgentId.
func extractAICFields(der []byte) (principalUid, agentId string, err error) {
	cert, parseErr := x509.ParseCertificate(der)
	if parseErr != nil {
		return "", "", parseErr
	}
	aic, aicErr := ParseAIC(cert)
	if aicErr != nil || aic == nil {
		return "", "", fmt.Errorf("no AIC extension")
	}
	pu := aic.PrincipalUid.String()
	if pu == ":" {
		pu = ""
	}
	return pu, aic.AgentId, nil
}

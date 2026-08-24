// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
)

var crlNumber atomic.Int64 // monotonic CRL number across GenerateCRL calls

// CRLNumberStore persists the last used CRL number per CA so the counter can
// be re-seeded at startup, preserving RFC 5280 §5.2.4 monotonicity across
// restarts (H12 fix). When set on CRLConfig, generateCRL raises the in-memory
// counter to the persisted value before incrementing and records the new number
// after each successful generation.
type CRLNumberStore interface {
	GetLastCRLNumber(caName string) (int64, error)
	SetLastCRLNumber(caName string, number int64) error
}

// SeedCRLNumber sets the CRL number counter to at least n.
// Call this at startup with the last known CRL number (from DB or parsed CRL file)
// to prevent RFC 5280 monotonicity violation across restarts.
func SeedCRLNumber(n int64) {
	for {
		old := crlNumber.Load()
		if old >= n {
			return
		}
		if crlNumber.CompareAndSwap(old, n) {
			return
		}
	}
}

func SanitizeCAName(name string) string {
	// M13 fix: normalize any character unsafe for a CRL filename (spaces plus
	// path/shell/metacharacters) to '-', not just spaces. Lowercased for
	// filesystem consistency.
	replacer := strings.NewReplacer(
		" ", "-",
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
		"\x00", "-",
	)
	return replacer.Replace(strings.ToLower(name))
}

// RevokedEntriesSource supplies the revoked-certificate entries a CRL is
// built from. Both *db.DB and *engine.Engine satisfy it; when the resident
// memory engine is enabled CRL generation should prefer it (memory-authoritative
// reads, zero SQL, immediate visibility of revocations), falling back to the
// DB when the engine is not configured.
type RevokedEntriesSource interface {
	GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)
}

// RevokedEntriesSinceSource is implemented by sources that support Delta CRL
// queries (revoked at/after a base thisUpdate). Both *db.DB and *engine.Engine
// satisfy it.
type RevokedEntriesSinceSource interface {
	GetRevokedCertEntriesSince(caName string, since time.Time) ([]*db.RevokedCertEntry, error)
}

type CRLConfig struct {
	DB              *db.DB
	CACert          *x509.Certificate
	CAKey           crypto.Signer
	CAName          string
	ValidityDays    int
	ThisUpdate      time.Time
	LastThisUpdate  time.Time // previous thisUpdate to guarantee monotonicity against clock rollback
	LastCRLNumber   *big.Int  // cRLNumber of the base CRL (for Delta CRL's Base CRL Number extension)
	Partition       int       // 0-based partition index. -1 means all (generate full CRL)
	TotalPartitions int       // total partition count. 0 or 1 = no partitioning

	// RevokedEntriesSource overrides the revoked-entries read path. When nil
	// (CLI/init-full) the DB is used directly. When set (serve layer with the
	// memory engine enabled) the engine is authoritative; revoked cross-cert
	// entries are always read from the DB as the engine does not index them.
	RevokedEntriesSource RevokedEntriesSource

	// NumberStore persists the last CRL number per CA (H12 fix). When nil the
	// in-memory counter is used and monotonicity is only guaranteed within a
	// single process lifetime.
	NumberStore CRLNumberStore
}

func CRLFilename(caName string, partition, total int) string {
	name := SanitizeCAName(caName)
	if total <= 1 {
		return name + ".crl"
	}
	return fmt.Sprintf("%s-p%d-of%d.crl", name, partition, total)
}

func partitionOfSerial(serial string, total int) int {
	if total <= 1 {
		return 0
	}
	h := sha256.Sum256([]byte(serial))
	return int(binary.LittleEndian.Uint32(h[:4]) % uint32(total))
}

func GenerateCRL(cfg *CRLConfig) ([]byte, error) {
	return generateCRL(cfg, nil)
}

// DeltaCRLConfig carries Delta CRL parameters.
type DeltaCRLConfig struct {
	// Since is the base CRL thisUpdate; only certificates revoked at or after
	// this time are included in the delta.
	Since time.Time
	// BaseCRLNumber is the cRLNumber of the base CRL the delta applies to
	// (encoded in the Base CRL Number extension, 2.5.29.31).
	BaseCRLNumber *big.Int
}

// GenerateDeltaCRL builds a Delta CRL (RFC 5280 §5.2.4) covering only the
// certificates revoked since the base CRL thisUpdate. It carries the Delta
// CRL Indicator (2.5.29.27) and Base CRL Number (2.5.29.31) extensions, which
// let clients merge the delta with the base CRL.
//
// The source must implement RevokedEntriesSinceSource (both *db.DB and
// *engine.Engine do). When the configured source does not, a full-CRL query is
// used and entries are filtered in memory.
func GenerateDeltaCRL(cfg *CRLConfig, dcfg *DeltaCRLConfig) ([]byte, error) {
	if dcfg == nil || dcfg.Since.IsZero() {
		return nil, fmt.Errorf("generate delta CRL: missing base thisUpdate")
	}
	return generateCRL(cfg, dcfg)
}

func generateCRL(cfg *CRLConfig, dcfg *DeltaCRLConfig) ([]byte, error) {
	caName := cfg.CAName
	if caName == "" {
		caName = cfg.CACert.Subject.CommonName
	}
	revSrc := RevokedEntriesSource(cfg.DB)
	if cfg.RevokedEntriesSource != nil {
		revSrc = cfg.RevokedEntriesSource
	}
	var revoked []*db.RevokedCertEntry
	var err error
	if dcfg != nil {
		if src, ok := revSrc.(RevokedEntriesSinceSource); ok {
			revoked, err = src.GetRevokedCertEntriesSince(caName, dcfg.Since)
		} else {
			all, allErr := revSrc.GetRevokedCertEntries(caName)
			if allErr != nil {
				return nil, fmt.Errorf("get revoked certs: %w", allErr)
			}
			for _, r := range all {
				if r.RevokedAt != nil && !r.RevokedAt.Before(dcfg.Since) {
					revoked = append(revoked, r)
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("get revoked certs since: %w", err)
		}
	} else {
		revoked, err = revSrc.GetRevokedCertEntries(caName)
		if err != nil {
			return nil, fmt.Errorf("get revoked certs: %w", err)
		}
	}

	// Include revoked cross-certificates issued by this CA. Cross certs are not
	// indexed by the in-memory engine, so this stays DB-backed; in engine-only
	// mode (cfg.DB == nil) they are skipped with a warning rather than panic.
	var crossRevoked []*db.CertRecord
	if cfg.DB != nil {
		crossRevoked, err = cfg.DB.GetRevokedCrossCerts(caName)
		if err != nil {
			return nil, fmt.Errorf("get revoked cross certs: %w", err)
		}
	} else {
		slog.Warn("ca/crl: cfg.DB is nil — revoked cross-certs are not indexed by the engine and are skipped",
			"ca", caName)
	}
	for _, cr := range crossRevoked {
		if dcfg != nil {
			if cr.RevokedAt == nil || cr.RevokedAt.Before(dcfg.Since) {
				continue
			}
		}
		revoked = append(revoked, &db.RevokedCertEntry{
			SerialNumber: cr.SerialNumber,
			RevokedAt:    cr.RevokedAt,
			RevokeReason: cr.RevokeReason,
		})
	}

	total := cfg.TotalPartitions
	if total <= 1 {
		total = 1
	}

	if cfg.Partition >= 0 && total > 1 {
		var filtered []*db.RevokedCertEntry
		for _, r := range revoked {
			if partitionOfSerial(r.SerialNumber, total) == cfg.Partition {
				filtered = append(filtered, r)
			}
		}
		revoked = filtered
	}

	now := cfg.ThisUpdate
	if now.IsZero() {
		now = time.Now().UTC().Round(time.Second)
		if !cfg.LastThisUpdate.IsZero() && now.Before(cfg.LastThisUpdate) {
			now = cfg.LastThisUpdate.Add(time.Second)
		}
	}
	nextUpdate := now.AddDate(0, 0, cfg.ValidityDays)
	if cfg.ValidityDays <= 0 {
		nextUpdate = now.AddDate(0, 0, 30)
	}

	crlNum := crlNumber.Add(1)

	// H12 fix: persist the CRL number after each successful generation so a
	// restart can re-seed the counter. Errors are non-fatal (a loss of
	// persistence only degrades to pre-fix behavior, it does not corrupt the
	// CRL being returned).
	if cfg.NumberStore != nil && cfg.CAName != "" {
		if err := cfg.NumberStore.SetLastCRLNumber(cfg.CAName, crlNum); err != nil {
			slog.Warn("crl: failed to persist CRL number", "ca", cfg.CAName, "number", crlNum, "error", err)
		}
	}

	rl := &x509.RevocationList{
		RevokedCertificateEntries: convertRevokedEntries(revoked),
		Number:                    big.NewInt(crlNum),
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
	}

	if dcfg != nil {
		// Delta CRL Indicator (2.5.29.27): value is an INTEGER (the CRL number
		// of the CRL type, conventionally 1 for deltas). Critical per RFC 5280.
		deltaIndicator, err := asn1.Marshal(big.NewInt(1))
		if err != nil {
			return nil, fmt.Errorf("marshal delta CRL indicator: %w", err)
		}
		rl.ExtraExtensions = append(rl.ExtraExtensions, pkix.Extension{
			Id:       oidDeltaCRLIndicator,
			Critical: true,
			Value:    deltaIndicator,
		})

		// Base CRL Number (2.5.29.31): the cRLNumber of the base CRL.
		base, err := asn1.Marshal(dcfg.BaseCRLNumber)
		if err != nil {
			return nil, fmt.Errorf("marshal base CRL number: %w", err)
		}
		rl.ExtraExtensions = append(rl.ExtraExtensions, pkix.Extension{
			Id:    oidBaseCRLNumber,
			Value: base,
		})
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, rl, cfg.CACert, cfg.CAKey)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}

	return crlDER, nil
}

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidBaseCRLNumber     = asn1.ObjectIdentifier{2, 5, 29, 31}
)

var oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}

func convertRevokedEntries(revoked []*db.RevokedCertEntry) []x509.RevocationListEntry {
	var entries []x509.RevocationListEntry
	for _, r := range revoked {
		serial := new(big.Int)
		if _, ok := serial.SetString(r.SerialNumber, 16); !ok {
			slog.Warn("crl: skipping entry with unparseable serial number", "serial", r.SerialNumber)
			continue
		}
		revTime := time.Now()
		if r.RevokedAt != nil {
			revTime = *r.RevokedAt
		}
		reason := 0
		if r.RevokeReason != nil {
			reason = *r.RevokeReason
		}
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revTime,
			ReasonCode:     reason,
		}
		if r.InvalidityDate != nil {
			ivalDER, err := asn1.Marshal(r.InvalidityDate.UTC())
			if err == nil {
				entry.Extensions = append(entry.Extensions, pkix.Extension{
					Id:       oidInvalidityDate,
					Critical: false,
					Value:    ivalDER,
				})
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

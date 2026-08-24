package ca

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/varwof/engine/db"
)

type AutoRenewPolicy struct {
	Enabled        bool          `json:"enabled"`
	Interval       time.Duration `json:"interval"`
	WindowDays     int           `json:"window_days"`
	DefaultValidity int          `json:"default_validity_days"`
	Profiles       []string      `json:"profiles,omitempty"`     // only auto-renew these profiles (empty = all)
	ExcludeCAs     []string      `json:"exclude_cas,omitempty"`  // skip these CAs
	NotifyOnly     bool          `json:"notify_only"`            // dry-run: notify but don't renew
	MaxRenewals    int           `json:"max_renewals"`           // max per run (0 = unlimited)
}

type AutoRenewResult struct {
	Serial       string `json:"serial"`
	CAName       string `json:"ca_name"`
	CommonName   string `json:"common_name"`
	OldNotAfter  string `json:"old_not_after"`
	NewSerial    string `json:"new_serial,omitempty"`
	Action       string `json:"action"` // renewed, skipped, error, notify
	Error        string `json:"error,omitempty"`
}

type AutoRenewCallback func(caName, serial string, validityDays int) (newSerial string, err error)

func AutoRenew(database *db.DB, policy *AutoRenewPolicy, renewFn AutoRenewCallback, notifyFn func(event, caName, serial, cn, msg string)) []AutoRenewResult {
	var results []AutoRenewResult
	now := time.Now()
	threshold := time.Duration(policy.WindowDays) * 24 * time.Hour

	metas, err := database.ListCAMetas()
	if err != nil {
		slog.Error("autorenew: list CAs", "error", err)
		return nil
	}

	excludeSet := make(map[string]bool, len(policy.ExcludeCAs))
	for _, name := range policy.ExcludeCAs {
		excludeSet[name] = true
	}

	profileSet := make(map[string]bool, len(policy.Profiles))
	for _, p := range policy.Profiles {
		profileSet[p] = true
	}

	count := 0
	for _, m := range metas {
		if excludeSet[m.Name] {
			continue
		}
		certs, err := database.ListCertsFiltered(m.Name, "V", "")
		if err != nil {
			slog.Error("autorenew: list certs", "ca", m.Name, "error", err)
			continue
		}
		for _, c := range certs {
			if policy.MaxRenewals > 0 && count >= policy.MaxRenewals {
				break
			}
			remaining := c.NotAfter.Sub(now)
			if remaining > threshold || remaining < 0 {
				continue
			}
			if len(profileSet) > 0 && !profileSet[c.Profile] {
				continue
			}

			cn := c.CommonName
			if cn == "" {
				cn = c.Subject
			}

			r := AutoRenewResult{
				Serial:      c.SerialNumber,
				CAName:      c.CAName,
				CommonName:  cn,
				OldNotAfter: c.NotAfter.Format(time.RFC3339),
			}

			if policy.NotifyOnly {
				r.Action = "notify"
				if notifyFn != nil {
					notifyFn("cert_expiring", c.CAName, c.SerialNumber, cn,
						fmt.Sprintf("cert %s/%s expires %s (%d days)", c.CAName, c.SerialNumber, c.NotAfter.Format("2006-01-02"), int(remaining.Hours()/24)))
				}
				results = append(results, r)
				continue
			}

			newSerial, err := renewFn(c.CAName, c.SerialNumber, policy.DefaultValidity)
			if err != nil {
				r.Action = "error"
				r.Error = err.Error()
				slog.Warn("autorenew: failed", "ca", c.CAName, "serial", c.SerialNumber, "error", err)
			} else {
				r.Action = "renewed"
				r.NewSerial = newSerial
				slog.Info("autorenew: renewed", "ca", c.CAName, "old_serial", c.SerialNumber, "new_serial", newSerial, "cn", cn)
				if notifyFn != nil {
					notifyFn("cert_renewed", c.CAName, newSerial, cn,
						fmt.Sprintf("cert %s/%s auto-renewed → %s", c.CAName, c.SerialNumber, newSerial))
				}
			}
			results = append(results, r)
			count++
		}
	}
	return results
}

func IsAutoRenewable(certDER []byte, caCert *x509.Certificate) bool {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil || cert.IsCA {
		return false
	}
	if cert.NotAfter.Before(time.Now()) {
		return false
	}
	return true
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DashboardStats is the complete PKI statistics response.
type DashboardStats struct {
	Summary       SummaryStats   `json:"summary"`
	PerCA         []CAStats      `json:"per_ca,omitempty"`
	Expiry        ExpiryBuckets  `json:"expiry"`
	Trends        TrendStats     `json:"trends,omitempty"`
	KeyTypes      map[string]int `json:"key_types,omitempty"`
	Profiles      map[string]int `json:"profiles,omitempty"`
	NearestExpiry *NearestExpiry `json:"nearest_expiry,omitempty"`
	UpdatedAt     string         `json:"updated_at"`
}

type SummaryStats struct {
	TotalCerts   int     `json:"total_certs"`
	TotalCAs     int     `json:"total_cas"`
	Valid        int     `json:"valid"`
	Revoked      int     `json:"revoked"`
	Expired      int     `json:"expired"`
	Expiring30d  int     `json:"expiring_30d"`
	RevokedRatio float64 `json:"revoked_ratio"`
}

type CAStats struct {
	Name       string `json:"name"`
	Certs      int    `json:"certs"`
	Revoked    int    `json:"revoked"`
	Expiring30 int    `json:"expiring_30d"`
	Subject    string `json:"subject"`
	NotAfter   string `json:"not_after"`
	Algorithm  string `json:"algorithm"`
}

type ExpiryBuckets struct {
	Within30d  int `json:"within_30d"`
	Within60d  int `json:"within_60d"`
	Within90d  int `json:"within_90d"`
	Within180d int `json:"within_180d"`
	Within365d int `json:"within_365d"`
	Over365d   int `json:"over_365d"`
}

// NearestExpiry holds the certificate closest to expiration.
type NearestExpiry struct {
	CommonName   string `json:"common_name"`
	SerialNumber string `json:"serial_number"`
	CAName       string `json:"ca_name"`
	NotAfter     string `json:"not_after"`
	DaysLeft     int    `json:"days_left"`
}

type TrendStats struct {
	IssuedToday     int `json:"issued_today"`
	IssuedThisWeek  int `json:"issued_this_week"`
	IssuedThisMonth int `json:"issued_this_month"`
	RevokedToday    int `json:"revoked_today"`
}

// ---- New Dashboard API ----

// apiDashboard handles GET /api/v1/dashboard
func (s *Server) apiDashboard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.collectDashboard())
}

// apiDashboardSSE handles GET /api/v1/dashboard/events (SSE stream)
func (s *Server) apiDashboardSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		apiErrorJSON(w, http.StatusInternalServerError, "streaming not supported", "")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	send := func() {
		data, _ := json.Marshal(s.collectDashboard())
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
	send()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func (s *Server) collectDashboard() *DashboardStats {
	db := s.getDB()
	d := &DashboardStats{
		KeyTypes: make(map[string]int),
		Profiles: make(map[string]int),
	}

	db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&d.Summary.TotalCerts)
	db.QueryRow("SELECT COUNT(*) FROM ca_meta").Scan(&d.Summary.TotalCAs)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V'").Scan(&d.Summary.Valid)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='R'").Scan(&d.Summary.Revoked)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after < datetime('now')").Scan(&d.Summary.Expired)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now') AND datetime('now','+30 days')").Scan(&d.Summary.Expiring30d)
	if d.Summary.TotalCerts > 0 {
		d.Summary.RevokedRatio = float64(d.Summary.Revoked) / float64(d.Summary.TotalCerts)
	}

	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now') AND datetime('now','+30 days')").Scan(&d.Expiry.Within30d)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now','+31 days') AND datetime('now','+60 days')").Scan(&d.Expiry.Within60d)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now','+61 days') AND datetime('now','+90 days')").Scan(&d.Expiry.Within90d)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now','+91 days') AND datetime('now','+180 days')").Scan(&d.Expiry.Within180d)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after BETWEEN datetime('now','+181 days') AND datetime('now','+365 days')").Scan(&d.Expiry.Within365d)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='V' AND not_after > datetime('now','+365 days')").Scan(&d.Expiry.Over365d)

	today := time.Now().UTC().Format("2006-01-02")
	thisWeek := time.Now().AddDate(0, 0, -7).UTC().Format("2006-01-02")
	thisMonth := time.Now().AddDate(0, -1, 0).UTC().Format("2006-01-02")
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE substr(not_before,1,10)=?", today).Scan(&d.Trends.IssuedToday)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE substr(not_before,1,10)>=?", thisWeek).Scan(&d.Trends.IssuedThisWeek)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE substr(not_before,1,10)>=?", thisMonth).Scan(&d.Trends.IssuedThisMonth)
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='R' AND substr(revoked_at,1,10)=?", today).Scan(&d.Trends.RevokedToday)

	rows, err := db.Query("SELECT name, subject, not_after, key_algorithm FROM ca_meta ORDER BY name")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cs CAStats
			if rows.Scan(&cs.Name, &cs.Subject, &cs.NotAfter, &cs.Algorithm) == nil {
				count := 0
				db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name=?", cs.Name).Scan(&count)
				cs.Certs = count
				db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name=? AND status='R'", cs.Name).Scan(&cs.Revoked)
				db.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name=? AND status='V' AND not_after BETWEEN datetime('now') AND datetime('now','+30 days')", cs.Name).Scan(&cs.Expiring30)
				d.PerCA = append(d.PerCA, cs)
			}
		}
	}

	d.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	var neCN, neSerial, neCA, neNotAfter string
	err = db.QueryRow("SELECT common_name, serial_number, ca_name, not_after FROM certificates WHERE status='V' AND not_after > datetime('now') ORDER BY not_after ASC LIMIT 1").Scan(&neCN, &neSerial, &neCA, &neNotAfter)
	if err == nil && neCN != "" {
		neDate, _ := time.Parse("2006-01-02 15:04:05", neNotAfter)
		if neDate.IsZero() {
			neDate, _ = time.Parse("2006-01-02T15:04:05Z07:00", neNotAfter)
		}
		if neDate.IsZero() {
			neDate, _ = time.Parse("2006-01-02", neNotAfter)
		}
		daysLeft := int(time.Until(neDate).Hours() / 24)
		d.NearestExpiry = &NearestExpiry{
			CommonName:   neCN,
			SerialNumber: neSerial,
			CAName:       neCA,
			NotAfter:     neNotAfter,
			DaysLeft:     daysLeft,
		}
	}
	return d
}

// ---- Legacy Stats (backward compat) ----
type Stats struct {
	TotalCerts   int            `json:"total_certs"`
	ByStatus     map[string]int `json:"by_status"`
	Expiring30d  int            `json:"expiring_30d"`
	TotalCAs     int            `json:"total_cas"`
	RevokedRatio float64        `json:"revoked_ratio"`
	UpdatedAt    string         `json:"updated_at"`
}

// apiStats handles GET /api/v1/stats
func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.collectStats())
}

// apiStatsSSE handles GET /api/v1/stats/events (SSE stream)
func (s *Server) apiStatsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		apiErrorJSON(w, http.StatusInternalServerError, "streaming not supported", "")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	stats := s.collectStats()
	data, _ := json.Marshal(stats)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			stats := s.collectStats()
			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) collectStats() *Stats {
	st := &Stats{ByStatus: map[string]int{}}
	db := s.getDB()
	db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&st.TotalCerts)
	rows, err := db.Query("SELECT status, COUNT(*) FROM certificates GROUP BY status")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var status string
			var count int
			if rows.Scan(&status, &count) == nil {
				st.ByStatus[status] = count
			}
		}
	}
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN datetime('now') AND datetime('now','+30 days') AND status='V'").Scan(&st.Expiring30d)
	db.QueryRow("SELECT COUNT(*) FROM ca_meta").Scan(&st.TotalCAs)
	revoked := 0
	db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status='R'").Scan(&revoked)
	if st.TotalCerts > 0 {
		st.RevokedRatio = float64(revoked) / float64(st.TotalCerts)
	}
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return st
}

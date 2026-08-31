// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// latencyBuckets are Prometheus-style histogram bounds in milliseconds.
var latencyBuckets = []float64{
	0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
}

// Metrics collects per-run counters and a latency histogram.
type Metrics struct {
	mu        sync.Mutex
	start     time.Time
	Total     int64
	Success   int64
	ErrCodes  map[int]int64
	buckets   []int64
	overflows []float64 // latency samples (ms) above the last bucket
	maxLat    float64
}

func NewMetrics() *Metrics {
	return &Metrics{start: time.Now(), ErrCodes: map[int]int64{}, buckets: make([]int64, len(latencyBuckets))}
}

// Record appends one issued-request result. latency of statusCode==0 means a
// transport error (no HTTP response); ok=false.
func (m *Metrics) Record(lat time.Duration, statusCode int, ok bool) {
	ms := float64(lat.Nanoseconds()) / 1e6
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Total++
	if ok {
		m.Success++
	} else {
		m.ErrCodes[statusCode]++
	}
	if ms > m.maxLat {
		m.maxLat = ms
	}
	idx := bucketIndex(ms, latencyBuckets)
	if idx >= 0 {
		m.buckets[idx]++
	} else {
		m.overflows = append(m.overflows, ms)
	}
}

func bucketIndex(ms float64, buckets []float64) int {
	for i, b := range buckets {
		if ms <= b {
			return i
		}
	}
	return -1
}

// Snapshot computes percentile estimates from the histogram + overflow samples.
func (m *Metrics) Snapshot() Totals {
	m.mu.Lock()
	defer m.mu.Unlock()

	elapsed := time.Since(m.start)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}
	sorted := append([]float64(nil), m.overflows...)
	sort.Float64s(sorted)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	return Totals{
		Total:       m.Total,
		Success:     m.Success,
		Failed:      m.ErrOther(),
		ErrCodes:    m.copyErrCodes(),
		Elapsed:     elapsed,
		IssuedRate:  float64(m.Success) / elapsed.Seconds(),
		RequestRate: float64(m.Total) / elapsed.Seconds(),
		LatencyP50:  m.percentile(50, sorted),
		LatencyP95:  m.percentile(95, sorted),
		LatencyP99:  m.percentile(99, sorted),
		LatencyMax:  m.maxLat,
		MemAlloc:    mem.Alloc,
		MemTotal:    mem.TotalAlloc,
	}
}

func (m *Metrics) ErrOther() int64 {
	var n int64
	for _, v := range m.ErrCodes {
		n += v
	}
	return n
}

func (m *Metrics) copyErrCodes() map[int]int64 {
	out := make(map[int]int64, len(m.ErrCodes))
	for k, v := range m.ErrCodes {
		out[k] = v
	}
	return out
}

// percentile locates the rank-th latency start from the cumulative histogram,
// interpolating across bin width; ranks beyond the last bucket use the exact
// overflow samples.
func (m *Metrics) percentile(p float64, sorted []float64) float64 {
	if m.Total == 0 {
		return 0
	}
	rank := int64(math.Ceil(float64(m.Total) * p / 100))
	if rank < 1 {
		rank = 1
	}
	count := int64(0)
	for i, c := range m.buckets {
		if c == 0 {
			continue
		}
		if count+c >= rank {
			start := lo(i)
			width := hi(i) - lo(i)
			if width == math.Inf(1) {
				// inside last (open-ended) bucket; fall back to overflow samples
				break
			}
			return start + float64(rank-count-1)/float64(c)*width
		}
		count += c
	}
	// Beyond counted buckets (incl. overflow). rank is 1-indexed among totals.
	// overflow samples come after all counted bins.
	startOfOverflow := count + 1
	idx := int(rank - startOfOverflow) // 0-based
	if idx >= 0 && idx < len(sorted) {
		return sorted[idx]
	}
	return m.maxLat
}

func lo(i int) float64 {
	if i == 0 {
		return 0
	}
	return latencyBuckets[i-1]
}

func hi(i int) float64 {
	return latencyBuckets[i]
}

// Report is the final JSON-serializable result.
type Report struct {
	Mode      string `json:"mode"`
	Scenario  string `json:"scenario"`
	Duration  string `json:"duration"`
	Agents    int    `json:"agents"`
	Users     int    `json:"users"`
	TargetQPS int    `json:"target_qps"`
	Interval  string `json:"interval,omitempty"`
	Totals    Totals `json:"totals"`
}

// Totals carries the aggregated run metrics.
type Totals struct {
	Total       int64         `json:"total_requests"`
	Success     int64         `json:"success"`
	Failed      int64         `json:"failures"`
	ErrCodes    map[int]int64 `json:"error_codes,omitempty"`
	Elapsed     time.Duration `json:"elapsed"`
	IssuedRate  float64       `json:"issued_per_sec"`
	RequestRate float64       `json:"requests_per_sec"`
	LatencyP50  float64       `json:"latency_p50_ms"`
	LatencyP95  float64       `json:"latency_p95_ms"`
	LatencyP99  float64       `json:"latency_p99_ms"`
	LatencyMax  float64       `json:"latency_max_ms"`
	MemAlloc    uint64        `json:"mem_alloc_bytes"`
	MemTotal    uint64        `json:"mem_total_bytes"`
	DBSize      int64         `json:"db_size_bytes"`
	CertCount   int64         `json:"certificate_rows"`
}

// JSON serializes the report.
func (r *Report) JSON() string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}

// Text renders a compact human-readable summary.
func (r *Report) Text() string {
	t := r.Totals
	var sb strings.Builder
	sb.WriteString("\n══════════════════════════════════════════\n")
	sb.WriteString("  Benchmark Report\n")
	sb.WriteString("══════════════════════════════════════════\n")
	fmt.Fprintf(&sb, "  mode: %s  scenario: %s  duration: %s\n", r.Mode, r.Scenario, r.Duration)
	fmt.Fprintf(&sb, "  agents: %d  users: %d  target_qps: %d\n\n", r.Agents, r.Users, r.TargetQPS)
	fmt.Fprintf(&sb, "  total requests: %d   (%.0f req/s)\n", t.Total, t.RequestRate)
	fmt.Fprintf(&sb, "  success: %d        (%.0f certs/s)\n", t.Success, t.IssuedRate)
	fmt.Fprintf(&sb, "  failures: %d\n", t.Failed)
	if len(t.ErrCodes) > 0 {
		var codes []int
		for c := range t.ErrCodes {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Fprintf(&sb, "    HTTP %d: %d\n", c, t.ErrCodes[c])
		}
	}
	fmt.Fprintf(&sb, "  latency: p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms\n",
		t.LatencyP50, t.LatencyP95, t.LatencyP99, t.LatencyMax)
	fmt.Fprintf(&sb, "  elapsed: %s\n", t.Elapsed)
	fmt.Fprintf(&sb, "  memory: alloc=%.1fMB total=%.1fMB\n",
		float64(t.MemAlloc)/1048576, float64(t.MemTotal)/1048576)
	fmt.Fprintf(&sb, "  db: %d rows, %s on disk\n", t.CertCount, formatBytes(t.DBSize))
	fmt.Fprintf(&sb, "  error rate: %.2f%%\n", 100*float64(t.Failed)/math.Max(1, float64(t.Total)))
	sb.WriteString("══════════════════════════════════════════\n")
	return sb.String()
}

// formatBytes renders a byte count in human units.
func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

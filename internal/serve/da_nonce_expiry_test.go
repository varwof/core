// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"testing"
	"time"
)

// TestDANonceExpiry covers the retention-window logic: with the timestamp-skew
// defense enabled the nonce only needs to outlive skew + the 3-minute buffer
// (DA lifetime is irrelevant because a stale DA is rejected by the freshness
// check); with skew disabled it falls back to the DA lifetime, then to NonceTTL.
func TestDANonceExpiry(t *testing.T) {
	const skew = 30 * time.Second
	const ttl = 24 * time.Hour
	now := time.Now()

	tests := []struct {
		name       string
		ts         int64
		lifetime   int64
		skew       time.Duration
		ttl        time.Duration
		expWithin  time.Duration // upper bound on (exp - now)
		expMinimal bool          // expect the floor (now + buffer) when inputs are stale
	}{
		{
			name:      "skew enabled dominates lifetime",
			ts:        now.Unix(),
			lifetime:  3600,
			skew:      skew,
			ttl:       ttl,
			expWithin: skew + daNonceClockBuffer + time.Second,
		},
		{
			name:      "skew disabled falls back to lifetime",
			ts:        now.Unix(),
			lifetime:  300,
			skew:      0,
			ttl:       ttl,
			expWithin: 300*time.Second + daNonceClockBuffer + time.Second,
		},
		{
			name:      "no skew no lifetime falls back to ttl",
			ts:        now.Unix(),
			lifetime:  0,
			skew:      0,
			ttl:       ttl,
			expWithin: ttl + daNonceClockBuffer + time.Second,
		},
		{
			name:       "stale timestamp floored to now+buffer",
			ts:         now.Add(-24 * time.Hour).Unix(),
			lifetime:   3600,
			skew:       skew,
			ttl:        ttl,
			expMinimal: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := daNonceExpiry(tt.ts, tt.lifetime, tt.skew, tt.ttl)
			if tt.expMinimal {
				want := now.Add(daNonceClockBuffer)
				if exp.Before(want) {
					t.Fatalf("expiry %v before floor %v", exp, want)
				}
				return
			}
			d := exp.Sub(now)
			if d <= 0 || d > tt.expWithin {
				t.Fatalf("expiry %v (%v from now) outside expected window (0, %v]", exp, d, tt.expWithin)
			}
		})
	}
}

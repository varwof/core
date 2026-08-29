// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"testing"

	"github.com/varwof/core/internal"
)

func TestCmdAutoRenewOnce(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)
	cfg.Defaults = internal.DefaultsConfig{KeyType: "ecdsa-p256", Hash: "sha256", DefaultOrg: "ACME", DefaultCountry: "US"}

	issueTestCert(t, d, caCert, caKey, "rev-ca", "expiring.example.com")

	cfg.AutoRenew = internal.AutoRenewConfig{
		Enabled:         boolPtr(true),
		WindowDays:      100, // issueTestCert issues 90d validity
		DefaultValidity: 365,
	}

	if err := cmdAutoRenew(cfg, nil); err != nil {
		t.Fatalf("auto-renew once: %v", err)
	}

	cfg.AutoRenew.NotifyOnly = boolPtr(true)
	cfg.AutoRenew.WindowDays = 100
	if err := cmdAutoRenew(cfg, nil); err != nil {
		t.Fatalf("auto-renew notify-only: %v", err)
	}
}

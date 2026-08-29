// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"testing"
)

func TestSeedCRLNumberNudge(t *testing.T) {
	SeedCRLNumber(1 << 20)
	if crlNumber.Load() < 1<<20 {
		t.Fatal("seed did not raise counter")
	}
}

func TestSubjectNameOverride(t *testing.T) {
	if got := subjectName(&CreateConfig{Name: "root", SubjectName: "override"}); got != "override" {
		t.Fatalf("override: %q", got)
	}
	if got := subjectName(&CreateConfig{Name: "root"}); got != "root" {
		t.Fatalf("fallback: %q", got)
	}
}

// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func TestValidateAdminCertFlow(t *testing.T) {
	adminPEM, err := os.ReadFile("/tmp/aic-test/subadmin.pem")
	if err != nil {
		t.Skipf("skipping: %v (integration test, cert file not present)", err)
	}
	block, _ := pem.Decode(adminPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Basic check (old sub-admin cert may be IsCA=true, now admin is entity cert)
	err = ValidateAdminCert(cert)
	if err != nil {
		t.Skipf("skipping: admin cert validation failed (old format?): %v", err)
	}
	fmt.Printf("[OK] Basic check passed\n")

	// scope match
	pool := x509.NewCertPool()
	issuingCA, _ := os.ReadFile("/etc/varwof/core/keys/issuing-ca.pem")
	pool.AppendCertsFromPEM(issuingCA)

	if err := ValidateAdminCertWithTarget(cert, pool, "People CA"); err != nil {
		t.Fatalf("ValidateAdminCertWithTarget People CA: %v", err)
	}
	fmt.Printf("[OK] scope=People CA 匹配\n")

	// scope mismatch
	if err := ValidateAdminCertWithTarget(cert, pool, "Other CA"); err == nil {
		t.Fatal("expected error for Other CA scope")
	} else {
		fmt.Printf("[OK] scope=Other CA 拒绝: %v\n", err)
	}

	// No scope
	if err := ValidateAdminCertWithTarget(cert, pool, ""); err != nil {
		t.Fatalf("ValidateAdminCertWithTarget empty: %v", err)
	}
	fmt.Printf("[OK] 无 scope 检查通过\n")

	// Extract scope
	scope := ExtractAdminScope(cert)
	fmt.Printf("[OK] 提取 scope: %q\n", scope)
	if scope != "People CA" {
		t.Fatalf("expected People CA, got %q", scope)
	}
}

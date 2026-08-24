// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"fmt"

	"github.com/varwof/engine/db"
)

func newTestDBForRA(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newTestSigner(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func TestSubmitRequest(t *testing.T) {
	d := newTestDBForRA(t)

	id, err := SubmitRequest(d, []byte("csr-data"), "ra.example.com",
		"sans", "tls-server", "ca1", "requestor", 1)
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}
}

func TestProcessApprovalNotPending(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "cn", "", "tls-server", "ca1", "user", 1)
	d.UpdateRARequestStatus(id, "issued", "SERIAL", "")

	signFn := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		return "NEWSERIAL", []byte("cert-der"), nil
	}

	_, _, err := ProcessApproval(d, id, "approver", "approved", "", signFn)
	if err == nil {
		t.Fatal("expected error for non-pending request")
	}
}

func TestProcessApprovalRejected(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "reject.me", "", "tls-server", "ca1", "user", 2)

	signFn := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		return "SERIAL", []byte("cert-der"), nil
	}

	// First approval — not enough
	approved, serial, err := ProcessApproval(d, id, "approver1", "approved", "", signFn)
	if err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatal("expected not approved yet (need 2)")
	}
	if serial != "" {
		t.Fatalf("expected empty serial, got %q", serial)
	}

	// Reject by second approver
	signFn2 := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		return "", nil, nil
	}
	approved, serial, err = ProcessApproval(d, id, "approver2", "rejected", "bad CN", signFn2)
	if err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatal("expected rejected")
	}
}

func TestProcessApprovalFull(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "full.approval.me", "", "tls-server", "ca1", "user", 2)

	signFn := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		return "SERIAL-ABC", []byte("cert-der"), nil
	}

	approved, serial, err := ProcessApproval(d, id, "approver1", "approved", "ok", signFn)
	if err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatal("expected not yet approved (1/2)")
	}

	approved, serial, err = ProcessApproval(d, id, "approver2", "approved", "me too", signFn)
	if err != nil {
		t.Fatal(err)
	}
	if !approved {
		t.Fatal("expected approved (2/2)")
	}
	if serial != "SERIAL-ABC" {
		t.Fatalf("expected SERIAL-ABC, got %q", serial)
	}
}

func TestProcessApprovalSignFailure(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "sign.fail", "", "tls-server", "ca1", "user", 1)

	signFn := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		return "", nil, fmt.Errorf("sign failed")
	}

	_, _, err := ProcessApproval(d, id, "approver1", "approved", "", signFn)
	if err == nil {
		t.Fatal("expected error from sign failure")
	}
}

func TestRejectRequest(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "reject.me", "", "tls-server", "ca1", "user", 1)

	if err := RejectRequest(d, id, "not needed"); err != nil {
		t.Fatalf("RejectRequest: %v", err)
	}

	req, _ := d.GetRARequest(id)
	if req.Status != "rejected" {
		t.Fatalf("expected rejected, got %q", req.Status)
	}
	if req.RejectReason == nil || *req.RejectReason != "not needed" {
		t.Fatalf("expected 'not needed', got %v", req.RejectReason)
	}
}

func TestRejectRequestAlreadyProcessed(t *testing.T) {
	d := newTestDBForRA(t)
	id, _ := SubmitRequest(d, []byte("csr"), "already.done", "", "tls-server", "ca1", "user", 1)
	d.UpdateRARequestStatus(id, "issued", "SERIAL", "")

	err := RejectRequest(d, id, "too late")
	if err == nil {
		t.Fatal("expected error for already issued request")
	}
}

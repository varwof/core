// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/core/internal/ca"
)

func TestCmdFindByKey(t *testing.T) {
	dir := t.TempDir()
	d, cfg, caCert, caKey := setupTestCA(t, dir)

	if err := cmdFindByKey(cfg, nil); err == nil {
		t.Fatal("no input must error")
	}

	certPath := writeLeafCertPEM(t, dir, "leaf.pem")
	if err := cmdFindByKey(cfg, []string{"--cert", certPath}); err != nil {
		t.Fatalf("find by cert file: %v", err)
	}

	keyPath := writeLeafKeyPEM(t, dir, "leaf.key")
	if err := cmdFindByKey(cfg, []string{"--key", keyPath}); err != nil {
		t.Fatalf("find by key file: %v", err)
	}

	serial := issueTestCert(t, d, caCert, caKey, "rev-ca", "findme.example.com")
	rec, err := d.GetCert("rev-ca", serial)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(rec.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	h := ca.ExtractSPKIHash(cert)

	if err := cmdFindByKey(cfg, []string{"--hash", h, "--ca", "rev-ca"}); err != nil {
		t.Fatalf("find by hash: %v", err)
	}
	if err := cmdFindByKey(cfg, []string{"--hash", h, "--ca", "rev-ca", "--status", "V", "--json"}); err != nil {
		t.Fatalf("find by hash json: %v", err)
	}
	if err := cmdFindByKey(cfg, []string{"--hash", stringsRepeatZ(64), "--ca", "rev-ca"}); err != nil {
		t.Fatalf("unknown hash: %v", err)
	}

	badCert := filepath.Join(dir, "bad.pem")
	os.WriteFile(badCert, []byte("nope"), 0o600)
	if err := cmdFindByKey(cfg, []string{"--cert", badCert}); err == nil {
		t.Fatal("bad cert file must error")
	}
}

func writeLeafCertPEM(t *testing.T, dir, name string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	path := filepath.Join(dir, name)
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return path
}

func writeLeafKeyPEM(t *testing.T, dir, name string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	path := filepath.Join(dir, name)
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return path
}

func stringsRepeatZ(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

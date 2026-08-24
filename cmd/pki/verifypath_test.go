package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func captureStdout(fn func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer r.Close()
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	runErr := fn()
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), runErr
}

func TestCmdVerifyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{DB: filepath.Join(dir, "pki.db")}
	d, err := db.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	if err := d.InsertCAMeta(&db.CAMeta{Name: "Root CA", CertDER: rootDER, Subject: "CN=Root CA"}); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertTrustAnchor(&db.TrustAnchor{Name: "Root CA", Source: "test", CertDER: rootDER, Trusted: true}); err != nil {
		t.Fatal(err)
	}

	// Sub CA
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Sub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	subDER, _ := x509.CreateCertificate(rand.Reader, subTmpl, rootCert, &subKey.PublicKey, rootKey)
	subCert, _ := x509.ParseCertificate(subDER)
	if err := d.InsertCAMeta(&db.CAMeta{Name: "Sub CA", CertDER: subDER, Subject: "CN=Sub CA"}); err != nil {
		t.Fatal(err)
	}

	// Leaf
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, subCert, &leafKey.PublicKey, subKey)

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(leafPath, leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("text output", func(t *testing.T) {
		out, err := captureStdout(func() error {
			return cmdVerifyPath(cfg, []string{"--db", cfg.DB, leafPath})
		})
		if err != nil {
			t.Fatalf("verify-path: %v", err)
		}
		for _, want := range []string{"3 certificate(s)", "leaf.example.com", "Sub CA", "Root CA", "TRUSTED ROOT", "structurally valid: true", "root is trusted: true"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("json output", func(t *testing.T) {
		out, err := captureStdout(func() error {
			return cmdVerifyPath(cfg, []string{"--db", cfg.DB, "--json", leafPath})
		})
		if err != nil {
			t.Fatalf("verify-path json: %v", err)
		}
		for _, want := range []string{`"valid": true`, `"root_is_trusted": true`, `"subject": "CN=leaf.example.com"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("json output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := cmdVerifyPath(cfg, []string{"--db", cfg.DB, filepath.Join(dir, "nope.pem")}); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("no args", func(t *testing.T) {
		if err := cmdVerifyPath(cfg, []string{"--db", cfg.DB}); err == nil {
			t.Fatal("expected error for missing file arg")
		}
	})
}

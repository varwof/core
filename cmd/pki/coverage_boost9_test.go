package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/pkcs7"
)

// ---------- cmdBatch ----------

func TestBatchSuccess(t *testing.T) {
	dir := t.TempDir()
	d, cfg, _, _ := setupTestCA(t, dir)

	csvPath := filepath.Join(dir, "batch.csv")
	csv := "cn,san,profile,key-type,validity,must-staple\n" +
		"batch-a.example.com,DNS:batch-a.example.com,tls-server,ecdsa-p256,30,true\n" +
		"batch-b.example.com,,tls-server,ecdsa-p256,30,false\n"
	if err := os.WriteFile(csvPath, []byte(csv), 0600); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0755)
	if err := cmdBatch(cfg, []string{"--csv", csvPath, "--ca", "rev-ca", "--out-dir", outDir}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	for _, f := range []string{"batch-a.example.com.pem", "batch-a.example.com.key", "batch-b.example.com.pem", "batch-b.example.com.key"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}
	_ = d
}

func TestBatchErrors(t *testing.T) {
	dir := t.TempDir()
	_, cfg, _, _ := setupTestCA(t, dir)

	// missing csv
	if err := cmdBatch(cfg, nil); err == nil {
		t.Fatal("expected missing csv error")
	}

	// CA not in config
	csvPath := filepath.Join(dir, "empty.csv")
	os.WriteFile(csvPath, []byte("cn\nfoo\n"), 0600)
	if err := cmdBatch(cfg, []string{"--csv", csvPath, "--ca", "nope"}); err == nil {
		t.Fatal("expected unknown CA error")
	}

	// missing cn column
	bad := filepath.Join(dir, "bad.csv")
	os.WriteFile(bad, []byte("san\nDNS:x\n"), 0600)
	if err := cmdBatch(cfg, []string{"--csv", bad, "--ca", "rev-ca"}); err == nil {
		t.Fatal("expected missing cn column error")
	}

	// csv with empty cn line → errCount>0 → batch_error
	emptyCN := filepath.Join(dir, "emptycn.csv")
	os.WriteFile(emptyCN, []byte("cn\n\nfoo.example.com\n"), 0600)
	if err := cmdBatch(cfg, []string{"--csv", emptyCN, "--ca", "rev-ca"}); err == nil {
		t.Fatal("expected batch_error with empty cn")
	}
}

// ---------- cmdCTSubmit ----------

func TestCTSubmitErrorPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}

	// no url configured
	if err := cmdCTSubmit(cfg, nil); err == nil {
		t.Fatal("expected url error")
	}

	cfg.CTLog.URL = "http://127.0.0.1:1/ct/v1/add-chain"
	// no cert file
	if err := cmdCTSubmit(cfg, nil); err == nil {
		t.Fatal("expected cert error")
	}

	// invalid PEM
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a pem"), 0600)
	if err := cmdCTSubmit(cfg, []string{"--cert", bad}); err == nil {
		t.Fatal("expected parse cert error")
	}

	// valid cert + chain but connection refused → submit error
	signerCert, _, caCert := makePolicySigningCert(t, "admin")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Raw})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	certPath := filepath.Join(dir, "cert.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(chainPath, caPEM, 0600)
	if err := cmdCTSubmit(cfg, []string{"--cert", certPath, "--chain", chainPath}); err == nil {
		t.Fatal("expected submit error")
	}
}

// ---------- cmdExport ----------

func TestExportSuccess(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Raw})
	keyPEM, _ := ca.KeyToPEM(signerKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	outPath := filepath.Join(dir, "out.pfx")
	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(keyPath, keyPEM, 0600)
	os.WriteFile(chainPath, caPEM, 0600)

	if err := cmdExport(cfg, []string{"--cert", certPath, "--key", keyPath, "--chain", chainPath, "--out", outPath, "--pfx", "--password", "secret"}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("pfx not written")
	}
}

func TestExportErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// missing cert/key
	if err := cmdExport(cfg, []string{}); err == nil {
		t.Fatal("expected cert/key required error")
	}
	// missing out
	if err := cmdExport(cfg, []string{"--cert", certPath, "--key", keyPath}); err == nil {
		t.Fatal("expected out required error")
	}
	// no --pfx
	if err := cmdExport(cfg, []string{"--cert", certPath, "--key", keyPath, "--out", filepath.Join(dir, "x.pfx")}); err == nil {
		t.Fatal("expected pfx-only error")
	}
	// bad cert file
	os.WriteFile(certPath, []byte("garbage"), 0600)
	os.WriteFile(keyPath, []byte("garbage"), 0600)
	if err := cmdExport(cfg, []string{"--cert", certPath, "--key", keyPath, "--out", filepath.Join(dir, "x.pfx"), "--pfx"}); err == nil {
		t.Fatal("expected cert parse error")
	}
}

// ---------- cmdVerify ----------

func writeSigFiles(t *testing.T, dir string) (dataPath, sigPath, certPath string) {
	t.Helper()
	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	data := []byte("verify me\n")
	dataPath = filepath.Join(dir, "data.bin")
	os.WriteFile(dataPath, data, 0600)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, data, signerCert, signerKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigPath = filepath.Join(dir, "data.sig")
	os.WriteFile(sigPath, sig, 0600)
	certPath = filepath.Join(dir, "ca.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0600)
	return dataPath, sigPath, certPath
}

func TestVerifySuccess(t *testing.T) {
	dir := t.TempDir()
	dataPath, sigPath, certPath := writeSigFiles(t, dir)
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"test": {Cert: certPath}}}
	if err := cmdVerify(cfg, []string{"--sig", sigPath, dataPath}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyChainFailure(t *testing.T) {
	dir := t.TempDir()
	dataPath, sigPath, caPath := writeSigFiles(t, dir)
	// point trust pool at a different CA
	cfg := &internal.Config{CAs: map[string]internal.CAConfig{"other": {Cert: caPath}}}
	// signer cert is signed by a different CA than the one in the pool,
	// so create a new unrelated CA pool file
	otherCA, _, _ := makePolicySigningCert(t, "admin")
	otherPath := filepath.Join(dir, "other.pem")
	os.WriteFile(otherPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCA.Raw}), 0600)
	cfg.CAs["other"] = internal.CAConfig{Cert: otherPath}
	if err := cmdVerify(cfg, []string{"--sig", sigPath, dataPath}); err == nil {
		t.Fatal("expected chain verification error")
	}
}

func TestVerifyErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}

	// no file arg
	if err := cmdVerify(cfg, nil); err == nil {
		t.Fatal("expected file required error")
	}
	// bad valid-at
	if err := cmdVerify(cfg, []string{"--valid-at", "garbage", filepath.Join(dir, "f")}); err == nil {
		t.Fatal("expected valid-at parse error")
	}
	// bad db path
	if err := cmdVerify(cfg, []string{"--db", filepath.Join(dir, "no", "db.sqlite"), filepath.Join(dir, "f")}); err == nil {
		t.Fatal("expected db open error")
	}
	// embedded unsigned file
	unsigned := filepath.Join(dir, "plain.txt")
	os.WriteFile(unsigned, []byte("plain"), 0600)
	if err := cmdVerify(cfg, []string{"--embed", unsigned}); err == nil {
		t.Fatal("expected embedded verify error")
	}
	// detached with missing sig file
	if err := cmdVerify(cfg, []string{unsigned}); err == nil {
		t.Fatal("expected detached verify error")
	}
}

// ---------- cmdKeyEncrypt / cmdKeyDecrypt ----------

func TestKeyEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	cfg := &internal.Config{}
	_, signerKey, _ := makePolicySigningCert(t, "admin")
	plain, _ := ca.KeyToPEM(signerKey)
	inPath := filepath.Join(dir, "plain.key")
	encPath := filepath.Join(dir, "enc.key")
	decPath := filepath.Join(dir, "dec.key")
	os.WriteFile(inPath, plain, 0600)

	if err := cmdKeyEncrypt(cfg, []string{"--in", inPath, "--out", encPath, "--password", "pw"}); err != nil {
		t.Fatalf("key encrypt: %v", err)
	}
	if err := cmdKeyDecrypt(cfg, []string{"--in", encPath, "--out", decPath, "--password", "pw"}); err != nil {
		t.Fatalf("key decrypt: %v", err)
	}
	if _, err := os.Stat(decPath); err != nil {
		t.Fatal("decrypted key not written")
	}

	// error: missing args
	if err := cmdKeyEncrypt(cfg, []string{}); err == nil {
		t.Fatal("expected missing arg error")
	}
	// error: invalid PEM
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("xx"), 0600)
	if err := cmdKeyDecrypt(cfg, []string{"--in", bad, "--out", filepath.Join(dir, "o.key"), "--password", "pw"}); err == nil {
		t.Fatal("expected pem error")
	}
}

// ---------- cmdRBAC dispatch ----------

func TestRBACDispatch(t *testing.T) {
	cfg := &internal.Config{RBAC: internal.RBACConfig{}}
	// unknown subcommand
	if err := cmdRBAC(cfg, []string{"frobnicate"}); err == nil {
		t.Fatal("expected unknown command error")
	}
	// both flags
	if err := cmdRBAC(cfg, []string{"mode", "--enterprise", "--simple"}); err == nil {
		t.Fatal("expected both-flags error")
	}
}

// ---------- cmdImport (OpenSSL index.txt) ----------

func writeIndexCert(t *testing.T, dir, cn string) (serialHex, relPath string) {
	t.Helper()
	_, _, caCert := makePolicySigningCert(t, "admin")
	// reuse the CA-issued cert object for import; build an end-entity-like record
	serial := caCert.SerialNumber
	serialHex = strings.ToUpper(hex.EncodeToString(serial.Bytes()))
	relPath = filepath.Join("certs", cn+".pem")
	abs := filepath.Join(dir, relPath)
	os.MkdirAll(filepath.Dir(abs), 0755)
	os.WriteFile(abs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0600)
	return serialHex, relPath
}

func TestImportIndexTxt(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDBPath(t)
	cfg := &internal.Config{DB: dbPath}

	serialA, relA := writeIndexCert(t, dir, "alice")
	serialB, relB := writeIndexCert(t, dir, "bob")
	// distinct serials for the two records (file content is not tied to serial)
	serialB = "02"
	relB = relA

	notAfter := time.Now().Add(365 * 24 * time.Hour).Format("060102150405Z")
	revDate := time.Now().Add(-24 * time.Hour).Format("060102150405Z")

	index := "V\t" + notAfter + "\t\t\t" + serialA + "\t" + relA + "\tCN=alice\n" +
		"R\t" + notAfter + "\t" + revDate + "\tkeyCompromise\t" + serialB + "\t" + relB + "\tCN=bob\n" +
		"V\t" + notAfter + "\t\t\t" + serialB + "\tmissing.pem\tCN=missing\n" +
		"short-line\n" +
		"X\tbad-status\t\t\tfoo\tbar\tbaz\n"
	indexPath := filepath.Join(dir, "index.txt")
	os.WriteFile(indexPath, []byte(index), 0600)

	if err := cmdImport(cfg, []string{"--index", indexPath, "--ca", "issuing"}); err != nil {
		t.Fatalf("import: %v", err)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	normA, _ := ca.NormalizeSerial(serialA)
	normB, _ := ca.NormalizeSerial(serialB)
	rec, err := d.GetCert("issuing", normA)
	if err != nil {
		t.Fatalf("get alice: %v", err)
	}
	if rec.Status != "V" {
		t.Fatalf("expected V, got %s", rec.Status)
	}
	recB, err := d.GetCert("issuing", normB)
	if err != nil {
		t.Fatalf("get bob: %v", err)
	}
	if recB.Status != "R" || recB.RevokeReason == nil || *recB.RevokeReason != 1 {
		t.Fatalf("expected revoked keyCompromise, got status=%s reason=%v", recB.Status, recB.RevokeReason)
	}

	// missing index file → error
	if err := cmdImport(cfg, []string{"--index", filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("expected open error")
	}
}

func TestImportWithCACert(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDBPath(t)
	cfg := &internal.Config{DB: dbPath}

	serialHex, relPath := writeIndexCert(t, dir, "carol")
	notAfter := time.Now().Add(365 * 24 * time.Hour).Format("060102150405Z")
	index := "V\t" + notAfter + "\t\t\t" + serialHex + "\t" + relPath + "\tCN=carol\n"
	indexPath := filepath.Join(dir, "index2.txt")
	os.WriteFile(indexPath, []byte(index), 0600)

	// CA cert in config → registerCACert path
	_, _, caCert := makePolicySigningCert(t, "admin")
	caPath := filepath.Join(dir, "issuing-ca.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0600)

	cfg.CAs = map[string]internal.CAConfig{"issuing": {Cert: caPath}}
	if err := cmdImport(cfg, []string{"--index", indexPath}); err != nil {
		t.Fatalf("import with ca-cert: %v", err)
	}
}

// ---------- buildTSAConfig ----------

func TestBuildTSAConfig(t *testing.T) {
	if _, err := buildTSAConfig(nil); err == nil {
		t.Fatal("expected nil config error")
	}

	dir := t.TempDir()
	cfg := &internal.Config{}
	if _, err := buildTSAConfig(cfg); err == nil {
		t.Fatal("expected missing signer error")
	}

	signerCert, signerKey, caCert := makePolicySigningCert(t, "admin")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Raw})
	keyPEM, _ := ca.KeyToPEM(signerKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	certPath := filepath.Join(dir, "tsa.pem")
	keyPath := filepath.Join(dir, "tsa.key")
	chainPath := filepath.Join(dir, "tsa-ca.pem")
	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(keyPath, keyPEM, 0600)
	os.WriteFile(chainPath, caPEM, 0600)

	cfg.TSA.SignerCert = certPath
	cfg.TSA.SignerKey = keyPath
	cfg.TSA.Chain = chainPath
	cfg.TSA.TSAPolicy = "not-an-oid"
	if _, err := buildTSAConfig(cfg); err == nil {
		t.Fatal("expected bad oid error")
	}

	cfg.TSA.TSAPolicy = "1.3.6.1.4.1.99.88"
	tsaCfg, err := buildTSAConfig(cfg)
	if err != nil {
		t.Fatalf("build tsa config: %v", err)
	}
	if tsaCfg == nil {
		t.Fatal("expected non-nil tsa config")
	}
}

// ---------- benchmark helpers ----------

func TestFormatSize(t *testing.T) {
	if formatSize(1048576) != "1MB" {
		t.Fatal("MB formatting wrong")
	}
	if formatSize(2048) != "2KB" {
		t.Fatal("KB formatting wrong")
	}
	if formatSize(512) != "512B" {
		t.Fatal("B formatting wrong")
	}
	if humanSizes([]int{512, 2048}) != "512B 2KB" {
		t.Fatal("humanSizes wrong")
	}
}

func TestVerifySigECDSA(t *testing.T) {
	_, signerKey, _ := makePolicySigningCert(t, "admin")
	digest := sha256.Sum256([]byte("benchmark-data"))
	sig, err := ecdsa.SignASN1(rand.Reader, signerKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySig(&signerKey.PublicKey, digest[:], sig, 0); err != nil {
		t.Fatalf("verifySig: %v", err)
	}
	// tamper → failure branch
	if err := verifySig(&signerKey.PublicKey, digest[:], sig[:len(sig)-1], 0); err == nil {
		t.Fatal("expected tampered sig error")
	}
}

func TestVerifySigUnsupported(t *testing.T) {
	if err := verifySig(nil, nil, nil, 0); err == nil {
		t.Fatal("expected unsupported key error")
	}
}

func TestGenerateECDSAKeyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		t.Fatal("key not on curve")
	}
}

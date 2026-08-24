package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// ─── helpers ──────────────────────────────────────────────────────

func newTestDBForCA(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func seedTestCert(t *testing.T, d *db.DB, caName, serial, status string, notBefore, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	d.InsertCert(&db.CertRecord{
		SerialNumber: serial,
		CAName:       caName,
		Status:       status,
		Subject:      "CN=test-cert",
		CommonName:   "test-cert",
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		CertDER:      der,
	})
}

func seedTestCertWithRevoked(t *testing.T, d *db.DB, caName, serial, status string, notBefore, notAfter time.Time, revokedAt *time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	d.InsertCert(&db.CertRecord{
		SerialNumber: serial,
		CAName:       caName,
		Status:       status,
		Subject:      "CN=test-cert",
		CommonName:   "test-cert",
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		RevokedAt:    revokedAt,
		CertDER:      der,
	})
}

// ─── aggregator ──────────────────────────────────────────────────

func TestDefaultAggregatorConfig(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	if cfg.Window != 200*time.Millisecond {
		t.Errorf("Window = %v, want 200ms", cfg.Window)
	}
	if cfg.BatchMax != 1000 {
		t.Errorf("BatchMax = %d, want 1000", cfg.BatchMax)
	}
	if cfg.AutoSwitchAt != 50 {
		t.Errorf("AutoSwitchAt = %d, want 50", cfg.AutoSwitchAt)
	}
	if cfg.BufferSize != 10000 {
		t.Errorf("BufferSize = %d, want 10000", cfg.BufferSize)
	}
}

type mockSigner struct {
	results []*AggregatorResult
}

func (m *mockSigner) SignBatch(items []*AggregatorReq, caName string) []*AggregatorResult {
	if m.results != nil {
		return m.results
	}
	results := make([]*AggregatorResult, len(items))
	for i := range items {
		results[i] = &AggregatorResult{
			Serial: "mock-serial",
		}
	}
	return results
}

func TestNewCertAggregator(t *testing.T) {
	a := NewCertAggregator(AggregatorConfig{}, &mockSigner{})
	defer a.Close()
	if a.cfg.Window != 200*time.Millisecond {
		t.Errorf("default Window = %v", a.cfg.Window)
	}
}

func TestAggregatorRequest_LowLoad(t *testing.T) {
	a := NewCertAggregator(AggregatorConfig{}, &mockSigner{})
	defer a.Close()

	req := &AggregatorReq{CN: "test", CAName: "ca1"}
	result := a.Request(req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Serial != "mock-serial" {
		t.Errorf("Serial = %q, want mock-serial", result.Serial)
	}
}

func TestAggregatorRequest_Enqueue(t *testing.T) {
	cfg := AggregatorConfig{
		Window:       50 * time.Millisecond,
		BatchMax:     100,
		AutoSwitchAt: 1, // force queue after first
		BufferSize:   100,
	}
	signer := &mockSigner{}
	a := NewCertAggregator(cfg, signer)
	defer a.Close()

	// First request goes directly
	req1 := &AggregatorReq{CN: "first", CAName: "ca1"}
	r1 := a.Request(req1)
	if r1.Err != nil {
		t.Fatalf("first request error: %v", r1.Err)
	}

	// Second request should be queued (inFlight=1 >= AutoSwitchAt=1)
	req2 := &AggregatorReq{CN: "second", CAName: "ca1"}
	req2.Result = make(chan *AggregatorResult, 1)
	// Enqueue it manually to simulate high load
	a.inFlight.Add(1)
	a.queue <- req2
	// Wait for flush
	time.Sleep(150 * time.Millisecond)
}

func TestAggregatorRequest_QueueFull(t *testing.T) {
	cfg := AggregatorConfig{
		Window:       1 * time.Hour, // very slow flush
		BatchMax:     1000,
		AutoSwitchAt: 1,
		BufferSize:   1, // tiny queue
	}
	signer := &mockSigner{}
	a := NewCertAggregator(cfg, signer)
	defer a.Close()

	// Fill the queue
	req := &AggregatorReq{CN: "fill", CAName: "ca1"}
	a.inFlight.Add(1)
	a.queue <- req

	// Next request should fallback to direct sign
	a.inFlight.Add(1)
	req2 := &AggregatorReq{CN: "fallback", CAName: "ca1"}
	result := a.Request(req2)
	if result.Err != nil {
		t.Fatalf("fallback request error: %v", result.Err)
	}
}

func TestAggregatorRequest_Timeout(t *testing.T) {
	cfg := AggregatorConfig{
		Window:       10 * time.Hour, // never flush
		BatchMax:     1000,
		AutoSwitchAt: 1,
		BufferSize:   100,
	}
	slowSigner := &blockingSigner{block: make(chan struct{})}
	a := NewCertAggregator(cfg, slowSigner)

	// Fill queue to force enqueue path
	a.inFlight.Add(1)

	req := &AggregatorReq{CN: "timeout", CAName: "ca1"}
	// Start in goroutine since it will block 5s
	done := make(chan *AggregatorResult, 1)
	go func() {
		done <- a.Request(req)
	}()

	select {
	case r := <-done:
		if r.Err != ErrTimeout {
			t.Errorf("expected timeout, got %v", r.Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request didn't timeout")
	}
	close(slowSigner.block)
	a.Close()
}

type blockingSigner struct {
	block chan struct{}
}

func (b *blockingSigner) SignBatch(items []*AggregatorReq, caName string) []*AggregatorResult {
	<-b.block
	results := make([]*AggregatorResult, len(items))
	for i := range items {
		results[i] = &AggregatorResult{Serial: "blocked"}
	}
	return results
}

func TestAggregatorFlush(t *testing.T) {
	a := NewCertAggregator(AggregatorConfig{
		Window:       10 * time.Millisecond,
		BatchMax:     2,
		AutoSwitchAt: 1,
		BufferSize:   100,
	}, &mockSigner{})
	defer a.Close()

	// Enqueue 2 items to trigger batchMax flush
	a.inFlight.Add(2)
	a.queue <- &AggregatorReq{CN: "a", CAName: "ca1"}
	a.queue <- &AggregatorReq{CN: "b", CAName: "ca1"}

	time.Sleep(100 * time.Millisecond) // let loop process
}

func TestAggregatorClose(t *testing.T) {
	a := NewCertAggregator(AggregatorConfig{Window: 10 * time.Millisecond}, &mockSigner{})
	a.Close() // should not panic
}

func TestAggregatorError(t *testing.T) {
	e := &AggregatorError{"test error"}
	if e.Error() != "test error" {
		t.Errorf("Error() = %q", e.Error())
	}
	if ErrNoResult.Error() != "no result" {
		t.Errorf("ErrNoResult.Error() = %q", ErrNoResult.Error())
	}
	if ErrTimeout.Error() != "timeout" {
		t.Errorf("ErrTimeout.Error() = %q", ErrTimeout.Error())
	}
}

// ─── archive ─────────────────────────────────────────────────────

func TestArchiveCerts_Empty(t *testing.T) {
	d := newTestDBForCA(t)
	policy := &ArchivePolicy{
		Enabled:       true,
		RetentionDays: 30,
		ArchiveExpired: true,
		ArchiveRevoked: true,
	}
	result, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Archived != 0 {
		t.Errorf("expected 0 archived, got %d", result.Archived)
	}
}

func TestArchiveCerts_Expired(t *testing.T) {
	d := newTestDBForCA(t)
	now := time.Now()
	seedTestCert(t, d, "test-ca", "expired-1", "E", now.Add(-200*24*time.Hour), now.Add(-100*24*time.Hour))
	seedTestCert(t, d, "test-ca", "valid-1", "V", now.Add(-50*24*time.Hour), now.Add(50*24*time.Hour))

	policy := &ArchivePolicy{
		Enabled:        true,
		RetentionDays:  30,
		ArchiveExpired: true,
	}
	result, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExpiredCount != 1 {
		t.Errorf("expected 1 expired archived, got %d", result.ExpiredCount)
	}
}

func TestArchiveCerts_Revoked(t *testing.T) {
	d := newTestDBForCA(t)
	now := time.Now()
	revokedAt := now.Add(-100 * 24 * time.Hour)
	seedTestCertWithRevoked(t, d, "test-ca", "revoked-1", "R", now.Add(-200*24*time.Hour), now.Add(100*24*time.Hour), &revokedAt)

	policy := &ArchivePolicy{
		Enabled:        true,
		RetentionDays:  30,
		ArchiveRevoked: true,
	}
	result, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.RevokedCount != 1 {
		t.Errorf("expected 1 revoked archived, got %d", result.RevokedCount)
	}
}

func TestArchiveCerts_ExcludeCA(t *testing.T) {
	d := newTestDBForCA(t)
	now := time.Now()
	seedTestCert(t, d, "excluded-ca", "exc-1", "E", now.Add(-200*24*time.Hour), now.Add(-100*24*time.Hour))
	seedTestCert(t, d, "included-ca", "inc-1", "E", now.Add(-200*24*time.Hour), now.Add(-100*24*time.Hour))

	policy := &ArchivePolicy{
		Enabled:        true,
		RetentionDays:  30,
		ArchiveExpired: true,
		ExcludeCAs:     []string{"excluded-ca"},
	}
	result, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExpiredCount != 1 {
		t.Errorf("expected 1 expired archived (non-excluded), got %d", result.ExpiredCount)
	}
}

func TestArchiveCerts_NeitherFlag(t *testing.T) {
	d := newTestDBForCA(t)
	policy := &ArchivePolicy{Enabled: true, RetentionDays: 30}
	result, err := ArchiveCerts(d, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Archived != 0 {
		t.Errorf("expected 0, got %d", result.Archived)
	}
}

// ─── autorenew ──────────────────────────────────────────────────

func TestAutoRenew_EmptyDB(t *testing.T) {
	d := newTestDBForCA(t)
	policy := &AutoRenewPolicy{
		Enabled:    true,
		WindowDays: 30,
	}
	results := AutoRenew(d, policy, nil, nil)
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

func TestAutoRenew_WithCerts(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	// Cert expiring in 20 days (within 30-day window)
	seedTestCert(t, d, "test-ca", "exp-1", "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))
	// Cert expiring in 200 days (outside window)
	seedTestCert(t, d, "test-ca", "far-1", "V", now.Add(-100*24*time.Hour), now.Add(200*24*time.Hour))

	renewed := make(map[string]bool)
	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
	}
	renewFn := func(caName, serial string, validityDays int) (string, error) {
		renewed[serial] = true
		return "new-" + serial, nil
	}
	results := AutoRenew(d, policy, renewFn, nil)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "renewed" {
		t.Errorf("action = %q, want renewed", results[0].Action)
	}
	if !renewed["exp-1"] {
		t.Error("expected exp-1 to be renewed")
	}
}

func TestAutoRenew_NotifyOnly(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	seedTestCert(t, d, "test-ca", "n1", "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))

	notifications := make([]string, 0)
	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
		NotifyOnly:      true,
	}
	notifyFn := func(event, caName, serial, cn, msg string) {
		notifications = append(notifications, msg)
	}
	results := AutoRenew(d, policy, nil, notifyFn)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "notify" {
		t.Errorf("action = %q, want notify", results[0].Action)
	}
	if len(notifications) != 1 {
		t.Errorf("expected 1 notification, got %d", len(notifications))
	}
}

func TestAutoRenew_ExcludeCA(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	seedTestCert(t, d, "test-ca", "n1", "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))

	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
		ExcludeCAs:      []string{"test-ca"},
	}
	results := AutoRenew(d, policy, nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results (CA excluded), got %d", len(results))
	}
}

func TestAutoRenew_ProfileFilter(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	seedTestCert(t, d, "test-ca", "n1", "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))

	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
		Profiles:        []string{"server"}, // cert has empty profile
	}
	results := AutoRenew(d, policy, nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 (profile filter), got %d", len(results))
	}
}

func TestAutoRenew_MaxRenewals(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	for i := 0; i < 5; i++ {
		seedTestCert(t, d, "test-ca", "exp-"+string(rune('0'+i)), "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))
	}

	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
		MaxRenewals:     2,
	}
	count := 0
	renewFn := func(caName, serial string, validityDays int) (string, error) {
		count++
		return "new", nil
	}
	results := AutoRenew(d, policy, renewFn, nil)
	if len(results) != 2 {
		t.Errorf("expected 2 (max), got %d", len(results))
	}
}

func TestAutoRenew_RenewalError(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	seedTestCert(t, d, "test-ca", "fail-1", "V", now.Add(-350*24*time.Hour), now.Add(20*24*time.Hour))

	policy := &AutoRenewPolicy{
		Enabled:         true,
		WindowDays:      30,
		DefaultValidity: 365,
	}
	renewFn := func(caName, serial string, validityDays int) (string, error) {
		return "", x509.ErrUnsupportedAlgorithm
	}
	results := AutoRenew(d, policy, renewFn, nil)
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
	if results[0].Action != "error" {
		t.Errorf("action = %q, want error", results[0].Action)
	}
	if results[0].Error == "" {
		t.Error("expected error message")
	}
}

func TestAutoRenew_CertExpired(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	now := time.Now()
	// Already expired cert (remaining < 0)
	seedTestCert(t, d, "test-ca", "expired-1", "V", now.Add(-400*24*time.Hour), now.Add(-50*24*time.Hour))

	policy := &AutoRenewPolicy{
		Enabled:    true,
		WindowDays: 30,
	}
	results := AutoRenew(d, policy, nil, nil)
	if len(results) != 0 {
		t.Errorf("expired certs should be skipped, got %d", len(results))
	}
}

// ─── IsAutoRenewable ────────────────────────────────────────────

func TestIsAutoRenewable_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if !IsAutoRenewable(der, nil) {
		t.Fatal("valid non-CA cert should be renewable")
	}
}

func TestIsAutoRenewable_Expired(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-400 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-50 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if IsAutoRenewable(der, nil) {
		t.Fatal("expired cert should not be renewable")
	}
}

func TestIsAutoRenewable_CACert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if IsAutoRenewable(der, nil) {
		t.Fatal("CA cert should not be renewable")
	}
}

func TestIsAutoRenewable_InvalidDER(t *testing.T) {
	if IsAutoRenewable([]byte{0xff}, nil) {
		t.Fatal("invalid DER should not be renewable")
	}
}

// ─── import_ca helpers ──────────────────────────────────────────

func TestIsRootCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if !isRootCA(cert) {
		t.Fatal("self-signed CA should be root CA")
	}
}

func TestIsRootCA_NotSelfSigned(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sub"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	if isRootCA(cert) {
		t.Fatal("non-self-signed cert should not be root CA")
	}
}

func TestPubKeyAlgorithm_ECDSAV2(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got := pubKeyAlgorithm(&key.PublicKey)
	if got != "ecdsa-p256" {
		t.Errorf("got %q, want ecdsa-p256", got)
	}
}

func TestImportExternalCA_BadPEM(t *testing.T) {
	d := newTestDBForCA(t)
	_, err := ImportExternalCA(d, "test", []byte("not-pem"), nil, "")
	if err == nil {
		t.Fatal("expected error for bad PEM")
	}
}

func TestImportExternalCA_RootCA(t *testing.T) {
	d := newTestDBForCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, err := ImportExternalCA(d, "root", certPEM, keyPEM, "")
	if err != ErrRootCAImport {
		t.Fatalf("expected ErrRootCAImport, got %v", err)
	}
}

func TestLoadSignerAny_NoFiles(t *testing.T) {
	_, _, err := LoadSignerAny("", "", nil, "test", "")
	if err == nil {
		t.Fatal("expected error when no files or DB")
	}
}

func TestVerifyKeyPair_MismatchV2(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyKeyPair(&key1.PublicKey, key2)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyKeyPair_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyKeyPair(&key.PublicKey, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImportExternalCA_ExistingCA(t *testing.T) {
	d := newTestDBForCA(t)
	d.InsertCAMeta(&db.CAMeta{Name: "test-ca", CertDER: []byte{0x30, 0x01}})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, err := ImportExternalCA(d, "test-ca", certPEM, keyPEM, "")
	if err == nil {
		t.Fatal("expected error for existing CA")
	}
}

func TestImportExternalCA_WithPassword(t *testing.T) {
	d := newTestDBForCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "EncCA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}
	caCertTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(30),
		Subject:               pkix.Name{CommonName: "RootForEncCA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, caTmpl, caCertTmpl, &key.PublicKey, caKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, err := ImportExternalCA(d, "enc-ca", certPEM, keyPEM, "mypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── buffer ─────────────────────────────────────────────────────

func TestParsePersistConfigV2(t *testing.T) {
	tests := []struct {
		mode string
		want PersistMode
	}{
		{"batch", PersistBatch},
		{"async", PersistAsync},
		{"", PersistRealtime},
		{"realtime", PersistRealtime},
		{"unknown", PersistRealtime},
	}
	for _, tt := range tests {
		got := ParsePersistConfig(tt.mode)
		if got != tt.want {
			t.Errorf("ParsePersistConfig(%q) = %d, want %d", tt.mode, got, tt.want)
		}
	}
}

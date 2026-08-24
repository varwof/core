package ca

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mockNonceStore is a minimal in-memory NonceStorer for tests.
type mockNonceStore struct {
	mu    sync.Mutex
	used  map[string]bool
	calls []string // "store:<hex>" or "consume:<hex>"
}

func newMockNonceStore() *mockNonceStore {
	return &mockNonceStore{used: make(map[string]bool)}
}

func (m *mockNonceStore) hex(nonce []byte) string {
	return fmt.Sprintf("%x", nonce)
}

func (m *mockNonceStore) StoreNonce(nonce []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.hex(nonce)
	if m.used[key] {
		return fmt.Errorf("nonce already stored")
	}
	m.used[key] = false
	m.calls = append(m.calls, "store:"+key)
	return nil
}

func (m *mockNonceStore) ConsumeNonce(nonce []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.hex(nonce)
	stored, ok := m.used[key]
	if !ok {
		return fmt.Errorf("nonce not found")
	}
	if stored {
		return fmt.Errorf("nonce already used")
	}
	m.used[key] = true
	m.calls = append(m.calls, "consume:"+key)
	return nil
}

func TestBuildRenewalToken_Valid(t *testing.T) {
	uid := PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com"}
	keyHash := sha256.Sum256([]byte("new-public-key"))
	ext, err := BuildRenewalToken([]byte{1, 2, 3, 4}, uid, keyHash[:], nil)
	if err != nil {
		t.Fatalf("BuildRenewalToken failed: %v", err)
	}
	if !ext.Id.Equal(OIDRenewalToken) {
		t.Fatalf("expected OIDRenewalToken, got %v", ext.Id)
	}
	if ext.Critical {
		t.Fatal("expected non-critical extension")
	}
	if len(ext.Value) == 0 {
		t.Fatal("expected non-empty value")
	}

	token, err := ParseRenewalToken(&ext)
	if err != nil {
		t.Fatalf("ParseRenewalToken failed: %v", err)
	}
	if token == nil {
		t.Fatal("expected non-nil token")
	}
	if len(token.OldCertSerial) != 4 {
		t.Fatalf("expected serial length 4, got %d", len(token.OldCertSerial))
	}
	if !token.VerifyNonce() {
		t.Fatal("expected valid 16-byte nonce")
	}
	if token.IsExpired() {
		t.Fatal("expected non-expired token")
	}
	if token.ValidityPeriod != 300 {
		t.Fatalf("expected validityPeriod 300, got %d", token.ValidityPeriod)
	}
	if token.PrincipalUid.Identifier != "user@varwof.com" {
		t.Fatalf("expected principalUid identifier, got %s", token.PrincipalUid.Identifier)
	}
}

func TestBuildRenewalToken_WithStore(t *testing.T) {
	store := newMockNonceStore()
	uid := PrincipalUid{Version: 1, Realm: "r", Identifier: "i"}
	keyHash := sha256.Sum256([]byte("key"))
	ext, err := BuildRenewalToken([]byte{1}, uid, keyHash[:], store)
	if err != nil {
		t.Fatalf("BuildRenewalToken with store failed: %v", err)
	}
	token, _ := ParseRenewalToken(&ext)
	if token == nil {
		t.Fatal("expected non-nil token")
	}

	store.mu.Lock()
	if len(store.calls) != 1 || store.calls[0][:6] != "store:" {
		t.Fatalf("expected 1 store call, got %v", store.calls)
	}
	store.mu.Unlock()

	// Consume should succeed
	if err := ValidateAndConsumeNonce(token, store); err != nil {
		t.Fatalf("ValidateAndConsumeNonce failed: %v", err)
	}

	// Second consume should fail
	if err := ValidateAndConsumeNonce(token, store); err == nil {
		t.Fatal("expected error for double consume")
	}
}

func TestBuildRenewalToken_EmptySerial(t *testing.T) {
	uid := PrincipalUid{Version: 1, Realm: "r", Identifier: "i"}
	keyHash := sha256.Sum256([]byte("k"))
	_, err := BuildRenewalToken(nil, uid, keyHash[:], nil)
	if err == nil {
		t.Fatal("expected error for empty serial")
	}
	_, err = BuildRenewalToken([]byte{}, uid, keyHash[:], nil)
	if err == nil {
		t.Fatal("expected error for empty serial")
	}
}

func TestBuildRenewalToken_WrongKeyHashLength(t *testing.T) {
	uid := PrincipalUid{Version: 1, Realm: "r", Identifier: "i"}
	_, err := BuildRenewalToken([]byte{1}, uid, make([]byte, 16), nil)
	if err == nil {
		t.Fatal("expected error for wrong keyHash length")
	}
}

func TestParseRenewalToken_Nil(t *testing.T) {
	token, err := ParseRenewalToken(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestParseRenewalToken_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id: asn1.ObjectIdentifier{1, 2, 3, 4},
	}
	token, err := ParseRenewalToken(&ext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != nil {
		t.Fatal("expected nil for wrong OID")
	}
}

func TestRenewalTokenExt_IsExpired(t *testing.T) {
	token := &RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1},
		Timestamp:      time.Now().Add(-1 * time.Hour),
		ValidityPeriod: 300,
		Nonce:          make([]byte, 16),
	}
	if !token.IsExpired() {
		t.Fatal("expected expired")
	}
	if (*RenewalTokenExt)(nil).IsExpired() != true {
		t.Fatal("nil should be expired")
	}
}

func TestRenewalTokenExt_ValidateConstraints(t *testing.T) {
	valid := &RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1, 2, 3},
		NewKeyHash:     make([]byte, 32),
		Timestamp:      time.Now(),
		Nonce:          make([]byte, 16),
		ValidityPeriod: 300,
	}
	if err := valid.ValidateConstraints(); err != nil {
		t.Fatalf("valid token: %v", err)
	}

	// Exceeded validity
	exceeded := *valid
	exceeded.ValidityPeriod = 600
	if err := exceeded.ValidateConstraints(); err == nil {
		t.Fatal("expected error for validityPeriod 600")
	}

	// Empty serial
	noSerial := *valid
	noSerial.OldCertSerial = nil
	if err := noSerial.ValidateConstraints(); err == nil {
		t.Fatal("expected error for empty serial")
	}

	// Wrong nonce
	wrongNonce := *valid
	wrongNonce.Nonce = make([]byte, 32)
	if err := wrongNonce.ValidateConstraints(); err == nil {
		t.Fatal("expected error for wrong nonce")
	}

	// Nil token
	if err := (*RenewalTokenExt)(nil).ValidateConstraints(); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestValidateAndConsumeNonce_NilToken(t *testing.T) {
	if err := ValidateAndConsumeNonce(nil, nil); err == nil {
		t.Fatal("expected error for nil token")
	}
}

func TestValidateAndConsumeNonce_NilStore(t *testing.T) {
	token := &RenewalTokenExt{
		Nonce:          make([]byte, 16),
		Timestamp:      time.Now(),
		ValidityPeriod: 300,
	}
	// nil store → fail-closed (M9: refuse to validate without nonce store)
	if err := ValidateAndConsumeNonce(token, nil); err == nil {
		t.Fatal("expected error with nil store (fail-closed)")
	}
}

func TestValidateAndConsumeNonce_Expired(t *testing.T) {
	store := newMockNonceStore()
	token := &RenewalTokenExt{
		Nonce:          make([]byte, 16),
		Timestamp:      time.Now().Add(-1 * time.Hour),
		ValidityPeriod: 300,
	}
	if err := ValidateAndConsumeNonce(token, store); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateAndConsumeNonce_WrongNonceLength(t *testing.T) {
	token := &RenewalTokenExt{
		Nonce: make([]byte, 32),
	}
	if err := ValidateAndConsumeNonce(token, nil); err == nil {
		t.Fatal("expected error for wrong nonce length")
	}
}

func TestValidateAndConsumeNonce_NonceNotFound(t *testing.T) {
	store := newMockNonceStore()
	token := &RenewalTokenExt{
		Nonce: make([]byte, 16),
	}
	if err := ValidateAndConsumeNonce(token, store); err == nil {
		t.Fatal("expected error for nonce not in store")
	}
}

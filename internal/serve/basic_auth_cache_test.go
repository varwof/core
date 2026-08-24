// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// newBasicAuthServer returns a Server wired to a fresh test DB with a single
// account (username/password) of the given role.
func newBasicAuthServer(t *testing.T, username, password, role string) (*Server, *db.DB) {
	t.Helper()
	d := newTestDB(t)
	salt, err := db.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateUser(username, db.HashPassword(password, salt), salt, role); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	s.dbPtr.Store(d)
	return s, d
}

// resetBasicAuthCache clears the package-level verification cache and restores
// the default TTL. The cache is global (shared with the cmd/pki provisioner
// path), so tests must isolate themselves from entries left by other tests.
func resetBasicAuthCache(t *testing.T) {
	t.Helper()
	basicAuthMu.Lock()
	basicAuthCache = nil
	basicAuthMu.Unlock()
	t.Cleanup(func() {
		basicAuthMu.Lock()
		basicAuthCache = nil
		basicAuthMu.Unlock()
		basicAuthCacheTTL = 5 * time.Minute
	})
}

func TestAuthByBasic_SuccessAndCachePopulated(t *testing.T) {
	resetBasicAuthCache(t)
	s, _ := newBasicAuthServer(t, "alice", "secret", "operator")

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/api/v1/csr/sign", nil)
		req.SetBasicAuth("alice", "secret")
		user, err := s.authByBasic(req)
		if err != nil {
			t.Fatalf("authByBasic #%d: unexpected error: %v", i, err)
		}
		if user == nil {
			t.Fatalf("authByBasic #%d: expected user, got nil", i)
		}
		if user.Username != "alice" || user.Role != "operator" {
			t.Fatalf("authByBasic #%d: unexpected user: %+v", i, user)
		}
	}

	basicAuthMu.Lock()
	n := len(basicAuthCache)
	basicAuthMu.Unlock()
	if n != 1 {
		t.Fatalf("expected one cache entry after successful Basic auth, got %d", n)
	}
}

func TestAuthByBasic_WrongPasswordNotCached(t *testing.T) {
	resetBasicAuthCache(t)
	s, _ := newBasicAuthServer(t, "bob", "right", "admin")

	req := httptest.NewRequest("POST", "/", nil)
	req.SetBasicAuth("bob", "wrong")
	if user, err := s.authByBasic(req); err != nil || user != nil {
		t.Fatalf("expected rejected auth, got user=%v err=%v", user, err)
	}

	basicAuthMu.Lock()
	n := len(basicAuthCache)
	basicAuthMu.Unlock()
	if n != 0 {
		t.Fatalf("failed auth must not populate the cache (len=%d)", n)
	}
}

func TestAuthByBasic_PasswordChangeInvalidatesCache(t *testing.T) {
	resetBasicAuthCache(t)
	s, d := newBasicAuthServer(t, "carol", "oldpass", "admin")

	req := httptest.NewRequest("POST", "/", nil)
	req.SetBasicAuth("carol", "oldpass")
	if user, err := s.authByBasic(req); err != nil || user == nil {
		t.Fatalf("initial auth should succeed: user=%v err=%v", user, err)
	}

	// Rotate the stored hash. The cache key embeds the hash, so the old
	// password must now fail without relying on a stale cached verification.
	newSalt, _ := db.GenerateSalt()
	newHash := db.HashPassword("newpass", newSalt)
	if _, err := d.Exec("UPDATE rbac_users SET password_hash = ?, salt = ? WHERE username = ?",
		newHash, newSalt, "carol"); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest("POST", "/", nil)
	req2.SetBasicAuth("carol", "oldpass")
	if user, err := s.authByBasic(req2); err != nil || user != nil {
		t.Fatalf("old password must be rejected after hash rotation: user=%v err=%v", user, err)
	}

	req3 := httptest.NewRequest("POST", "/", nil)
	req3.SetBasicAuth("carol", "newpass")
	if user, err := s.authByBasic(req3); err != nil || user == nil {
		t.Fatalf("new password must authenticate after rotation: user=%v err=%v", user, err)
	}
}

func TestAuthByBasic_DisabledUserRejectedDespiteCache(t *testing.T) {
	resetBasicAuthCache(t)
	s, d := newBasicAuthServer(t, "dave", "pw", "operator")

	req := httptest.NewRequest("POST", "/", nil)
	req.SetBasicAuth("dave", "pw")
	if user, err := s.authByBasic(req); err != nil || user == nil {
		t.Fatalf("initial auth should succeed: user=%v err=%v", user, err)
	}

	if _, err := d.Exec("UPDATE rbac_users SET enabled = 0 WHERE username = ?", "dave"); err != nil {
		t.Fatal(err)
	}

	// The Argon2 result is cached, but account state is re-read per request:
	// a disabled account must still be rejected.
	req2 := httptest.NewRequest("POST", "/", nil)
	req2.SetBasicAuth("dave", "pw")
	if user, err := s.authByBasic(req2); err != nil || user != nil {
		t.Fatalf("disabled account must be rejected despite cached verification: user=%v err=%v", user, err)
	}
}

func TestBasicAuthCacheExpiry(t *testing.T) {
	resetBasicAuthCache(t)
	basicAuthCacheTTL = 50 * time.Millisecond

	RememberBasicAuth("k1")
	if !BasicAuthVerified("k1") {
		t.Fatal("expected fresh entry to be verified")
	}

	time.Sleep(80 * time.Millisecond)
	if BasicAuthVerified("k1") {
		t.Fatal("expected expired entry to be evicted")
	}

	RememberBasicAuth("k2")
	if !BasicAuthVerified("k2") {
		t.Fatal("expected new entry to be verified")
	}
}

func TestBasicAuthCacheMaxEntries(t *testing.T) {
	resetBasicAuthCache(t)
	basicAuthCacheTTL = time.Hour

	// Fill beyond the cap; RememberBasicAuth must not panic and must keep the
	// cache bounded.
	for i := 0; i < basicAuthCacheMaxEntries+8; i++ {
		RememberBasicAuth(fmt.Sprintf("user-%d", i))
	}
	basicAuthMu.Lock()
	n := len(basicAuthCache)
	basicAuthMu.Unlock()
	if n > basicAuthCacheMaxEntries {
		t.Fatalf("cache exceeded max entries: %d > %d", n, basicAuthCacheMaxEntries)
	}
	if n == 0 {
		t.Fatal("expected cache to retain entries")
	}
}

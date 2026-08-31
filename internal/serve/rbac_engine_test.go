// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

func sessionReqWithToken(ts *httptest.Server, token string) int {
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/session", nil)
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestEngineLoginTokenMemoryAuthoritative proves the hot token-auth path is
// served from the engine's resident token index: after the token row is deleted
// from the database out-of-band (like the previous per-request SELECT would have
// to discover), memory still authenticates the request. Logout then evicts the
// token from memory and the request is rejected.
func TestEngineLoginTokenMemoryAuthoritative(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	e := srv.Engine()
	if e == nil {
		t.Fatal("engine not enabled")
	}
	if _, err := e.GetToken(token); err != nil {
		t.Fatalf("engine should hold the login token: %v", err)
	}
	if n := e.Metrics().TokenIndexSize; n < 1 {
		t.Fatalf("token index size = %d, want >= 1", n)
	}

	// Out-of-band deletion in the DB must not break the memory path.
	if err := d.DeleteTokenByHash(db.TokenHash(token)); err != nil {
		t.Fatalf("db delete (out-of-band): %v", err)
	}
	if code := sessionReqWithToken(ts, token); code != http.StatusOK {
		t.Fatalf("memory token auth after DB row deleted = %d, want 200", code)
	}

	// Logout evicts from memory and DB.
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/users/logout", strings.NewReader(string(body)))
	req.Header.Set("X-Auth-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := e.GetToken(token); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("engine should evict token on logout, got err=%v", err)
	}
	if code := sessionReqWithToken(ts, token); code != http.StatusUnauthorized {
		t.Fatalf("session after logout = %d, want 401", code)
	}
}

// TestEngineOutOfBandUserFallback proves DB fallback keeps out-of-band accounts
// usable: a user created directly in the DB (no engine involvement) can still
// log in and authenticate through the memory engine after the login write.
func TestEngineOutOfBandUserFallback(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	if err := d.CreateUser("oob-user", db.HashPassword("secret", "saltx"), "saltx", "operator"); err != nil {
		t.Fatalf("out-of-band create user: %v", err)
	}
	// Confirm the engine has not seen this user.
	if _, err := srv.Engine().GetUserByUsername("oob-user"); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("engine should not hold out-of-band user, got err=%v", err)
	}

	bodyLogin, _ := json.Marshal(map[string]string{"username": "oob-user", "password": "secret"})
	resp, err := http.Post(ts.URL+"/api/v1/users/login", "application/json", strings.NewReader(string(bodyLogin)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	token, _ := r["token"].(string)
	if token == "" {
		t.Fatalf("login for DB-only user failed: %d", resp.StatusCode)
	}
	// The out-of-band account is not resident, so memory alone cannot resolve
	// the token (the owning user is missing from the user index); the wrapper
	// must fall back to the DB so the account stays usable immediately.
	if code := sessionReqWithToken(ts, token); code != http.StatusOK {
		t.Fatalf("session for out-of-band user = %d, want 200 via DB fallback", code)
	}
}

// TestEngineUpdateUserPasswordInvalidatesTokens verifies the write-through path
// for password rotation: DB tokens are cleared AND the engine memory copies the
// effect, so the old token stops authenticating from memory alone.
func TestEngineUpdateUserPasswordInvalidatesTokens(t *testing.T) {
	srv, d, h := newTestServerWithEngine(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdminWiring(t, ts)
	if token == "" {
		t.Fatal("login failed")
	}
	admin, err := d.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	e := srv.Engine()

	newHash := db.HashPassword("newpassword", "newsalt")
	if err := srv.updateUserPassword(admin.ID, newHash, "newsalt"); err != nil {
		t.Fatalf("updateUserPassword: %v", err)
	}
	if _, err := e.GetToken(token); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("engine should invalidate tokens on password change, got err=%v", err)
	}
	if u, err := e.GetUserByUsername("admin"); err != nil || u.PasswordHash != newHash {
		t.Fatalf("engine user password not refreshed: hash=%q err=%v", u.PasswordHash, err)
	}
	if code := sessionReqWithToken(ts, token); code != http.StatusUnauthorized {
		t.Fatalf("old token after password change = %d, want 401", code)
	}
	// Sanity: the DB side is invalidated too.
	if _, err := d.GetToken(token); err == nil {
		t.Fatal("DB should also clear tokens on password change")
	}
}

// TestEngineUserWriteThroughAPI verifies the API user create/delete path keeps
// the engine user index and token index in step with the backend.
func TestEngineUserWriteThroughAPI(t *testing.T) {
	srv, _, h := newTestServerWithEngine(t)
	fx := newMTLSAdminFixture(t, h, "ca:list", "user:list", "user:manage")
	e := srv.Engine()

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "secret", "role": "operator"})
	resp := authedMTLSPost(t, fx.Client, fx.Server, "/api/v1/users", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /users = %d, want 200", resp.StatusCode)
	}
	u, err := e.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("engine should hold API-created user: %v", err)
	}
	if u.Role != "operator" {
		t.Fatalf("created role = %q, want operator", u.Role)
	}

	delReq, _ := http.NewRequest("DELETE", fx.Server.URL+"/api/v1/users/"+strconv.Itoa(u.ID), nil)
	dresp, err := fx.Client.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /users/%d = %d, want 200", u.ID, dresp.StatusCode)
	}
	if _, err := e.GetUserByUsername("alice"); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("engine should evict deleted user, got err=%v", err)
	}
}

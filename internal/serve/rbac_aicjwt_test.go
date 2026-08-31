// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/types/aicjwt"
)

// aicjwtPrincipalUIDTest mirrors aicjwtPrincipalUID for test data: builds the
// DB username (communication-format principalUid) from realm/id/keyHash.
func aicjwtPrincipalUIDTest(realm, id string, keyHash []byte) string {
	return caPrincipalUIDString(realm, id, keyHash)
}

func caPrincipalUIDString(realm, id string, keyHash []byte) string {
	return realm + ":" + id + ":" + base64.RawURLEncoding.EncodeToString(keyHash)
}

func TestAuthFromAICJWT(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)

	keyHash := sha256.Sum256([]byte("principal-key-spki"))
	uid := aicjwtPrincipalUIDTest("r", "agent-a", keyHash[:])
	if err := d.CreateUser(uid, "h", "s", "viewer"); err != nil {
		t.Fatal(err)
	}

	result := &provisioner.AuthResult{
		AICJWT: &provisioner.AICJWTIdentity{
			Principal:    aicjwt.Principal{Realm: "r", ID: "agent-a", KeyHash: base64.RawURLEncoding.EncodeToString(keyHash[:]), HashAlg: "sha-256"},
			Issuer:       "varwof-core",
			TokenID:      "t1",
			Capabilities: []string{"std/database-v1:SELECT:*", "std/database-v1:INSERT:*"},
		},
	}

	user, err := srv.authResultToUser(result)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("authResultToUser returned nil for enabled principal")
	}
	if user.Username != uid {
		t.Fatalf("username = %q, want %q", user.Username, uid)
	}
	if len(user.Permissions) != 2 {
		t.Fatalf("permissions = %v, want 2 capabilities", user.Permissions)
	}
	if user.Permissions[0] != "std/database-v1:SELECT:*" {
		t.Fatalf("perm[0] = %q", user.Permissions[0])
	}
	if user.Role != "viewer(agent)" {
		t.Fatalf("role = %q, want viewer(agent)", user.Role)
	}
	if !user.HasPerm("std/database-v1:SELECT:*") {
		t.Fatal("HasPerm(SELECT:*) must be true for JWT capability")
	}
}

func TestAuthFromAICJWT_DisabledUser(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)

	keyHash := sha256.Sum256([]byte("disabled-principal"))
	uid := aicjwtPrincipalUIDTest("r", "disabled", keyHash[:])
	if err := d.CreateUser(uid, "h", "s", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE rbac_users SET enabled = 0 WHERE username = ?", uid); err != nil {
		t.Fatal(err)
	}

	user, err := srv.authResultToUser(&provisioner.AuthResult{
		AICJWT: &provisioner.AICJWTIdentity{
			Principal:    aicjwt.Principal{Realm: "r", ID: "disabled", KeyHash: base64.RawURLEncoding.EncodeToString(keyHash[:]), HashAlg: "sha-256"},
			Capabilities: []string{"std/database-v1:SELECT:*"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("disabled principal must fail closed, got user %q", user.Username)
	}
}

func TestAuthFromAICJWT_UnknownUser(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)

	user, err := srv.authResultToUser(&provisioner.AuthResult{
		AICJWT: &provisioner.AICJWTIdentity{
			Principal:    aicjwt.Principal{Realm: "r", ID: "ghost", KeyHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", HashAlg: "sha-256"},
			Capabilities: []string{"std/database-v1:SELECT:*"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("unknown principal must fail closed, got user %q", user.Username)
	}
}

func TestAICJWTProvisionerAuthenticate(t *testing.T) {
	srv, d, _ := newTestServerFull7(t)

	keyHash := sha256.Sum256([]byte("bearer-principal"))
	uid := aicjwtPrincipalUIDTest("r", "bearer", keyHash[:])
	if err := d.CreateUser(uid, "h", "s", "viewer"); err != nil {
		t.Fatal(err)
	}
	reg := provisioner.NewRegistry()
	if err := reg.Register(provisioner.NewAICJWTProvisioner()); err != nil {
		t.Fatal(err)
	}
	srv.SetProvisioners(reg)
	provisioner.SetAICJWTResolver(func(token string, r *http.Request) (*provisioner.AuthResult, error) {
		return &provisioner.AuthResult{
			AICJWT: &provisioner.AICJWTIdentity{
				Principal:    aicjwt.Principal{Realm: "r", ID: "bearer", KeyHash: base64.RawURLEncoding.EncodeToString(keyHash[:]), HashAlg: "sha-256"},
				Issuer:       "varwof-core",
				Capabilities: []string{"std/database-v1:SELECT:*"},
			},
		}, nil
	})
	defer provisioner.SetAICJWTResolver(nil)

	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	req.Header.Set("Authorization", "Bearer eyJ.fake.aicjwtsig")

	user, err := srv.authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("authenticate with Bearer AIC-JWT returned nil")
	}
	if user.Username != uid {
		t.Fatalf("username = %q, want %q", user.Username, uid)
	}
	if !user.HasPerm("std/database-v1:SELECT:*") {
		t.Fatal("user must carry the token capability")
	}
}

func TestAICJWTNoBearerFallsThrough(t *testing.T) {
	srv, _, _ := newTestServerFull7(t)
	reg := provisioner.NewRegistry()
	if err := reg.Register(provisioner.NewAICJWTProvisioner()); err != nil {
		t.Fatal(err)
	}
	srv.SetProvisioners(reg)
	defer provisioner.SetAICJWTResolver(nil)

	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	user, err := srv.authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("non-Bearer request must not authenticate as AIC-JWT, got %q", user.Username)
	}
}

// pemBytes is a tiny helper used by the resolver tests to keep PEM payloads.
func pemBytes(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
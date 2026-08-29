// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteIdentitySourceLookupExtra(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/lookup":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			switch body["username"] {
			case "alice":
				if body["source"] != "ssource" {
					t.Errorf("unexpected source %q", body["source"])
				}
				if r.Header.Get("Authorization") != "Bearer s3cret" {
					t.Errorf("missing bearer token")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"dn": "cn=alice", "staff_id": "A-100", "full_name": "Alice Liddell",
					"dept": "eng", "email": "alice@example.com", "source": "ads", "disabled": false,
					"groups": []string{"eng", "admins"},
				})
			case "notfound":
				w.WriteHeader(http.StatusNotFound)
			case "badreq":
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "bad source"})
			case "badreq2":
				w.WriteHeader(http.StatusBadRequest)
			case "broken":
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
			default:
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("not json"))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &IdentitySourceConfig{SourceURL: server.URL + "/", Token: "s3cret", Source: "ssource"}
	src, err := NewIdentitySource(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := src.Lookup(context.Background(), "", ""); err == nil {
		t.Fatal("empty username must error")
	}

	id, err := src.Lookup(context.Background(), "", "alice")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if id.Username != "A-100" || id.FullName != "Alice Liddell" || id.Source != "ads" || len(id.Groups) != 2 {
		t.Fatalf("unexpected identity: %+v", id)
	}

	if _, err := src.Lookup(context.Background(), "", "notfound"); err == nil {
		t.Fatal("404 must error")
	}
	if _, err := src.Lookup(context.Background(), "", "badreq"); err == nil {
		t.Fatal("400 with error must error")
	}
	if _, err := src.Lookup(context.Background(), "", "badreq2"); err == nil {
		t.Fatal("400 without error must error")
	}
	if _, err := src.Lookup(context.Background(), "", "broken"); err == nil {
		t.Fatal("500 must error")
	}
	if _, err := src.Lookup(context.Background(), "", "garbage"); err == nil {
		t.Fatal("bad json must error")
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := down.URL
	down.Close()
	deadCfg := &IdentitySourceConfig{SourceURL: addr}
	deadSrc, err := NewIdentitySource(deadCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deadSrc.Lookup(context.Background(), "", "alice"); err == nil {
		t.Fatal("network error must error")
	}
}

func TestIdentityBearerTokenNil(t *testing.T) {
	if got := identityBearerToken(nil); got != "" {
		t.Fatalf("nil cfg token must be empty, got %q", got)
	}
}

func TestOAuthIdentitySourceLookupExtra(t *testing.T) {
	userinfoMode := "ok"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/token":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["password"] != "pw" || body["username"] != "svc" {
				t.Errorf("unexpected automation creds: %+v", body)
			}
			if r.Header.Get("Authorization") != "Bearer s3cret" {
				t.Errorf("missing bearer token")
			}
			switch body["source"] {
			case "deny":
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "authentication failed"})
			case "deny2":
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{}`))
			default:
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-123"})
			}
		case "/api/v1/userinfo":
			w.Header().Set("Content-Type", "application/json")
			switch userinfoMode {
			case "gone":
				w.WriteHeader(http.StatusNotFound)
			case "broken":
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "upstream down"})
			case "garbage":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("not json"))
			default:
				json.NewEncoder(w).Encode(map[string]interface{}{
					"sub": "S-9", "username": "Bob", "full_name": "Bob Roberts",
					"email": "bob@example.com", "source": "idp", "groups": []string{"ops"},
				})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &IdentitySourceConfig{
		Type: IdentitySourceOAuth, SourceURL: server.URL + "/", Token: "s3cret",
		Source: "provision", Username: "svc", Password: "pw",
	}
	src, err := NewIdentitySource(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := src.Lookup(context.Background(), "", ""); err == nil {
		t.Fatal("empty username must error")
	}

	id, err := src.Lookup(context.Background(), "", "bob")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if id.Username != "Bob" || id.Source != "idp" {
		t.Fatalf("unexpected identity: %+v", id)
	}

	for _, m := range []string{"gone", "broken", "garbage"} {
		userinfoMode = m
		if _, err := src.Lookup(context.Background(), "", "bob"); err == nil {
			t.Fatalf("userinfo %q must error", m)
		}
	}

	noCreds := &IdentitySourceConfig{Type: IdentitySourceOAuth, SourceURL: server.URL}
	noCredsSrc, err := NewIdentitySource(noCreds)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCredsSrc.Lookup(context.Background(), "", "bob"); err == nil {
		t.Fatal("missing automation creds must error")
	}

	denyCfg := &IdentitySourceConfig{Type: IdentitySourceOAuth, SourceURL: server.URL, Source: "deny", Username: "svc", Password: "pw", Token: "s3cret"}
	denySrc, _ := NewIdentitySource(denyCfg)
	if _, err := denySrc.Lookup(context.Background(), "", "bob"); err == nil {
		t.Fatal("token error must propagate")
	}

	deny2Cfg := &IdentitySourceConfig{Type: IdentitySourceOAuth, SourceURL: server.URL, Source: "deny2", Username: "svc", Password: "pw", Token: "s3cret"}
	deny2Src, _ := NewIdentitySource(deny2Cfg)
	if _, err := deny2Src.Lookup(context.Background(), "", "bob"); err == nil {
		t.Fatal("token empty error must propagate")
	}
}

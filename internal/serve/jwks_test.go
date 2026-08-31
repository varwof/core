// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/varwof/core/internal/ca"
)

func TestServeJWKS(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	cfg := srv.getConfig()
	var caName string
	var certPath, keyPath string
	for name, c := range cfg.CAs {
		caName, certPath, keyPath = name, c.Cert, c.Key
	}
	if caName == "" || certPath == "" || keyPath == "" {
		t.Fatal("test server has no CA configured")
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var jwks ca.JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("json decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("jwks has zero keys")
	}

	issuerCert, _, err := ca.LoadSigner(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	want, err := ca.CertToJWK(issuerCert)
	if err != nil {
		t.Fatalf("CertToJWK: %v", err)
	}

	found := false
	for _, k := range jwks.Keys {
		if k.Kid == want.Kid {
			found = true
			if len(k.X5c) == 0 || k.Use != "sig" {
				t.Fatalf("jwk missing x5c/use: %+v", k)
			}
		}
	}
	if !found {
		t.Fatalf("jwks missing CA kid %q (keys: %d)", want.Kid, len(jwks.Keys))
	}
}

func TestServeJWKSMethodNotAllowed(t *testing.T) {
	srv, handler := newTestServerWithDB(t)
	_ = srv
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestServeJWKSReachableUnauthenticated(t *testing.T) {
	_, handler := newTestServerWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("public jwks endpoint requires auth: %d", rr.Code)
	}
}

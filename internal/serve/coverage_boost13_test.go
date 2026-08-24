package serve

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/varwof/core/auth"
	"golang.org/x/time/rate"
)

// ─── Red line #4: ACL / RBAC ─────────────────────────────────────

func TestAuthScopesCacheEvictionFull(t *testing.T) {
	authScopesMu.Lock()
	authScopesCache = make(map[string]authScopesEntry)
	for i := 0; i < authScopesCacheMaxEntries; i++ {
		authScopesCache[fmt.Sprintf("k%d", i)] = authScopesEntry{scopes: []string{"S"}, exp: time.Now().Add(time.Minute)}
	}
	// one expired entry so the eviction loop actually deletes something
	authScopesCache["expired-key"] = authScopesEntry{scopes: []string{"S"}, exp: time.Now().Add(-time.Minute)}
	authScopesMu.Unlock()

	rememberAuthScopes("overflow-user", []string{"Z"})

	authScopesMu.Lock()
	_, added := authScopesCache["overflow-user"]
	_, expiredGone := authScopesCache["expired-key"]
	authScopesCache = nil
	authScopesMu.Unlock()

	if added {
		t.Fatal("expected overflow-user to be rejected when cache stays full after eviction")
	}
	if expiredGone {
		t.Fatal("expected expired entry to be evicted")
	}
}

func TestPermissionRolesWithAndWithoutPolicy(t *testing.T) {
	srv, _, _, _ := newTestServerWithCA(t)

	prev := auth.GetPolicy()
	defer auth.SetPolicy(prev)

	p, err := auth.LoadPolicyData([]byte(`{
		"version": "v2",
		"roles": {
			"admin": {"grants": ["ca:list", "cert:issue"], "ou": ["admin"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	auth.SetPolicy(p)

	w := httptest.NewRecorder()
	srv.apiPermissionRoles(w, httptest.NewRequest("GET", "/api/v1/permissions/roles", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("with policy: expected 200, got %d", w.Code)
	}
	if !jsonBodyHas(w, "permissions") {
		t.Fatalf("with policy: body missing permissions: %s", w.Body.String())
	}

	// no policy → hardcoded fallback matrix
	auth.SetPolicy(nil)
	w2 := httptest.NewRecorder()
	srv.apiPermissionRoles(w2, httptest.NewRequest("GET", "/api/v1/permissions/roles", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("without policy: expected 200, got %d", w2.Code)
	}
	if !jsonBodyHas(w2, "permissions") {
		t.Fatalf("without policy: body missing permissions: %s", w2.Body.String())
	}
}

// ─── ratelimit cleanup ─────────────────────────────────────────────

func TestRateLimiterCleanup(t *testing.T) {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Limit(1),
		burst:    1,
	}
	rl.visitors["stale"] = &visitor{limiter: rate.NewLimiter(1, 1), lastSeen: time.Now().Add(-2 * time.Minute)}
	rl.visitors["fresh"] = &visitor{limiter: rate.NewLimiter(1, 1), lastSeen: time.Now()}

	go rl.cleanup(10 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	rl.mu.Lock()
	_, staleGone := rl.visitors["stale"]
	_, freshStill := rl.visitors["fresh"]
	rl.mu.Unlock()

	if staleGone {
		t.Fatal("expected stale visitor to be cleaned up")
	}
	if !freshStill {
		t.Fatal("expected fresh visitor to survive cleanup")
	}
}

// ─── api_subca.parsePrivateKey ─────────────────────────────────────

func TestParsePrivateKeyServe(t *testing.T) {
	// no PEM block
	if _, err := parsePrivateKey([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage input")
	}

	// PKCS8
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := parsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	if parsed == nil {
		t.Fatal("PKCS8: nil signer")
	}

	// EC PRIVATE KEY fallback
	ecDer, _ := x509.MarshalECPrivateKey(ecKey)
	pemData2 := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDer})
	if _, err := parsePrivateKey(pemData2); err != nil {
		t.Fatalf("EC: %v", err)
	}

	// RSA PKCS1 fallback
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemData3 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaDER})
	if _, err := parsePrivateKey(pemData3); err != nil {
		t.Fatalf("RSA PKCS1: %v", err)
	}

	// unsupported: valid PEM block but not a private key
	pemData4 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})
	if _, err := parsePrivateKey(pemData4); err == nil {
		t.Fatal("expected error for unsupported key format")
	}
}

// ─── api_upload.keyInfo ────────────────────────────────────────────

func TestKeyInfo(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo, size := keyInfo(&rsaKey.PublicKey); algo != "RSA" || size != 2048 {
		t.Fatalf("RSA: got %s/%d", algo, size)
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if algo, size := keyInfo(&ecKey.PublicKey); algo != "ECDSA" || size != 256 {
		t.Fatalf("ECDSA: got %s/%d", algo, size)
	}
	if algo, size := keyInfo(ed25519Pub()); algo != "Ed25519" || size != 256 {
		t.Fatalf("Ed25519: got %s/%d", algo, size)
	}
	if algo, size := keyInfo(42); algo != "Unknown" || size != 0 {
		t.Fatalf("Unknown: got %s/%d", algo, size)
	}
}

func ed25519Pub() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub
}

func jsonBodyHas(w *httptest.ResponseRecorder, key string) bool {
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

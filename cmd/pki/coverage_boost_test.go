package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func TestResolveConfigPath(t *testing.T) {
	if got := resolveConfigPath("/tmp/explicit.json"); got != "/tmp/explicit.json" {
		t.Fatalf("explicit: %q", got)
	}
	if got := resolveConfigPath(""); got == "" {
		t.Fatal("expected non-empty default")
	}
}

func TestReadWriteRawConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")

	if _, err := readRawConfig(path); err == nil {
		t.Fatal("expected error for missing config")
	}

	if err := writeRawConfig(path, map[string]interface{}{"defaults": map[string]interface{}{"org": "acme"}}); err != nil {
		t.Fatal(err)
	}
	cfgMap, err := readRawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfgMap["defaults"] == nil {
		t.Fatal("roundtrip lost data")
	}

	// writeRawConfig on bad value → marshal error
	ch := make(chan int)
	if err := writeRawConfig(path, map[string]interface{}{"x": ch}); err == nil {
		t.Fatal("expected marshal error")
	}

	// writeFileAtomic error path (bad perm dir)
	if err := writeFileAtomic(filepath.Join(dir, "nodir", "f"), []byte("x"), 0644); err == nil {
		t.Fatal("expected write error")
	}

	// requireWriteConfig
	configPath = ""
	if _, err := requireWriteConfig(); err == nil {
		t.Fatal("expected error when configPath empty")
	}
	configPath = path
	if got, err := requireWriteConfig(); err != nil || got != path {
		t.Fatalf("requireWriteConfig: %q %v", got, err)
	}
}

func TestSplitCSV(t *testing.T) {
	if splitCSV("") != nil {
		t.Fatal("empty should return nil")
	}
	got := splitCSV(" a , b,, c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestParseBasicAuth(t *testing.T) {
	if _, _, ok := parseBasicAuth("!!not-base64!!"); ok {
		t.Fatal("expected decode failure")
	}
	if _, _, ok := parseBasicAuth(base64.StdEncoding.EncodeToString([]byte("nocolon"))); ok {
		t.Fatal("expected no-colon failure")
	}
	u, p, ok := parseBasicAuth(base64.StdEncoding.EncodeToString([]byte("user:pw:extra")))
	if !ok || u != "user" || p != "pw:extra" {
		t.Fatalf("unexpected: %q %q %v", u, p, ok)
	}
}

func TestParseAgentSessionMaxTTL(t *testing.T) {
	if got := parseAgentSessionMaxTTL(""); got != 24*3600_000_000_000 {
		t.Fatalf("empty should default 24h, got %v", got)
	}
	if got := parseAgentSessionMaxTTL("bogus"); got != 24*3600_000_000_000 {
		t.Fatalf("invalid should default 24h, got %v", got)
	}
	if got := parseAgentSessionMaxTTL("1h"); got != 3600_000_000_000 {
		t.Fatalf("expected 1h, got %v", got)
	}
}

func TestInitLogFormat(t *testing.T) {
	initLogFormat("json", "", true)
	initLogFormat("json-flag", "stderr", false)
	initLogFormat("text", "file:/tmp/pki-test-log.log", true)
	initLogFormat("anything", "syslog", false)
	initLogFormat("text", "bogus-target", false)
}

func TestSetShutdownTimeout(t *testing.T) {
	setShutdownTimeout(nil)
	cfg := &internal.Config{}
	cfg.Serve.ShutdownTimeout = "5s"
	setShutdownTimeout(cfg)
	if shutdownTimeout != 5*1_000_000_000 {
		t.Fatalf("expected 5s, got %v", shutdownTimeout)
	}
	cfg.Serve.ShutdownTimeout = "garbage"
	setShutdownTimeout(cfg)
	if shutdownTimeout != 5*1_000_000_000 {
		t.Fatalf("garbage should be ignored, got %v", shutdownTimeout)
	}
}

func TestCopyAndShredFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(dst)
	if string(data) != "hello" {
		t.Fatalf("copy mismatch: %q", data)
	}
	if err := copyFile(filepath.Join(dir, "missing"), dst); err == nil {
		t.Fatal("expected copy error")
	}

	// shredFile overwrites + removes
	if err := shredFile(dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("file should be removed")
	}
	if err := shredFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected shred error for missing file")
	}
}

func TestPrintJSONAndTrunc(t *testing.T) {
	if err := printJSON(map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if err := printJSON(make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}

	if got := truncStr("hello", 3); got != "hel" {
		t.Fatalf("trunc: %q", got)
	}
	if got := truncStr("ab", 5); got != "ab" {
		t.Fatalf("no trunc: %q", got)
	}
}

func TestPwdAsPKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if len(pwdAsPKCS8(key)) == 0 {
		t.Fatal("expected DER output")
	}
	if pwdAsPKCS8(struct{ x int }{}) != nil {
		t.Fatal("expected nil for unsupported type")
	}
}

func TestParseCertPEMHelper(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := parseCertPEM(pemBytes)
	if err != nil || cert == nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if _, err := parseCertPEM([]byte("junk")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestGetRolePerms(t *testing.T) {
	d := newTestDB(t)

	// fallback (no policy): admin role
	perms := getRolePerms("admin", d)
	if len(perms) == 0 {
		t.Fatal("expected non-empty perms for admin")
	}

	// policy branch
	pol, err := auth.LoadPolicyData([]byte(`{
		"version": "v2",
		"roles": {
			"admin": {"display_name": "Admin", "profiles": ["m-admin"], "grants": ["cert:list"]}
		},
		"ou_mapping": {"gateway:admin": "admin"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	auth.SetPolicy(pol)
	defer auth.SetPolicy(nil)
	if got := getRolePerms("admin", d); len(got) != 1 || got[0] != "cert:list" {
		t.Fatalf("policy perms: %v", got)
	}
	if got := getRolePerms("ghost-role", d); got != nil {
		t.Fatalf("expected nil for unknown role, got %v", got)
	}
}

func TestResolveAPIToken(t *testing.T) {
	d := newTestDB(t)
	salt := "testsalt"
	if err := d.CreateUser("apiuser", db.HashPassword("pw", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}
	u, err := d.GetUserByUsername("apiuser")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := d.CreateAPIToken(u.ID, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateUserCAScopes(u.ID, "issuing-ca"); err != nil {
		t.Fatal(err)
	}

	res, err := resolveAPIToken(tok.Token, d)
	if err != nil || res == nil {
		t.Fatalf("resolveAPIToken: %v", err)
	}
	if res.Username != "apiuser" || res.Role != "admin" {
		t.Fatalf("unexpected: %+v", res)
	}
	foundScope := false
	for _, p := range res.Permissions {
		if strings.HasPrefix(p, "cas:scope:") {
			foundScope = true
		}
	}
	if !foundScope {
		t.Fatalf("expected ca scope permission, got %v", res.Permissions)
	}

	if res2, _ := resolveAPIToken("nope", d); res2 != nil {
		t.Fatal("expected nil for unknown token")
	}
}

func TestResolveBasicAuth(t *testing.T) {
	d := newTestDB(t)
	user := fmt.Sprintf("bob-%d", time.Now().UnixNano())
	salt := fmt.Sprintf("bassalt-%d", time.Now().UnixNano())
	if err := d.CreateUser(user, db.HashPassword("s3cret", salt), salt, "admin"); err != nil {
		t.Fatal(err)
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(user + ":s3cret"))

	// malformed header
	if r, _ := resolveBasicAuth("no-space", d); r != nil {
		t.Fatal("expected nil for malformed header")
	}
	// bad base64
	if r, _ := resolveBasicAuth("Basic %%", d); r != nil {
		t.Fatal("expected nil for bad base64")
	}
	// unknown user
	if r, _ := resolveBasicAuth("Basic "+base64.StdEncoding.EncodeToString([]byte("ghost:x")), d); r != nil {
		t.Fatal("expected nil for unknown user")
	}
	// wrong password
	if r, _ := resolveBasicAuth("Basic "+base64.StdEncoding.EncodeToString([]byte(user+":wrong")), d); r != nil {
		t.Fatal("expected nil for wrong password")
	}

	// success path
	res, err := resolveBasicAuth(header, d)
	if err != nil || res == nil || res.Username != user {
		t.Fatalf("resolveBasicAuth: %+v %v", res, err)
	}
	// second call hits the basic-auth cache path
	res2, _ := resolveBasicAuth(header, d)
	if res2 == nil {
		t.Fatal("expected cached auth")
	}

	// disabled user
	if _, err := d.Exec("UPDATE rbac_users SET enabled = 0 WHERE username = ?", user); err != nil {
		t.Fatal(err)
	}
	if r, _ := resolveBasicAuth(header, d); r != nil {
		t.Fatal("expected nil for disabled user")
	}
}

func TestRevocationCacheInvalidators(t *testing.T) {
	// populate the cache
	rememberRevocationStatus("issuer\x00serial1", true)
	if revoked, ok := cachedRevocationStatus("issuer\x00serial1"); !ok || !revoked {
		t.Fatal("expected cached revoked entry")
	}

	invalidateRevocationCache("issuer", "serial1")
	if _, ok := cachedRevocationStatus("issuer\x00serial1"); ok {
		t.Fatal("expected cache miss after invalidateRevocationCache")
	}

	rememberRevocationStatus("issuer\x00serial2", true)
	rememberRevocationStatus("other\x00serial2", true)
	invalidateRevocationBySerial("serial2")
	if _, ok := cachedRevocationStatus("issuer\x00serial2"); ok {
		t.Fatal("expected miss after invalidateRevocationBySerial")
	}
	if _, ok := cachedRevocationStatus("other\x00serial2"); ok {
		t.Fatal("expected miss for other issuer too")
	}

	rememberRevocationStatus("issuer\x00serial3", true)
	clearRevocationCache()
	if _, ok := cachedRevocationStatus("issuer\x00serial3"); ok {
		t.Fatal("expected miss after clear")
	}

	// expired-entry branch
	rememberRevocationStatus("issuer\x00expired", true)
	revocationMu.Lock()
	revocationCache["issuer\x00expired"] = revocationEntry{revoked: true, exp: time.Now().Add(-time.Second)}
	revocationMu.Unlock()
	if _, ok := cachedRevocationStatus("issuer\x00expired"); ok {
		t.Fatal("expected expired entry to be dropped")
	}

	// eviction branch: max entries with only one expired → new entry evicts it
	revocationMu.Lock()
	revocationCache = make(map[string]revocationEntry)
	for i := 0; i < revocationCacheMaxEntries-1; i++ {
		revocationCache[revocationCacheKey("e", fmt.Sprintf("%d", i))] = revocationEntry{revoked: false, exp: time.Now().Add(time.Hour)}
	}
	revocationCache[revocationCacheKey("e", "expired")] = revocationEntry{revoked: false, exp: time.Now().Add(-time.Hour)}
	revocationMu.Unlock()
	rememberRevocationStatus("issuer\x00overflow", true)
	if _, ok := cachedRevocationStatus("issuer\x00overflow"); !ok {
		t.Fatal("expected overflow entry stored after evicting expired")
	}
	if _, ok := cachedRevocationStatus(revocationCacheKey("e", "expired")); ok {
		t.Fatal("expected expired entry evicted")
	}
}



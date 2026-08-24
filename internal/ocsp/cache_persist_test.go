package ocsp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ocsp-cache.json")

	c := NewCache(100, time.Hour)
	c.SetWithSerial("k1", "SERIAL1", []byte("resp1"))
	c.SetWithSerial("k2", "SERIAL2", []byte("resp2"))
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2 := NewCache(100, time.Hour)
	if err := c2.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if c2.Len() != 2 {
		t.Fatalf("expected 2 entries after load, got %d", c2.Len())
	}
	got, ok := c2.Get("k1")
	if !ok || string(got) != "resp1" {
		t.Fatalf("k1 after load: %q ok=%v", got, ok)
	}
	got, ok = c2.Get("k2")
	if !ok || string(got) != "resp2" {
		t.Fatalf("k2 after load: %q ok=%v", got, ok)
	}
	// serial index restored → purge works after load
	c2.PurgeSerial("SERIAL1")
	if _, ok := c2.Get("k1"); ok {
		t.Fatal("k1 should be purged after load")
	}
	if _, ok := c2.Get("k2"); !ok {
		t.Fatal("k2 should survive serial purge")
	}
}

func TestCacheSaveLoadExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ocsp-cache.json")

	c := NewCache(100, time.Hour)
	c.SetWithSerial("k1", "S1", []byte("resp1"))
	c.mu.Lock()
	c.entries["k1"].Value.(*cacheEntry).expiresAt = time.Now().Add(-time.Minute)
	c.mu.Unlock()
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2 := NewCache(100, time.Hour)
	if err := c2.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if c2.Len() != 0 {
		t.Fatalf("expired entries should not survive save/load, got %d", c2.Len())
	}
}

func TestCacheLoadMissingFile(t *testing.T) {
	c := NewCache(10, time.Hour)
	if err := c.Load(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Fatalf("missing file should be a no-op, got %v", err)
	}
}

func TestCacheSaveAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ocsp-cache.json")

	c := NewCache(10, time.Hour)
	c.Set("k", []byte("v"))
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	// No .tmp residue after successful rename.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no .tmp residue, err=%v", err)
	}
}

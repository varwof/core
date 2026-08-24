// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ocsp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestCacheGetSet(t *testing.T) {
	c := NewCache(10, 5*time.Minute)

	got, ok := c.Get("missing")
	if ok {
		t.Fatal("expected miss for missing key")
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	c.Set("key1", []byte("value1"))
	got, ok = c.Get("key1")
	if !ok {
		t.Fatal("expected hit for key1")
	}
	if string(got) != "value1" {
		t.Fatalf("expected 'value1', got %q", string(got))
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := NewCache(10, 5*time.Minute)

	c.Set("k", []byte("v1"))
	c.Set("k", []byte("v2"))

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected hit")
	}
	if string(got) != "v2" {
		t.Fatalf("expected 'v2', got %q", string(got))
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(2, 5*time.Minute)

	c.Set("a", []byte("1"))
	c.Set("b", []byte("2"))
	c.Set("c", []byte("3"))

	// "a" should be evicted (first inserted)
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted")
	}

	// b and c should still exist
	for _, k := range []string{"b", "c"} {
		_, ok := c.Get(k)
		if !ok {
			t.Fatalf("expected %q to exist", k)
		}
	}
}

func TestCacheEvictionOrder(t *testing.T) {
	c := NewCache(3, 5*time.Minute)

	c.Set("a", []byte("1"))
	time.Sleep(1 * time.Millisecond)
	c.Set("b", []byte("2"))
	time.Sleep(1 * time.Millisecond)
	c.Set("c", []byte("3"))

	// Overwrite "b" to update its expiry
	c.Set("b", []byte("22"))

	// Now add "d" — "a" should be evicted (oldest insertion)
	c.Set("d", []byte("4"))

	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted (oldest)")
	}

	for _, k := range []string{"b", "c", "d"} {
		_, ok := c.Get(k)
		if !ok {
			t.Fatalf("expected %q to exist", k)
		}
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache(10, 50*time.Millisecond)

	c.Set("e", []byte("expiring"))

	time.Sleep(20 * time.Millisecond)
	_, ok := c.Get("e")
	if !ok {
		t.Fatal("expected hit before expiry")
	}

	time.Sleep(50 * time.Millisecond)
	_, ok = c.Get("e")
	if ok {
		t.Fatal("expected miss after expiry")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache(100, time.Minute)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := string(rune('a' + n))
			c.Set(key, []byte{byte(n)})
			_, _ = c.Get(key)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCacheZeroMaxSize(t *testing.T) {
	c := NewCache(0, time.Minute)

	// With maxSize=0, every new key immediately evicts the oldest,
	// but the new key itself is still stored.
	c.Set("x", []byte("1"))
	v, ok := c.Get("x")
	if !ok {
		t.Fatal("expected hit for x (item is stored)")
	}
	if string(v) != "1" {
		t.Fatalf("expected '1', got %q", string(v))
	}
}

func TestCacheEvictionWithZeroMaxSize(t *testing.T) {
	c := NewCache(0, time.Minute)

	c.Set("a", []byte("1"))
	c.Set("b", []byte("2"))
	c.Set("c", []byte("3"))

	// "a" should be evicted (oldest)
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted when maxSize=0")
	}

	// "c" should exist (most recently added)
	_, ok = c.Get("c")
	if !ok {
		t.Fatal("expected 'c' to exist")
	}
}

func TestCacheKey(t *testing.T) {
	req := []byte("test request")
	key := cacheKey(req)
	h := sha256.Sum256(req)
	expected := hex.EncodeToString(h[:])
	if key != expected {
		t.Fatalf("cacheKey: expected %q, got %q", expected, key)
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	k1 := cacheKey([]byte("same input"))
	k2 := cacheKey([]byte("same input"))
	if k1 != k2 {
		t.Fatal("cacheKey should be deterministic")
	}
}

func TestCacheKeyDiffInput(t *testing.T) {
	k1 := cacheKey([]byte("input A"))
	k2 := cacheKey([]byte("input B"))
	if bytes.Equal([]byte(k1), []byte(k2)) {
		t.Fatal("different inputs should produce different keys")
	}
}

func TestSetCache(t *testing.T) {
	h := &Handler{}
	c := NewCache(10, time.Minute)
	h.SetCache(c)
	if h.cache != c {
		t.Fatal("SetCache did not set handler cache")
	}
}

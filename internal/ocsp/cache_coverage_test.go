package ocsp

import (
	"testing"
	"time"
)

func TestCachePurgeSerial(t *testing.T) {
	c := NewCache(10, time.Minute)

	c.SetWithSerial("k1", "AAA", []byte("1"))
	c.SetWithSerial("k2", "AAA", []byte("2"))
	c.SetWithSerial("k3", "BBB", []byte("3"))

	// unknown serial → no-op
	c.PurgeSerial("ZZZ")
	if _, ok := c.Get("k3"); !ok {
		t.Fatal("expected k3 to remain")
	}

	// purge all entries carrying serial AAA
	c.PurgeSerial("AAA")
	for _, k := range []string{"k1", "k2"} {
		if _, ok := c.Get(k); ok {
			t.Fatalf("expected %q to be purged", k)
		}
	}
	if _, ok := c.Get("k3"); !ok {
		t.Fatal("expected k3 to remain")
	}

	// serialKeys fully cleaned → second purge is a no-op
	c.PurgeSerial("AAA")
	c.PurgeSerial("BBB")
	for _, k := range []string{"k3"} {
		if _, ok := c.Get(k); ok {
			t.Fatal("expected k3 to be purged")
		}
	}
	if len(c.serialKeys) != 0 {
		t.Fatalf("expected empty serialKeys, got %d", len(c.serialKeys))
	}
}

func TestCacheEvictionCleansSerialKey(t *testing.T) {
	c := NewCache(1, time.Minute)

	// each SetWithSerial evicts the previous entry → removeLocked must clean serialKeys
	c.SetWithSerial("k1", "AAA", []byte("1"))
	c.SetWithSerial("k2", "BBB", []byte("2"))
	c.SetWithSerial("k3", "CCC", []byte("3"))

	for _, s := range []string{"AAA", "BBB"} {
		if _, ok := c.serialKeys[s]; ok {
			t.Fatalf("expected serial %q cleaned from serialKeys after eviction", s)
		}
	}
	if _, ok := c.serialKeys["CCC"]; !ok {
		t.Fatal("expected serial CCC still tracked")
	}

	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected k1 evicted")
	}
	if _, ok := c.Get("k3"); !ok {
		t.Fatal("expected k3 present")
	}
}

func TestCacheExpiryCleansSerialKey(t *testing.T) {
	c := NewCache(10, 30*time.Millisecond)

	c.SetWithSerial("k1", "AAA", []byte("1"))

	time.Sleep(50 * time.Millisecond)
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected k1 expired")
	}
	if _, ok := c.serialKeys["AAA"]; ok {
		t.Fatal("expected serial AAA cleaned after expiry")
	}
}

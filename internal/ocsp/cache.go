package ocsp

import (
	"container/list"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Cache struct {
	mu          sync.RWMutex
	entries     map[string]*list.Element
	serialKeys  map[string]map[string]struct{} // serial → set of cache keys
	order       *list.List
	maxSize     int
	ttl         time.Duration
}

type cacheEntry struct {
	key       string
	serial    string
	data      []byte
	expiresAt time.Time
}

func NewCache(maxSize int, ttl time.Duration) *Cache {
	return &Cache{
		entries:    make(map[string]*list.Element),
		serialKeys: make(map[string]map[string]struct{}),
		order:      list.New(),
		maxSize:    maxSize,
		ttl:        ttl,
	}
}

func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.removeLocked(elem)
		return nil, false
	}
	c.order.MoveToFront(elem)
	return entry.data, true
}

func (c *Cache) Set(key string, data []byte) {
	c.SetWithSerial(key, "", data)
}

func (c *Cache) SetWithSerial(key, serial string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.data = data
		entry.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(elem)
		return
	}

	if c.order.Len() >= c.maxSize {
		back := c.order.Back()
		if back != nil {
			c.removeLocked(back)
		}
	}

	entry := &cacheEntry{
		key:       key,
		serial:    serial,
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	elem := c.order.PushFront(entry)
	c.entries[key] = elem

	if serial != "" {
		if _, ok := c.serialKeys[serial]; !ok {
			c.serialKeys[serial] = make(map[string]struct{})
		}
		c.serialKeys[serial][key] = struct{}{}
	}
}

func (c *Cache) PurgeSerial(serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys, ok := c.serialKeys[serial]
	if !ok {
		return
	}
	for key := range keys {
		if elem, ok := c.entries[key]; ok {
			c.order.Remove(elem)
			delete(c.entries, key)
		}
	}
	delete(c.serialKeys, serial)
}

func (c *Cache) removeLocked(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	c.order.Remove(elem)
	delete(c.entries, entry.key)
	if entry.serial != "" {
		if keys, ok := c.serialKeys[entry.serial]; ok {
			delete(keys, entry.key)
			if len(keys) == 0 {
				delete(c.serialKeys, entry.serial)
			}
		}
	}
}

// cacheDump is the on-disk representation of the cache, allowing OCSP nodes
// to persist (and share) verified responses across restarts so a cold node
// does not immediately hammer the shared CA database (stateless OCSP node).
type cacheDump struct {
	SavedAt  time.Time `json:"saved_at"`
	Entries  []cacheEntryJSON `json:"entries"`
}

type cacheEntryJSON struct {
	Key       string    `json:"key"`
	Serial    string    `json:"serial,omitempty"`
	Data      []byte    `json:"data"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Save serializes the cache (only unexpired entries) to path. It is safe to
// call concurrently; stale bytes on disk are overwritten atomically.
func (c *Cache) Save(path string) error {
	c.mu.Lock()
	dump := cacheDump{SavedAt: time.Now().UTC()}
	for _, elem := range c.orderListSnapshot() {
		e := elem.Value.(*cacheEntry)
		if time.Now().After(e.expiresAt) {
			continue
		}
		dump.Entries = append(dump.Entries, cacheEntryJSON{
			Key:       e.key,
			Serial:    e.serial,
			Data:      e.data,
			ExpiresAt: e.expiresAt,
		})
	}
	c.mu.Unlock()

	raw, err := json.Marshal(dump)
	if err != nil {
		return fmt.Errorf("marshal cache dump: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write cache dump: %w", err)
	}
	return os.Rename(tmp, path)
}

// orderListSnapshot returns the elements of the LRU list in order. Callers
// must hold c.mu (or copy under the lock, as Save does).
func (c *Cache) orderListSnapshot() []*list.Element {
	var out []*list.Element
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		out = append(out, elem)
	}
	return out
}

// Load reads a previously persisted dump into the cache. Expired entries are
// dropped. Errors (missing file, corrupt JSON) are reported to the caller so
// the server can decide whether to fail or continue with an empty cache.
func (c *Cache) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read cache dump: %w", err)
	}
	var dump cacheDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return fmt.Errorf("parse cache dump: %w", err)
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range dump.Entries {
		if e.ExpiresAt.Before(now) || e.Key == "" || len(e.Data) == 0 {
			continue
		}
		entry := &cacheEntry{
			key:       e.Key,
			serial:    e.Serial,
			data:      e.Data,
			expiresAt: e.ExpiresAt,
		}
		elem := c.order.PushFront(entry)
		c.entries[e.Key] = elem
		if e.Serial != "" {
			if _, ok := c.serialKeys[e.Serial]; !ok {
				c.serialKeys[e.Serial] = make(map[string]struct{})
			}
			c.serialKeys[e.Serial][e.Key] = struct{}{}
		}
	}
	return nil
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

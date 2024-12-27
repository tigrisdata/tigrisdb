package kv

import (
	"sync"
	"time"
)

// TTLCache extends LRUCache to support TTL
type TTLCache struct {
	cache     *LRUCache
	expiries  map[string]time.Time
	mu        sync.Mutex
	ttlWorker *time.Ticker
}

// NewTTLCache creates a TTL-enabled cache
func NewTTLCache(capacity int, cleanupInterval time.Duration) *TTLCache {
	c := &TTLCache{
		cache:     NewLRUCache(capacity),
		expiries:  make(map[string]time.Time),
		ttlWorker: time.NewTicker(cleanupInterval),
	}

	go c.cleanup()
	return c
}

// Put adds an item with TTL
func (c *TTLCache) Put(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := time.Now().Add(ttl)
	c.cache.Put(key, value)
	c.expiries[key] = expiry
}

// Get retrieves an item, checking TTL
func (c *TTLCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if expiry, exists := c.expiries[key]; exists {
		if time.Now().After(expiry) {
			// Item expired, remove it
			c.cache.Remove(key)
			delete(c.expiries, key)
			return nil, false
		}
	}
	return c.cache.Get(key)
}

// Cleanup removes expired items
func (c *TTLCache) cleanup() {
	for range c.ttlWorker.C {
		c.mu.Lock()
		for key, expiry := range c.expiries {
			if time.Now().After(expiry) {
				c.cache.Remove(key)
				delete(c.expiries, key)
			}
		}
		c.mu.Unlock()
	}
}


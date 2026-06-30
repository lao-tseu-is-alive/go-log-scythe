// Package cache provides an in-memory LRU cache for tracking visitors
// (IP addresses that have generated suspicious HTTP activity).
//
// The cache is bounded and automatically evicts least-recently-used
// entries when it reaches capacity. It is safe for concurrent use.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// Visitor represents a single IP address being tracked by the system.
//
// It accumulates a threat score over time and records which paths
// it has requested (used for repeat-penalty logic). It also keeps
// a sliding window of 4xx timestamps for burst detection.
type Visitor struct {
	IP       string
	Score    float64         // Cumulative danger score
	Paths    map[string]bool // Distinct paths seen (for repeat penalty)
	HitTimes []time.Time     // Timestamps of recent 4xx responses (for burst detection)
	LastSeen time.Time
}

// LRUCache is a thread-safe, bounded cache using the Least-Recently-Used
// eviction policy.
//
// All public methods are safe for concurrent callers.
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	items    map[string]*list.Element
	order    *list.List // Front = most recently used
}

// entry is the value stored in the linked list.
type entry struct {
	key   string
	value *Visitor
}

// NewLRUCache creates a new LRU cache with the given maximum capacity.
func NewLRUCache(capacity int) *LRUCache {
	if capacity <= 0 {
		capacity = 1000
	}
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Get retrieves a visitor. It marks the entry as recently used.
func (c *LRUCache) Get(ip string) (*Visitor, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[ip]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*entry).value, true
	}
	return nil, false
}

// Put inserts or updates a visitor and marks it as most recently used.
// If the cache is at capacity, the least recently used entry is evicted.
func (c *LRUCache) Put(ip string, visitor *Visitor) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[ip]; ok {
		c.order.MoveToFront(elem)
		elem.Value.(*entry).value = visitor
		return
	}

	if c.order.Len() >= c.capacity {
		c.evictOldest()
	}

	elem := c.order.PushFront(&entry{key: ip, value: visitor})
	c.items[ip] = elem
}

// Delete removes a visitor from the cache.
func (c *LRUCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[ip]; ok {
		c.order.Remove(elem)
		delete(c.items, ip)
	}
}

// Len returns the current number of entries in the cache.
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// CleanExpired removes all visitors whose LastSeen is older than the given window.
// It returns the number of visitors that were removed.
func (c *LRUCache) CleanExpired(window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for elem := c.order.Back(); elem != nil; {
		prev := elem.Prev()
		v := elem.Value.(*entry).value
		if now.Sub(v.LastSeen) > window {
			c.order.Remove(elem)
			delete(c.items, v.IP)
			removed++
		}
		elem = prev
	}
	return removed
}

func (c *LRUCache) evictOldest() {
	if elem := c.order.Back(); elem != nil {
		ent := elem.Value.(*entry)
		c.order.Remove(elem)
		delete(c.items, ent.key)
	}
}

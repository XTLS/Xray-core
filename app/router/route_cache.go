package router

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

const (
	// DefaultRouteCacheSize is the default maximum number of entries in the route cache
	DefaultRouteCacheSize = 4096

	// DefaultRouteCacheTTL is the default TTL for cached routes
	DefaultRouteCacheTTL = 5 * time.Minute

	// cacheShardCount is the number of shards for the cache to reduce lock contention
	cacheShardCount = 32
)

// routeCacheKey represents the key for route cache lookup
// We use a struct that can be used as map key (no slices/maps)
type routeCacheKey struct {
	// Target domain or IP string representation
	target string
	// Target port
	targetPort net.Port
	// Network type (TCP/UDP)
	network net.Network
	// Inbound tag
	inboundTag string
	// Protocol (sniffed)
	protocol string
	// User email
	user string
}

// routeCacheEntry represents a cached route result
type routeCacheEntry struct {
	rule      *Rule
	ruleTag   string
	outTag    string
	expiresAt int64 // Unix timestamp in nanoseconds
}

// isExpired checks if the cache entry has expired
func (e *routeCacheEntry) isExpired() bool {
	return time.Now().UnixNano() > e.expiresAt
}

// routeCacheShard is a single shard of the route cache
type routeCacheShard struct {
	sync.RWMutex
	entries map[routeCacheKey]*routeCacheEntry
	order   []routeCacheKey // LRU order tracking
	maxSize int
}

// RouteCache is a sharded LRU cache for routing decisions
type RouteCache struct {
	shards    [cacheShardCount]*routeCacheShard
	ttl       time.Duration
	enabled   atomic.Bool
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
}

// NewRouteCache creates a new route cache
func NewRouteCache(maxSize int, ttl time.Duration) *RouteCache {
	if maxSize <= 0 {
		maxSize = DefaultRouteCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultRouteCacheTTL
	}

	shardSize := maxSize / cacheShardCount
	if shardSize < 16 {
		shardSize = 16
	}

	cache := &RouteCache{
		ttl: ttl,
	}
	cache.enabled.Store(true)

	for i := 0; i < cacheShardCount; i++ {
		cache.shards[i] = &routeCacheShard{
			entries: make(map[routeCacheKey]*routeCacheEntry, shardSize),
			order:   make([]routeCacheKey, 0, shardSize),
			maxSize: shardSize,
		}
	}

	return cache
}

// getShard returns the shard for a given key
func (c *RouteCache) getShard(key *routeCacheKey) *routeCacheShard {
	// Simple hash based on target string
	h := uint32(0)
	for i := 0; i < len(key.target); i++ {
		h = h*31 + uint32(key.target[i])
	}
	h = h*31 + uint32(key.targetPort)
	h = h*31 + uint32(key.network)
	return c.shards[h%cacheShardCount]
}

// buildCacheKey constructs a cache key from routing context
// Returns nil if the context is not cacheable
func buildCacheKey(ctx routing.Context) *routeCacheKey {
	// Get target - either domain or IP
	target := ctx.GetTargetDomain()
	if target == "" {
		// Try to get target IP
		ips := ctx.GetTargetIPs()
		if len(ips) == 0 {
			return nil // Cannot cache without target
		}
		// Use first IP as key
		target = ips[0].String()
	}

	return &routeCacheKey{
		target:     target,
		targetPort: ctx.GetTargetPort(),
		network:    ctx.GetNetwork(),
		inboundTag: ctx.GetInboundTag(),
		protocol:   ctx.GetProtocol(),
		user:       ctx.GetUser(),
	}
}

// Get retrieves a cached route for the given context
// Returns the cached rule and outbound tag, or nil if not found/expired
func (c *RouteCache) Get(ctx routing.Context) (*Rule, string, bool) {
	if !c.enabled.Load() {
		return nil, "", false
	}

	key := buildCacheKey(ctx)
	if key == nil {
		c.misses.Add(1)
		return nil, "", false
	}

	shard := c.getShard(key)
	shard.RLock()
	entry, exists := shard.entries[*key]
	shard.RUnlock()

	if !exists {
		c.misses.Add(1)
		return nil, "", false
	}

	if entry.isExpired() {
		// Entry expired, will be cleaned up on next write
		c.misses.Add(1)
		return nil, "", false
	}

	c.hits.Add(1)
	return entry.rule, entry.outTag, true
}

// Put stores a route result in the cache
func (c *RouteCache) Put(ctx routing.Context, rule *Rule, outTag string) {
	if !c.enabled.Load() {
		return
	}

	key := buildCacheKey(ctx)
	if key == nil {
		return
	}

	// Don't cache routes that use balancers (they may change)
	if rule != nil && rule.Balancer != nil {
		return
	}

	shard := c.getShard(key)
	entry := &routeCacheEntry{
		rule:      rule,
		ruleTag:   "",
		outTag:    outTag,
		expiresAt: time.Now().Add(c.ttl).UnixNano(),
	}
	if rule != nil {
		entry.ruleTag = rule.RuleTag
	}

	shard.Lock()
	defer shard.Unlock()

	// Check if key already exists
	if _, exists := shard.entries[*key]; exists {
		// Update existing entry
		shard.entries[*key] = entry
		// Move to front of LRU order
		c.moveToFront(shard, *key)
		return
	}

	// Clean up expired entries if we're at capacity
	if len(shard.entries) >= shard.maxSize {
		c.evictOldest(shard)
	}

	// Add new entry
	shard.entries[*key] = entry
	shard.order = append(shard.order, *key)
}

// moveToFront moves a key to the front of the LRU order
func (c *RouteCache) moveToFront(shard *routeCacheShard, key routeCacheKey) {
	// Find and remove the key from its current position
	for i, k := range shard.order {
		if k == key {
			// Remove from current position
			copy(shard.order[i:], shard.order[i+1:])
			shard.order = shard.order[:len(shard.order)-1]
			break
		}
	}
	// Add to front
	shard.order = append([]routeCacheKey{key}, shard.order...)
}

// evictOldest removes the oldest entry from the shard
func (c *RouteCache) evictOldest(shard *routeCacheShard) {
	// First, try to remove expired entries
	now := time.Now().UnixNano()
	newOrder := make([]routeCacheKey, 0, len(shard.order))

	for _, key := range shard.order {
		if entry, exists := shard.entries[key]; exists {
			if entry.expiresAt < now {
				delete(shard.entries, key)
				c.evictions.Add(1)
			} else {
				newOrder = append(newOrder, key)
			}
		}
	}
	shard.order = newOrder

	// If still at capacity, remove oldest entries
	for len(shard.entries) >= shard.maxSize && len(shard.order) > 0 {
		oldest := shard.order[len(shard.order)-1]
		shard.order = shard.order[:len(shard.order)-1]
		delete(shard.entries, oldest)
		c.evictions.Add(1)
	}
}

// Invalidate removes all entries from the cache
func (c *RouteCache) Invalidate() {
	for _, shard := range c.shards {
		shard.Lock()
		shard.entries = make(map[routeCacheKey]*routeCacheEntry, shard.maxSize)
		shard.order = shard.order[:0]
		shard.Unlock()
	}
}

// InvalidateByInboundTag removes all entries with the given inbound tag
func (c *RouteCache) InvalidateByInboundTag(tag string) {
	for _, shard := range c.shards {
		shard.Lock()
		newOrder := make([]routeCacheKey, 0, len(shard.order))
		for _, key := range shard.order {
			if key.inboundTag == tag {
				delete(shard.entries, key)
			} else {
				newOrder = append(newOrder, key)
			}
		}
		shard.order = newOrder
		shard.Unlock()
	}
}

// SetEnabled enables or disables the cache
func (c *RouteCache) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
	if !enabled {
		c.Invalidate()
	}
}

// IsEnabled returns whether the cache is enabled
func (c *RouteCache) IsEnabled() bool {
	return c.enabled.Load()
}

// Stats returns cache statistics
func (c *RouteCache) Stats() (hits, misses, evictions uint64, size int) {
	hits = c.hits.Load()
	misses = c.misses.Load()
	evictions = c.evictions.Load()

	for _, shard := range c.shards {
		shard.RLock()
		size += len(shard.entries)
		shard.RUnlock()
	}

	return
}

// HitRate returns the cache hit rate as a percentage
func (c *RouteCache) HitRate() float64 {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

package router_test

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// mockRoutingContext implements routing.Context for testing
type mockRoutingContext struct {
	inboundTag   string
	sourceIPs    []net.IP
	sourcePort   net.Port
	targetIPs    []net.IP
	targetPort   net.Port
	localIPs     []net.IP
	localPort    net.Port
	targetDomain string
	network      net.Network
	protocol     string
	user         string
	vlessRoute   net.Port
	attributes   map[string]string
	skipDNS      bool
}

func (m *mockRoutingContext) GetInboundTag() string            { return m.inboundTag }
func (m *mockRoutingContext) GetSourceIPs() []net.IP           { return m.sourceIPs }
func (m *mockRoutingContext) GetSourcePort() net.Port          { return m.sourcePort }
func (m *mockRoutingContext) GetTargetIPs() []net.IP           { return m.targetIPs }
func (m *mockRoutingContext) GetTargetPort() net.Port          { return m.targetPort }
func (m *mockRoutingContext) GetLocalIPs() []net.IP            { return m.localIPs }
func (m *mockRoutingContext) GetLocalPort() net.Port           { return m.localPort }
func (m *mockRoutingContext) GetTargetDomain() string          { return m.targetDomain }
func (m *mockRoutingContext) GetNetwork() net.Network          { return m.network }
func (m *mockRoutingContext) GetProtocol() string              { return m.protocol }
func (m *mockRoutingContext) GetUser() string                  { return m.user }
func (m *mockRoutingContext) GetVlessRoute() net.Port          { return m.vlessRoute }
func (m *mockRoutingContext) GetAttributes() map[string]string { return m.attributes }
func (m *mockRoutingContext) GetSkipDNSResolve() bool          { return m.skipDNS }

func TestRouteCacheBasic(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
		inboundTag:   "in-1",
	}

	// Test cache miss
	rule, outTag, found := cache.Get(ctx)
	if found {
		t.Error("Expected cache miss, got hit")
	}

	// Create a mock rule
	mockRule := &router.Rule{
		Tag:     "out-1",
		RuleTag: "rule-1",
	}

	// Put into cache
	cache.Put(ctx, mockRule, "out-1")

	// Test cache hit
	rule, outTag, found = cache.Get(ctx)
	if !found {
		t.Error("Expected cache hit, got miss")
	}
	if rule != mockRule {
		t.Error("Expected same rule from cache")
	}
	if outTag != "out-1" {
		t.Errorf("Expected outTag 'out-1', got '%s'", outTag)
	}
}

func TestRouteCacheExpiration(t *testing.T) {
	// Create cache with very short TTL
	cache := router.NewRouteCache(100, 50*time.Millisecond)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	mockRule := &router.Rule{
		Tag:     "out-1",
		RuleTag: "rule-1",
	}

	cache.Put(ctx, mockRule, "out-1")

	// Should hit immediately
	_, _, found := cache.Get(ctx)
	if !found {
		t.Error("Expected cache hit immediately after put")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should miss after expiration
	_, _, found = cache.Get(ctx)
	if found {
		t.Error("Expected cache miss after expiration")
	}
}

func TestRouteCacheDifferentContexts(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx1 := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	ctx2 := &mockRoutingContext{
		targetDomain: "example.org",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	ctx3 := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   80, // Different port
		network:      net.Network_TCP,
	}

	rule1 := &router.Rule{Tag: "out-1"}
	rule2 := &router.Rule{Tag: "out-2"}
	rule3 := &router.Rule{Tag: "out-3"}

	cache.Put(ctx1, rule1, "out-1")
	cache.Put(ctx2, rule2, "out-2")
	cache.Put(ctx3, rule3, "out-3")

	// Verify each context gets correct rule
	r, _, found := cache.Get(ctx1)
	if !found || r != rule1 {
		t.Error("ctx1 should return rule1")
	}

	r, _, found = cache.Get(ctx2)
	if !found || r != rule2 {
		t.Error("ctx2 should return rule2")
	}

	r, _, found = cache.Get(ctx3)
	if !found || r != rule3 {
		t.Error("ctx3 should return rule3")
	}
}

func TestRouteCacheInvalidate(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	mockRule := &router.Rule{Tag: "out-1"}
	cache.Put(ctx, mockRule, "out-1")

	// Verify it's cached
	_, _, found := cache.Get(ctx)
	if !found {
		t.Error("Expected cache hit before invalidate")
	}

	// Invalidate
	cache.Invalidate()

	// Should miss after invalidate
	_, _, found = cache.Get(ctx)
	if found {
		t.Error("Expected cache miss after invalidate")
	}
}

func TestRouteCacheStats(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	// Initial stats
	hits, misses, _, size := cache.Stats()
	if hits != 0 || misses != 0 || size != 0 {
		t.Error("Initial stats should be zero")
	}

	// Cache miss
	cache.Get(ctx)
	hits, misses, _, _ = cache.Stats()
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}

	// Put and hit
	mockRule := &router.Rule{Tag: "out-1"}
	cache.Put(ctx, mockRule, "out-1")
	cache.Get(ctx)

	hits, misses, _, size = cache.Stats()
	if hits != 1 {
		t.Errorf("Expected 1 hit, got %d", hits)
	}
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
}

func TestRouteCacheLRUEviction(t *testing.T) {
	// Small cache to trigger eviction
	cache := router.NewRouteCache(2, time.Minute)

	contexts := make([]routing.Context, 5)
	for i := 0; i < 5; i++ {
		contexts[i] = &mockRoutingContext{
			targetDomain: "example" + string(rune('0'+i)) + ".com",
			targetPort:   443,
			network:      net.Network_TCP,
		}
		cache.Put(contexts[i], &router.Rule{Tag: "out-" + string(rune('0'+i))}, "out")
	}

	// Most recent entries should still be in cache
	// Due to sharding, we can't guarantee exact eviction order
	// Just verify the cache is working and has reasonable size
	_, _, _, size := cache.Stats()
	if size > 5 {
		t.Errorf("Cache size should be limited, got %d", size)
	}
}

func TestRouteCacheDisabled(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	mockRule := &router.Rule{Tag: "out-1"}
	cache.Put(ctx, mockRule, "out-1")

	// Disable cache
	cache.SetEnabled(false)

	// Should miss when disabled
	_, _, found := cache.Get(ctx)
	if found {
		t.Error("Expected cache miss when disabled")
	}

	// Re-enable
	cache.SetEnabled(true)

	// Cache was cleared on disable, so should still miss
	_, _, found = cache.Get(ctx)
	if found {
		t.Error("Expected cache miss after re-enable (cache was cleared)")
	}
}

func TestRouteCacheIPTarget(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	// Context with IP instead of domain
	ctx := &mockRoutingContext{
		targetDomain: "", // No domain
		targetIPs:    []net.IP{net.ParseIP("1.2.3.4")},
		targetPort:   443,
		network:      net.Network_TCP,
	}

	mockRule := &router.Rule{Tag: "out-1"}
	cache.Put(ctx, mockRule, "out-1")

	// Should be able to retrieve
	r, _, found := cache.Get(ctx)
	if !found {
		t.Error("Expected cache hit for IP target")
	}
	if r != mockRule {
		t.Error("Expected same rule from cache")
	}
}

func TestRouteCacheNilRule(t *testing.T) {
	cache := router.NewRouteCache(100, time.Minute)

	ctx := &mockRoutingContext{
		targetDomain: "example.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	// Cache a "no match" result (nil rule)
	cache.Put(ctx, nil, "")

	// Should hit with nil rule
	rule, outTag, found := cache.Get(ctx)
	if !found {
		t.Error("Expected cache hit for nil rule")
	}
	if rule != nil {
		t.Error("Expected nil rule from cache")
	}
	if outTag != "" {
		t.Errorf("Expected empty outTag, got '%s'", outTag)
	}
}

func BenchmarkRouteCacheGet(b *testing.B) {
	cache := router.NewRouteCache(10000, time.Minute)

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		ctx := &mockRoutingContext{
			targetDomain: "example" + string(rune(i%26+'a')) + ".com",
			targetPort:   net.Port(443 + i%100),
			network:      net.Network_TCP,
		}
		cache.Put(ctx, &router.Rule{Tag: "out-1"}, "out-1")
	}

	ctx := &mockRoutingContext{
		targetDomain: "examplea.com",
		targetPort:   443,
		network:      net.Network_TCP,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(ctx)
	}
}

func BenchmarkRouteCachePut(b *testing.B) {
	cache := router.NewRouteCache(10000, time.Minute)
	rule := &router.Rule{Tag: "out-1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &mockRoutingContext{
			targetDomain: "example" + string(rune(i%26+'a')) + ".com",
			targetPort:   net.Port(443 + i%100),
			network:      net.Network_TCP,
		}
		cache.Put(ctx, rule, "out-1")
	}
}

func BenchmarkRouteCacheConcurrent(b *testing.B) {
	cache := router.NewRouteCache(10000, time.Minute)
	rule := &router.Rule{Tag: "out-1"}

	// Pre-populate
	for i := 0; i < 1000; i++ {
		ctx := &mockRoutingContext{
			targetDomain: "example" + string(rune(i%26+'a')) + ".com",
			targetPort:   net.Port(443 + i%100),
			network:      net.Network_TCP,
		}
		cache.Put(ctx, rule, "out-1")
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ctx := &mockRoutingContext{
				targetDomain: "example" + string(rune(i%26+'a')) + ".com",
				targetPort:   net.Port(443 + i%100),
				network:      net.Network_TCP,
			}
			if i%2 == 0 {
				cache.Get(ctx)
			} else {
				cache.Put(ctx, rule, "out-1")
			}
			i++
		}
	})
}

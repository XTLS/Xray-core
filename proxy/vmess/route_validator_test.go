package vmess

import (
	"encoding/binary"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

func accountID(user, route int) uuid.UUID {
	id := uuid.UUID{0x31, 0x75, 0x30, 0xa8, 0x3c, 0x1d, 0x12, 0x34, 0x8d, 0x8e, 0x7c, 0xb7}
	binary.BigEndian.PutUint32(id[12:], uint32(user))
	binary.BigEndian.PutUint16(id[6:8], uint16(route))
	return id
}

func keyFor(user, route int) [16]byte {
	var result [16]byte
	copy(result[:], aead.KDF16(protocol.NewID(accountID(user, route)).CmdKey(), aead.KDFSaltConstAuthIDEncryptionKey))
	return result
}

func queryFor(user, route int, now uint64) [16]byte {
	return aead.CreateAuthID(protocol.NewID(accountID(user, route)).CmdKey(), int64(now))
}

type testRouteRules []uint16

func (r *testRouteRules) ForUser(string, string) []uint16 { return slices.Clone(*r) }

type testRouteSource struct {
	rules atomic.Pointer[testRouteRules]
}

func (s *testRouteSource) UserRouteRules() routing.UserRouteRules { return s.rules.Load() }
func (s *testRouteSource) set(routes ...uint16)                   { r := testRouteRules(routes); s.rules.Store(&r) }

func TestServerOnlyRouteLifecycle(t *testing.T) {
	v := NewTimedUserValidator()
	defer v.Close()
	u := &protocol.MemoryUser{Email: "alice", Level: 7, Account: &MemoryAccount{ID: protocol.NewID(accountID(0, 4660))}}
	if err := v.Add(u); err != nil {
		t.Fatal(err)
	}
	source := new(testRouteSource)
	source.set(0, 1, 300, 65535)
	if err := v.SetRouteSource(source, "in"); err != nil {
		t.Fatal(err)
	}
	match := func(user, route int) (*AEADMatch, error) {
		q := queryFor(user, route, uint64(time.Now().Unix()))
		return v.MatchAEAD(q[:])
	}
	for _, route := range []int{0, 1, 300, 65535, 4660} {
		m, err := match(0, route)
		if err != nil || m.User != u || int(m.Route) != route {
			t.Fatalf("route %d: %v %v", route, m, err)
		}
		if v.routeCache.bytes != 0 {
			t.Fatal("candidate populated cache")
		}
	}
	if _, err := match(0, 2); err == nil {
		t.Fatal("undeclared alias accepted")
	}
	first, _ := match(0, 300)
	release, err := v.AdmitAEAD(first)
	if err != nil {
		t.Fatal(err)
	}
	if v.routeCache.bytes != 4*routeKeyBytes {
		t.Fatal("wrong prepared keys")
	}
	stale, _ := match(0, 1)
	source.set(0, 65535)
	if _, err := v.AdmitAEAD(stale); err == nil {
		t.Fatal("removed route admitted")
	}
	state := v.routeCache.states[v.routeIDs[u]]
	if state.active != 1 {
		t.Fatal("reload lost active lease")
	}
	source.set()
	v.syncRoutes()
	if v.routeCache.states[v.routeIDs[u]].active != 1 || v.routeCache.bytes != 0 {
		t.Fatal("empty catalog lost lease")
	}
	source.set(300)
	v.syncRoutes()
	release()
	if state.active != 0 {
		t.Fatal("old lease did not close through empty catalog")
	}
	if v.GetCount() != 1 || len(v.GetUsers()) != 1 {
		t.Fatal("aliases leaked into API")
	}
	// An existing account in the same masked identity disables generated aliases.
	u2 := &protocol.MemoryUser{Email: "bob", Account: &MemoryAccount{ID: protocol.NewID(accountID(0, 27))}}
	if err := v.Add(u2); err != nil {
		t.Fatal(err)
	}
	if _, err := match(0, 300); err == nil {
		t.Fatal("ambiguous alias accepted")
	}
	for route, want := range map[int]*protocol.MemoryUser{4660: u, 27: u2} {
		m, err := match(0, route)
		if err != nil || m.User != want {
			t.Fatal("exact ownership changed")
		}
	}
	v.Remove("bob")
	m, err := match(0, 300)
	if err != nil {
		t.Fatal(err)
	}
	v.Remove("alice")
	if _, err := v.AdmitAEAD(m); err == nil {
		t.Fatal("deleted user admitted")
	}
}

func TestServerOnlyWithoutRouteSource(t *testing.T) {
	v := NewTimedUserValidator()
	defer v.Close()
	if err := v.Add(&protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(accountID(0, 4660))}}); err != nil {
		t.Fatal(err)
	}
	q := queryFor(0, 4660, uint64(time.Now().Unix()))
	m, err := v.MatchAEAD(q[:])
	if err != nil {
		t.Fatal(err)
	}
	release, err := v.AdmitAEAD(m)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if len(v.routeAccounts) != 0 || len(v.routeCache.states) != 0 || v.routeCache.bytes != 0 {
		t.Fatal("ordinary validator allocated route state without a source")
	}
}

func TestRouteSearchEdges(t *testing.T) {
	now := uint64(time.Now().Unix())
	for _, count := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 300} {
		keys := make([][16]byte, count)
		for i := range keys {
			keys[i] = keyFor(0, i)
		}
		prepared := prepareRouteKeys(keys)
		for _, index := range []int{0, count / 2, count - 1} {
			if index < 0 || index >= count {
				continue
			}
			q := queryFor(0, index, now)
			if scanRouteRaw(keys, &q, now) != index || prepared.match(&q, now) != index {
				t.Fatal("candidate mismatch", count, index)
			}
			if prepared.match(&q, now+121) != -1 {
				t.Fatal("expired candidate accepted")
			}
		}
		q := queryFor(1, 0, now)
		if scanRouteRaw(keys, &q, now) != -1 || prepared.match(&q, now) != -1 {
			t.Fatal("unknown user")
		}
	}
}

func TestServerOnlyRouteScale(t *testing.T) {
	if os.Getenv("XRAY_TEST_ROUTE_SCALE") != "1" {
		t.Skip("explicit 10000 x 300 resource check")
	}
	v := NewTimedUserValidator()
	defer v.Close()
	start := time.Now()
	for i := 0; i < 10000; i++ {
		if err := v.Add(&protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(accountID(i, 4660))}}); err != nil {
			t.Fatal(err)
		}
	}
	source := new(testRouteSource)
	values := make([]uint16, 300)
	for i := range values {
		values[i] = uint16(i + 1)
	}
	source.set(values...)
	if err := v.SetRouteSource(source, "vm"); err != nil {
		t.Fatal(err)
	}
	if v.routeAliasCount != 3000000 {
		t.Fatal(v.routeAliasCount)
	}
	t.Logf("catalog_build=%s raw_key_bytes=%d", time.Since(start), v.routeAliasCount*16)
	q := queryFor(10001, 300, uint64(time.Now().Unix()))
	start = time.Now()
	if _, err := v.MatchAEAD(q[:]); err == nil {
		t.Fatal("unknown user accepted")
	}
	t.Logf("cold_miss=%s", time.Since(start))
	var releases []func()
	for i := 0; i < 1000; i++ {
		q := queryFor(i, 4660, uint64(time.Now().Unix()))
		m, err := v.MatchAEAD(q[:])
		if err != nil {
			t.Fatal(err)
		}
		release, err := v.AdmitAEAD(m)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if v.routeCache.bytes != min(1000, routeCacheBudget/(300*routeKeyBytes))*300*routeKeyBytes {
		t.Fatal("cache payload", v.routeCache.bytes)
	}
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("online=1000 prepared_key_bytes=%d process_go_heap_bytes=%d", v.routeCache.bytes, memory.HeapAlloc)
	q = queryFor(999, 300, uint64(time.Now().Unix()))
	start = time.Now()
	m, err := v.MatchAEAD(q[:])
	if err != nil || !m.hot {
		t.Fatal("cached alias", err)
	}
	t.Logf("hot_match=%s", time.Since(start))
	for i := 1000; i < 10000; i++ {
		q := queryFor(i, 4660, uint64(time.Now().Unix()))
		m, err := v.MatchAEAD(q[:])
		if err != nil {
			t.Fatal(err)
		}
		release, err := v.AdmitAEAD(m)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if len(v.routeCache.states) != 10000 || v.routeCache.bytes > routeCacheBudget {
		t.Fatal("all-online budget/accounting")
	}
	t.Logf("online=10000 prepared_key_bytes=%d cached_users=%d", v.routeCache.bytes, v.routeCache.recent.Len())
	for _, release := range releases {
		release()
	}
	v.routeCache.mu.Lock()
	v.routeCache.expireLocked(time.Now().Add(3 * time.Minute))
	v.routeCache.mu.Unlock()
	if v.routeCache.bytes != 0 || len(v.routeCache.states) != 0 {
		t.Fatal("all-online cleanup leaked")
	}
}

func TestServerOnlyCatalogBudgetAndScanLimit(t *testing.T) {
	v := NewTimedUserValidator()
	defer v.Close()
	for i := 0; i < 129; i++ {
		if err := v.Add(&protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(accountID(i, 4660))}}); err != nil {
			t.Fatal(err)
		}
	}
	source := new(testRouteSource)
	routes := make([]uint16, 65536)
	for i := range routes {
		routes[i] = uint16(i)
	}
	source.set(routes...)
	if err := v.SetRouteSource(source, "vm"); err == nil {
		t.Fatal("oversized catalog accepted")
	}
	q := queryFor(0, 4660, uint64(time.Now().Unix()))
	if _, err := v.MatchAEAD(q[:]); err != nil {
		t.Fatal("original credential lost", err)
	}
	if v.routeAliasCount != 0 || v.routeCache.bytes != 0 {
		t.Fatal("oversized catalog retained alias keys")
	}
	source.set(300)
	q = queryFor(0, 300, uint64(time.Now().Unix()))
	if _, err := v.MatchAEAD(q[:]); err != nil {
		t.Fatal("catalog recovery", err)
	}
	v.routeScans <- struct{}{}
	v.routeScans <- struct{}{}
	q = queryFor(0, 300, uint64(time.Now().Unix()))
	if _, err := v.MatchAEAD(q[:]); err == nil {
		t.Fatal("scan limit bypassed")
	}
	q = queryFor(0, 4660, uint64(time.Now().Unix()))
	if _, err := v.MatchAEAD(q[:]); err != nil {
		t.Fatal("scan limit blocked original", err)
	}
	<-v.routeScans
	<-v.routeScans
}

func TestServerOnlyConcurrentUpdates(t *testing.T) {
	v := NewTimedUserValidator()
	defer v.Close()
	add := func() {
		if err := v.Add(&protocol.MemoryUser{Email: "alice", Account: &MemoryAccount{ID: protocol.NewID(accountID(0, 4660))}}); err != nil {
			t.Fatal(err)
		}
	}
	add()
	source := new(testRouteSource)
	source.set(1, 300)
	if err := v.SetRouteSource(source, "vm"); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				q := queryFor(0, 300, uint64(time.Now().Unix()))
				m, err := v.MatchAEAD(q[:])
				if err != nil {
					continue
				}
				if release, err := v.AdmitAEAD(m); err == nil {
					release()
					release()
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		source.set(1)
		v.syncRoutes()
		v.Remove("alice")
		add()
		source.set(1, 300)
		v.syncRoutes()
	}
	workers.Wait()
	cacheAssertInvariants(t, v.routeCache)
	for _, state := range v.routeCache.states {
		if state.active != 0 {
			t.Fatal("concurrent lease leaked")
		}
	}
}

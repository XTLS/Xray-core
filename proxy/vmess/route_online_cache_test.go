package vmess

import (
	"sync"
	"testing"
	"time"
)

func cacheTestAccount(id uint32, cryptoUser, routes int, version uint64) *cacheAccount {
	account := &cacheAccount{id: id, generation: version, keys: make([][16]byte, routes)}
	for i := range account.keys {
		account.keys[i] = keyFor(cryptoUser, i+1)
	}
	return account
}

func cacheTestMatch(t *testing.T, c *onlineCache, user, route int, hot bool) cacheCandidate {
	t.Helper()
	now := uint64(c.now().Unix())
	query := queryFor(user, route, now)
	candidate, ok := c.match(&query, now)
	if !ok || candidate.index != route-1 || candidate.hot != hot {
		t.Fatalf("match user=%d route=%d hot=%v: %+v %v", user, route, hot, candidate, ok)
	}
	return candidate
}

func cacheTestAdmit(t *testing.T, c *onlineCache, candidate cacheCandidate) func() {
	t.Helper()
	release, ok := c.authenticated(candidate)
	if !ok {
		t.Fatal("current authenticated account rejected")
	}
	return release
}

func TestOnlineCacheLifecycle(t *testing.T) {
	now := time.Unix(1700000000, 0)
	account := cacheTestAccount(0, 0, 300, 1)
	c := newOnlineCache([]*cacheAccount{account}, 300*routeKeyBytes, 2*time.Minute, func() time.Time { return now })
	first := cacheTestMatch(t, c, 0, 12, false)
	if c.bytes != 0 || len(c.states) != 0 {
		t.Fatal("candidate-only match polluted online cache")
	}
	release1 := cacheTestAdmit(t, c, first)
	release2 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 27, true))
	release1()
	release1()
	if c.states[0].active != 1 {
		t.Fatal("connection lease did not release exactly once")
	}
	now = now.Add(10 * time.Minute)
	cacheTestMatch(t, c, 0, 300, true)
	release2()
	now = now.Add(time.Minute)
	cacheTestMatch(t, c, 0, 1, true)
	// Lookup alone must not extend the post-disconnect grace period.
	now = now.Add(time.Minute)
	cacheTestMatch(t, c, 0, 27, false)
	if c.bytes != 0 || len(c.states) != 0 || len(c.accounts) != 1 {
		t.Fatal("expiry must release prepared keys but retain the offline account")
	}
}

func TestOnlineCacheEvictionAndColdFallback(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1), cacheTestAccount(2, 2, 2, 1)}
	c := newOnlineCache(accounts, 4*routeKeyBytes, time.Minute, time.Now)
	release0 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	release1 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))
	release1()
	release2 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 2, 1, false))
	cacheTestMatch(t, c, 0, 2, true)
	cacheTestMatch(t, c, 1, 2, false)
	cacheTestMatch(t, c, 2, 2, true)
	if c.bytes > c.budget {
		t.Fatal("prepared-key budget exceeded")
	}
	// With all remaining entries online, evict the least recently authenticated.
	release3 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))
	cacheTestMatch(t, c, 0, 2, false)
	release0()
	if c.states[0] != nil {
		t.Fatal("evicted user's connection accounting leaked")
	}
	release2()
	release3()
}

func TestOnlineCacheRevocationAndStaleLease(t *testing.T) {
	old := cacheTestAccount(0, 0, 2, 1)
	c := newOnlineCache([]*cacheAccount{old}, 2*routeKeyBytes, time.Minute, time.Now)
	staleCandidate := cacheTestMatch(t, c, 0, 1, false)
	oldRelease := cacheTestAdmit(t, c, staleCandidate)
	replacement := cacheTestAccount(0, 100, 2, 2)
	c.testReplace(replacement)
	if _, accepted := c.authenticated(staleCandidate); accepted {
		t.Fatal("old generation admitted after replacement")
	}
	current := cacheTestMatch(t, c, 100, 2, false)
	newRelease := cacheTestAdmit(t, c, current)
	oldRelease()
	if c.states[0].active != 1 {
		t.Fatal("old connection changed replacement account state")
	}
	c.remove(0)
	newRelease()
	if _, accepted := c.authenticated(current); accepted || c.bytes != 0 || len(c.states) != 0 {
		t.Fatal("revoked account was retained or admitted")
	}
	now := uint64(time.Now().Unix())
	query := queryFor(100, 2, now)
	if _, found := c.match(&query, now); found {
		t.Fatal("revoked credential found")
	}
}

func TestOnlineCacheInvalidTrafficAndSmallBudget(t *testing.T) {
	account := cacheTestAccount(0, 0, 300, 1)
	c := newOnlineCache([]*cacheAccount{account}, routeKeyBytes, 0, time.Now)
	now := uint64(time.Now().Unix())
	unknown := queryFor(100, 1, now)
	if _, found := c.match(&unknown, now); found || c.bytes != 0 || len(c.states) != 0 {
		t.Fatal("invalid traffic created online state")
	}
	release := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 300, false))
	if c.bytes != 0 || c.states[0].active != 1 {
		t.Fatal("oversized entry must remain authenticated without prepared caching")
	}
	release()
	if len(c.states) != 0 {
		t.Fatal("uncached offline account retained online state")
	}
}

func TestOnlineCacheConcurrentConnections(t *testing.T) {
	account := cacheTestAccount(0, 0, 300, 1)
	c := newOnlineCache([]*cacheAccount{account}, 300*routeKeyBytes, time.Minute, time.Now)
	candidate := cacheTestMatch(t, c, 0, 1, false)
	anchor := cacheTestAdmit(t, c, candidate)
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			release, accepted := c.authenticated(candidate)
			if !accepted {
				t.Error("concurrent valid account rejected")
				return
			}
			now := uint64(time.Now().Unix())
			query := queryFor(0, 27, now)
			if got, ok := c.match(&query, now); !ok || got.account != account || !got.hot {
				t.Error("concurrent cached route change failed")
			}
			release()
			release()
		}()
	}
	workers.Wait()
	if c.states[0].active != 1 {
		t.Fatal("concurrent releases corrupted active count")
	}
	anchor()
	if c.states[0].active != 0 {
		t.Fatal("last connection remained active")
	}
}

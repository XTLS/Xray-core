package vmess

import (
	"math/rand"
	"sync"
	"testing"
	"time"
)

func (c *onlineCache) testReplace(account *cacheAccount) {
	c.remove(account.id)
	c.mu.RLock()
	accounts := []*cacheAccount{account}
	for _, current := range c.accounts {
		accounts = append(accounts, current)
	}
	c.mu.RUnlock()
	c.reconcile(accounts)
}

func (c *onlineCache) testUpdateRoutes(expected, updated *cacheAccount) bool {
	c.mu.RLock()
	if c.accounts[expected.id] != expected {
		c.mu.RUnlock()
		return false
	}
	accounts := []*cacheAccount{updated}
	for id, current := range c.accounts {
		if id != expected.id {
			accounts = append(accounts, current)
		}
	}
	c.mu.RUnlock()
	c.reconcile(accounts)
	return true
}

func TestOnlineCacheRouteReloadPreservesConnections(t *testing.T) {
	now := time.Unix(1700000000, 0)
	account := cacheTestAccount(0, 0, 3, 1)
	c := newOnlineCache([]*cacheAccount{account}, 3*routeKeyBytes, time.Minute, func() time.Time { return now })
	release := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	staleCandidate := cacheTestMatch(t, c, 0, 3, true)
	updated := cacheTestAccount(0, 0, 2, 2)
	if !c.testUpdateRoutes(account, updated) {
		t.Fatal("current route-only update rejected")
	}
	if c.states[0] == nil || c.states[0].active != 1 {
		t.Fatal("route-only reload lost the existing account's active connection")
	}
	now = now.Add(2 * time.Minute)
	cacheTestMatch(t, c, 0, 2, true)
	if _, accepted := c.authenticated(staleCandidate); accepted {
		t.Fatal("removed route admitted through stale candidate")
	}
	release()
	now = now.Add(time.Minute)
	cacheTestMatch(t, c, 0, 1, false)
	if c.testUpdateRoutes(account, account) {
		t.Fatal("stale catalog update rolled back current routes")
	}
}

func TestOnlineCacheRouteReloadKeepsIdleDeadline(t *testing.T) {
	now := time.Unix(1700000000, 0)
	account := cacheTestAccount(0, 0, 3, 1)
	c := newOnlineCache([]*cacheAccount{account}, 3*routeKeyBytes, time.Minute, func() time.Time { return now })
	release := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	release()
	now = now.Add(40 * time.Second)
	updated := cacheTestAccount(0, 0, 2, 2)
	if !c.testUpdateRoutes(account, updated) {
		t.Fatal("idle route update rejected")
	}
	cacheTestMatch(t, c, 0, 2, true)
	now = now.Add(20 * time.Second)
	cacheTestMatch(t, c, 0, 1, false)
}

func TestOnlineCacheRouteGrowthCanEvictWithoutLosingLease(t *testing.T) {
	account := cacheTestAccount(0, 0, 1, 1)
	c := newOnlineCache([]*cacheAccount{account}, routeKeyBytes, 0, time.Now)
	release := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	updated := cacheTestAccount(0, 0, 3, 2)
	if !c.testUpdateRoutes(account, updated) || c.states[0].active != 1 || c.bytes != 0 {
		t.Fatal("route growth must preserve the online lease without exceeding the cache budget")
	}
	cacheTestMatch(t, c, 0, 3, false)
	release()
	if len(c.states) != 0 {
		t.Fatal("uncached route-updated lease leaked")
	}
}

func TestOnlineCacheRouteReloadDoesNotRefreshRecency(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1), cacheTestAccount(2, 2, 2, 1)}
	c := newOnlineCache(accounts, 4*routeKeyBytes, time.Minute, time.Now)
	close0 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	close1 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))
	updated := cacheTestAccount(0, 0, 2, 2)
	if !c.testUpdateRoutes(accounts[0], updated) {
		t.Fatal("route update rejected")
	}
	close2 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 2, 1, false))
	cacheTestMatch(t, c, 1, 2, true)
	cacheTestMatch(t, c, 0, 2, false)
	close0()
	close1()
	close2()
}

func TestOnlineCacheRouteReloadDoesNotPromoteEvictedUser(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1)}
	c := newOnlineCache(accounts, 2*routeKeyBytes, time.Minute, time.Now)
	close0 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	close1 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))
	updated := cacheTestAccount(0, 0, 2, 2)
	if !c.testUpdateRoutes(accounts[0], updated) {
		t.Fatal("route update rejected")
	}
	cacheTestMatch(t, c, 0, 2, false)
	cacheTestMatch(t, c, 1, 2, true)
	close0()
	close1()
}

func cacheAssertInvariants(t *testing.T, c *onlineCache) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	measured := 0
	seen := make(map[*cacheAccount]bool)
	previousAuth := ^uint64(0)
	for e := c.recent.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*preparedAccount)
		state := c.states[entry.account.id]
		if state == nil || state.element != e || state.account != entry.account || c.accounts[entry.account.id] != entry.account || seen[entry.account] {
			t.Fatal("cache entry ownership/list invariant")
		}
		seen[entry.account] = true
		if state.lastAuth == 0 || state.lastAuth >= previousAuth {
			t.Fatal("authentication recency order")
		}
		previousAuth = state.lastAuth
		measured += entry.keys.size()
	}
	if measured != c.bytes || measured > c.budget || c.bytes < 0 {
		t.Fatal("prepared byte accounting", measured, c.bytes, c.budget)
	}
	for id, state := range c.states {
		if c.accounts[id] != state.account || state.active < 0 || (state.active == 0 && state.element == nil) {
			t.Fatal("online state invariant")
		}
	}
	partition := make(map[*cacheAccount]int)
	for account := range seen {
		partition[account]++
	}
	for _, account := range c.cold {
		partition[account]++
		if seen[account] {
			t.Fatal("hot account searched again in cold partition")
		}
	}
	if len(partition) != len(c.accounts) {
		t.Fatal("credential partition size")
	}
	for _, account := range c.accounts {
		if partition[account] != 1 {
			t.Fatal("account missing from or duplicated in search partitions")
		}
	}
}

func TestOnlineCacheReauthenticationSearchOrder(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1)}
	c := newOnlineCache(accounts, 4*routeKeyBytes, time.Minute, time.Now)
	defer cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))()
	defer cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))()
	var searched []uint32
	for e := c.recent.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*preparedAccount)
		entry.keys = cacheSearchRecorder{entry.keys, &searched, entry.account.id}
	}
	defer cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 2, true))()
	searched = nil
	cacheTestMatch(t, c, 0, 1, true)
	if len(searched) != 1 || searched[0] != 0 {
		t.Fatal("most recently authenticated account was not searched first", searched)
	}
	cacheAssertInvariants(t, c)
}

type cacheSearchRecorder struct {
	routeKeys
	searched *[]uint32
	id       uint32
}

func (r cacheSearchRecorder) match(query *[16]byte, now uint64) int {
	*r.searched = append(*r.searched, r.id)
	return r.routeKeys.match(query, now)
}

func TestOnlineCacheRejectedGrowthDoesNotEvictOtherUsers(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1), cacheTestAccount(2, 2, 1, 1)}
	c := newOnlineCache(accounts, 5*routeKeyBytes, time.Minute, time.Now)
	for _, id := range []int{0, 2, 1} {
		defer cacheTestAdmit(t, c, cacheTestMatch(t, c, id, 1, false))()
	}
	updated := cacheTestAccount(2, 2, 4, 2)
	if !c.testUpdateRoutes(accounts[2], updated) {
		t.Fatal("route update rejected")
	}
	cacheTestMatch(t, c, 0, 1, true)
	cacheTestMatch(t, c, 1, 1, true)
	cacheTestMatch(t, c, 2, 1, false)
	cacheAssertInvariants(t, c)
}

func TestOnlineCacheRouteGrowthPreservesNewerEntry(t *testing.T) {
	accounts := []*cacheAccount{cacheTestAccount(0, 0, 2, 1), cacheTestAccount(1, 1, 2, 1)}
	c := newOnlineCache(accounts, 4*routeKeyBytes, time.Minute, time.Now)
	close0 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, false))
	close1 := cacheTestAdmit(t, c, cacheTestMatch(t, c, 1, 1, false))
	updated := cacheTestAccount(0, 0, 3, 2)
	if !c.testUpdateRoutes(accounts[0], updated) {
		t.Fatal("route update rejected")
	}
	cacheTestMatch(t, c, 0, 3, false)
	cacheTestMatch(t, c, 1, 2, true)
	cacheAssertInvariants(t, c)
	close0()
	close1()
}

func TestOnlineCacheConcurrentRouteReloadAndClose(t *testing.T) {
	account := cacheTestAccount(0, 0, 3, 1)
	c := newOnlineCache([]*cacheAccount{account}, 3*routeKeyBytes, time.Minute, time.Now)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		release := cacheTestAdmit(t, c, cacheTestMatch(t, c, 0, 1, i > 0))
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			release()
			release()
		}()
	}
	close(start)
	for i := 0; i < 64; i++ {
		updated := cacheTestAccount(0, 0, 1+i%3, uint64(i+2))
		if !c.testUpdateRoutes(account, updated) {
			t.Fatal("current route update rejected")
		}
		account = updated
	}
	workers.Wait()
	cacheAssertInvariants(t, c)
	if c.states[0].active != 0 {
		t.Fatal("concurrent route updates lost connection releases")
	}
}

func TestOnlineCacheRandomizedLifecycle(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := newOnlineCache(nil, 8*routeKeyBytes, 5*time.Second, func() time.Time { return now })
	type lease struct {
		account *cacheAccount
		release func()
		closed  bool
	}
	var leases []lease
	current := make(map[uint32]*cacheAccount)
	cryptoUsers := make(map[uint32]int)
	random := rand.New(rand.NewSource(20261114))
	for step := 0; step < 4000; step++ {
		id := uint32(random.Intn(8))
		switch random.Intn(6) {
		case 0:
			account := cacheTestAccount(id, step+100, 1+random.Intn(6), uint64(step+1))
			c.testReplace(account)
			current[id] = account
			cryptoUsers[id] = step + 100
		case 1:
			c.remove(id)
			delete(current, id)
		case 2:
			if account := current[id]; account != nil {
				release, ok := c.authenticated(cacheCandidate{account: account, index: 0})
				if !ok {
					t.Fatal("current account rejected")
				}
				leases = append(leases, lease{account: account, release: release})
			}
		case 3:
			if len(leases) > 0 {
				i := random.Intn(len(leases))
				leases[i].release()
				leases[i].closed = true
			}
		case 4:
			now = now.Add(time.Duration(random.Intn(8)) * time.Second)
			var invalid [16]byte
			if _, matched := c.match(&invalid, uint64(now.Unix())); matched {
				t.Fatal("invalid candidate matched")
			}
		case 5:
			if old := current[id]; old != nil {
				updated := cacheTestAccount(id, cryptoUsers[id], 1+random.Intn(6), uint64(step+1))
				if !c.testUpdateRoutes(old, updated) {
					t.Fatal("current route generation rejected")
				}
				current[id] = updated
				for i := range leases {
					if leases[i].account == old {
						leases[i].account = updated
					}
				}
			}
		}
		cacheAssertInvariants(t, c)
		for id, account := range current {
			expected := 0
			for _, lease := range leases {
				if !lease.closed && lease.account == account {
					expected++
				}
			}
			actual := 0
			if state := c.states[id]; state != nil {
				actual = state.active
			}
			if actual != expected {
				t.Fatalf("step=%d id=%d active=%d want=%d", step, id, actual, expected)
			}
		}
	}
	for _, lease := range leases {
		lease.release()
	}
	now = now.Add(time.Minute)
	var invalid [16]byte
	c.match(&invalid, uint64(now.Unix()))
	cacheAssertInvariants(t, c)
	if len(c.states) != 0 || c.bytes != 0 {
		t.Fatal("closed/expired state leaked")
	}
}

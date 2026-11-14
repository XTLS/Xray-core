package vmess

import (
	"container/list"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

// Accounts and key slices are immutable catalog records, independent of online status.
type cacheAccount struct {
	id         uint32
	generation uint64
	keys       [][16]byte
	user       *protocol.MemoryUser
	routes     []uint16
}

// reconcile publishes a whole catalog once, retaining leases only for the same owner.
func (c *onlineCache) reconcile(accounts []*cacheAccount) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(c.now())
	current := make(map[uint32]*cacheAccount, len(accounts))
	for _, account := range accounts {
		current[account.id] = account
	}
	var refresh []*onlineState
	for id, state := range c.states {
		updated := current[id]
		if updated == state.account {
			continue
		}
		wasCached := state.element != nil
		c.detachPreparedLocked(state)
		if updated == nil || updated.user != state.account.user {
			delete(c.states, id)
			state.account = nil
			continue
		}
		state.account = updated
		if wasCached {
			refresh = append(refresh, state)
		}
	}
	c.accounts = current
	for _, state := range refresh {
		c.prepareLocked(state)
	}
	for id, state := range c.states {
		if state.active == 0 && state.element == nil {
			delete(c.states, id)
		}
	}
	c.publishLocked()
}

type cacheCandidate struct {
	account *cacheAccount
	index   int
	hot     bool
}

type preparedAccount struct {
	account *cacheAccount
	keys    routeKeys
}

type onlineState struct {
	account  *cacheAccount
	active   int
	lastAuth uint64
	expires  time.Time
	element  *list.Element
}

// onlineCache tracks authenticated account leases, without source-address inputs.
type onlineCache struct {
	mu           sync.RWMutex
	accounts     map[uint32]*cacheAccount
	states       map[uint32]*onlineState
	recent       list.List
	hot          []*preparedAccount
	cold         []*cacheAccount
	bytes        int
	budget       int
	grace        time.Duration
	nextExpiry   time.Time
	now          func() time.Time
	authSequence uint64
}

func newOnlineCache(accounts []*cacheAccount, budget int, grace time.Duration, now func() time.Time) *onlineCache {
	if budget < 0 || grace < 0 {
		panic("negative online cache limit")
	}
	c := &onlineCache{accounts: make(map[uint32]*cacheAccount), states: make(map[uint32]*onlineState), budget: budget, grace: grace, now: now}
	for _, account := range accounts {
		c.accounts[account.id] = account
	}
	c.publishLocked()
	return c
}

func (c *onlineCache) publishLocked() {
	hot := make([]*preparedAccount, 0, c.recent.Len())
	for e := c.recent.Front(); e != nil; e = e.Next() {
		hot = append(hot, e.Value.(*preparedAccount))
	}
	cold := make([]*cacheAccount, 0, len(c.accounts)-len(hot))
	for id, account := range c.accounts {
		if state := c.states[id]; state == nil || state.element == nil {
			cold = append(cold, account)
		}
	}
	c.hot, c.cold = hot, cold
}

func (c *onlineCache) detachPreparedLocked(state *onlineState) {
	if state.element != nil {
		entry := state.element.Value.(*preparedAccount)
		c.bytes -= entry.keys.size()
		c.recent.Remove(state.element)
		state.element = nil
	}
}

func (c *onlineCache) dropLocked(state *onlineState) {
	c.detachPreparedLocked(state)
	if state.active == 0 {
		delete(c.states, state.account.id)
	}
}

func (c *onlineCache) expireLocked(now time.Time) {
	if c.nextExpiry.IsZero() || now.Before(c.nextExpiry) {
		return
	}
	c.nextExpiry = time.Time{}
	changed := false
	for e := c.recent.Back(); e != nil; {
		previous := e.Prev()
		state := c.states[e.Value.(*preparedAccount).account.id]
		if state.active == 0 {
			if !now.Before(state.expires) {
				c.dropLocked(state)
				changed = true
			} else if c.nextExpiry.IsZero() || state.expires.Before(c.nextExpiry) {
				c.nextExpiry = state.expires
			}
		}
		e = previous
	}
	if changed {
		c.publishLocked()
	}
}

func (c *onlineCache) remove(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state := c.states[id]; state != nil {
		c.dropLocked(state)
		delete(c.states, id)
		state.account = nil
	}
	delete(c.accounts, id)
	c.publishLocked()
}

func (c *onlineCache) prepareLocked(state *onlineState) bool {
	account := state.account
	if len(account.keys) == 0 || len(account.keys) > c.budget/routeKeyBytes {
		return false
	}
	needed := len(account.keys) * routeKeyBytes
	for c.bytes+needed > c.budget {
		victim := c.recent.Back()
		for e := c.recent.Back(); e != nil; e = e.Prev() {
			if c.states[e.Value.(*preparedAccount).account.id].active == 0 {
				victim = e
				break
			}
		}
		victimState := c.states[victim.Value.(*preparedAccount).account.id]
		// A route refresh must not outrank a more eligible cached account.
		if (state.active == 0 && victimState.active > 0) ||
			((state.active == 0) == (victimState.active == 0) && state.lastAuth < victimState.lastAuth) {
			return false
		}
		c.dropLocked(victimState)
	}
	entry := &preparedAccount{account: account, keys: prepareRouteKeys(account.keys)}
	for e := c.recent.Front(); e != nil; e = e.Next() {
		if c.states[e.Value.(*preparedAccount).account.id].lastAuth < state.lastAuth {
			state.element = c.recent.InsertBefore(entry, e)
			break
		}
	}
	if state.element == nil {
		state.element = c.recent.PushBack(entry)
	}
	c.bytes += needed
	return true
}

// match proposes a candidate only. A match does not create or refresh an online entry.
func (c *onlineCache) match(query *[16]byte, now uint64) (cacheCandidate, bool) {
	c.mu.RLock()
	if !c.nextExpiry.IsZero() && !c.now().Before(c.nextExpiry) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.expireLocked(c.now())
		c.mu.Unlock()
		c.mu.RLock()
	}
	defer c.mu.RUnlock()
	hot, cold := c.hot, c.cold
	for _, entry := range hot {
		if index := entry.keys.match(query, now); index >= 0 && c.accounts[entry.account.id] == entry.account {
			return cacheCandidate{entry.account, index, true}, true
		}
	}
	for _, account := range cold {
		if index := scanRouteRaw(account.keys, query, now); index >= 0 && c.accounts[account.id] == account {
			return cacheCandidate{account, index, false}, true
		}
	}
	return cacheCandidate{}, false
}

// authenticated must be called only after full header/replay validation and admission.
func (c *onlineCache) authenticated(candidate cacheCandidate) (release func(), accepted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	account := candidate.account
	if account == nil || c.accounts[account.id] != account || candidate.index < -1 || candidate.index >= len(account.keys) {
		return nil, false
	}
	now := c.now()
	c.expireLocked(now)
	state := c.states[account.id]
	if state == nil {
		state = &onlineState{account: account}
		c.states[account.id] = state
	}
	state.active++
	c.authSequence++
	state.lastAuth = c.authSequence
	state.expires = time.Time{}
	if state.element != nil {
		c.recent.MoveToFront(state.element)
	} else if c.prepareLocked(state) {
		c.publishLocked()
	}
	var once sync.Once
	id := account.id
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.states[id] != state {
				return
			}
			state.active--
			if state.active == 0 {
				if state.element == nil {
					delete(c.states, id)
					return
				}
				state.expires = c.now().Add(c.grace)
				if c.nextExpiry.IsZero() || state.expires.Before(c.nextExpiry) {
					c.nextExpiry = state.expires
				}
				c.expireLocked(c.now())
			}
		})
	}, true
}

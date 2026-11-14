package vmess

import (
	"slices"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

const (
	routeCacheBudget     = 64 << 20
	routeCatalogKeyLimit = (128 << 20) / 16
)

// AEADMatch keeps the wire key separate from the original user's policy identity.
// It is a candidate until the complete header has been checked and AdmitAEAD succeeds.
type AEADMatch struct {
	User       *protocol.MemoryUser
	CmdKey     [16]byte
	Route      net.Port
	generation uint64
	index      int
	hot        bool
	alias      bool
}

func (v *TimedUserValidator) SetRouteSource(source routing.UserRouteProvider, tag string) error {
	v.Lock()
	defer v.Unlock()
	v.routeSource, v.inboundTag, v.routesDirty = source, tag, true
	return v.syncRoutesLocked()
}

func (v *TimedUserValidator) syncRoutesLocked() error {
	var snapshot routing.UserRouteRules
	if v.routeSource != nil {
		snapshot = v.routeSource.UserRouteRules()
	}
	if snapshot == v.routeSnapshot && !v.routesDirty {
		return v.routeError
	}
	v.routeSnapshot, v.routesDirty = snapshot, false
	v.routeError = nil
	if snapshot == nil {
		v.routeAccounts = nil
		v.routeAliasCount = 0
		v.routeCache.reconcile(nil)
		return nil
	}
	groups := make(map[uuid.UUID]int)
	for _, user := range v.users {
		a := user.Account.(*MemoryAccount)
		if !a.UserRoute {
			id := a.ID.UUID()
			id[6], id[7] = 0, 0
			groups[id]++
		}
	}
	var accounts []*cacheAccount
	count := 0
	for _, user := range v.users {
		a := user.Account.(*MemoryAccount)
		id := a.ID.UUID()
		base := id
		base[6], base[7] = 0, 0
		var routes []uint16
		if snapshot != nil && !a.UserRoute && groups[base] == 1 {
			routes = snapshot.ForUser(v.inboundTag, user.Email)
		}
		original := uint16(net.PortFromBytes(id[6:8]))
		routes = slices.DeleteFunc(routes, func(route uint16) bool { return route == original })
		count += len(routes)
		if count > routeCatalogKeyLimit {
			v.routeError = errors.New("VMess userRoute catalog exceeds 128 MiB of raw keys")
			accounts = make([]*cacheAccount, 0, len(v.users))
			for _, u := range v.users {
				accounts = append(accounts, v.newRouteAccount(u, nil))
			}
			count = 0
			break
		}
		if old := v.routeAccounts[user]; old != nil && slices.Equal(old.routes, routes) {
			accounts = append(accounts, old)
			continue
		}
		accounts = append(accounts, v.newRouteAccount(user, routes))
	}
	// Check the entire catalog budget before doing any new key derivation.
	for _, account := range accounts {
		if account.keys != nil || len(account.routes) == 0 {
			continue
		}
		account.keys = make([][16]byte, len(account.routes))
		id := account.user.Account.(*MemoryAccount).ID.UUID()
		for i, route := range account.routes {
			id[6], id[7] = byte(route>>8), byte(route)
			copy(account.keys[i][:], aead.KDF16(protocol.NewID(id).CmdKey(), aead.KDFSaltConstAuthIDEncryptionKey))
		}
	}
	v.routeAccounts = make(map[*protocol.MemoryUser]*cacheAccount, len(accounts))
	for _, account := range accounts {
		v.routeAccounts[account.user] = account
	}
	v.routeCache.reconcile(accounts)
	v.routeAliasCount = count
	return v.routeError
}

func (v *TimedUserValidator) newRouteAccount(user *protocol.MemoryUser, routes []uint16) *cacheAccount {
	v.nextRouteGeneration++
	return &cacheAccount{id: v.routeIDs[user], generation: v.nextRouteGeneration, user: user, routes: routes}
}

func (v *TimedUserValidator) syncRoutes() {
	v.RLock()
	changed := v.routesDirty || (v.routeSource != nil && v.routeSource.UserRouteRules() != v.routeSnapshot)
	v.RUnlock()
	if changed {
		v.Lock()
		v.syncRoutesLocked()
		v.Unlock()
	}
}

func (v *TimedUserValidator) MatchAEAD(userHash []byte) (*AEADMatch, error) {
	if len(userHash) != 16 {
		return nil, aead.ErrNotFound
	}
	v.syncRoutes()
	v.RLock()
	defer v.RUnlock()
	if v.closed {
		return nil, aead.ErrNotFound
	}
	var authID [16]byte
	copy(authID[:], userHash)
	user, err := v.aeadDecoderHolder.Match(authID)
	if err == nil {
		u := user.(*protocol.MemoryUser)
		a := u.Account.(*MemoryAccount)
		match := &AEADMatch{User: u, Route: net.PortFromBytes(a.ID.Bytes()[6:8])}
		copy(match.CmdKey[:], a.CmdKey())
		return match, nil
	}
	if err != aead.ErrNotFound {
		return nil, err
	}
	if v.routeError != nil {
		return nil, v.routeError
	}
	if v.routeAliasCount == 0 {
		return nil, aead.ErrNotFound
	}
	// Bound expensive cold scans independently of the number of pending sockets.
	select {
	case v.routeScans <- struct{}{}:
		defer func() { <-v.routeScans }()
	default:
		return nil, errors.New("VMess route authentication busy")
	}
	candidate, found := v.routeCache.match(&authID, uint64(time.Now().Unix()))
	if !found {
		return nil, aead.ErrNotFound
	}
	route := candidate.account.routes[candidate.index]
	id := candidate.account.user.Account.(*MemoryAccount).ID.UUID()
	id[6], id[7] = byte(route>>8), byte(route)
	match := &AEADMatch{User: candidate.account.user, Route: net.Port(route), generation: candidate.account.generation, index: candidate.index, hot: candidate.hot, alias: true}
	copy(match.CmdKey[:], protocol.NewID(id).CmdKey())
	// Always recheck a native candidate with the standard AuthID decoder.
	_, _, _, plain := aead.NewAuthIDDecoder(match.CmdKey[:]).Decode(authID)
	if !valid((*[16]byte)(plain), uint64(time.Now().Unix())) {
		return nil, aead.ErrNotFound
	}
	if !v.aeadDecoderHolder.CheckReplay(authID) {
		return nil, aead.ErrReplay
	}
	return match, nil
}

// AdmitAEAD is called only after header authentication, syntax and session replay checks.
func (v *TimedUserValidator) AdmitAEAD(match *AEADMatch) (func(), error) {
	v.syncRoutes()
	v.RLock()
	defer v.RUnlock()
	if v.closed || match == nil || v.routeIDs[match.User] == 0 {
		return nil, aead.ErrNotFound
	}
	if match.alias {
		if v.routeSource == nil || v.routeSource.UserRouteRules() != v.routeSnapshot {
			return nil, aead.ErrNotFound
		}
		account := v.routeAccounts[match.User]
		if account == nil || account.generation != match.generation {
			return nil, aead.ErrNotFound
		}
		release, ok := v.routeCache.authenticated(cacheCandidate{account: account, index: match.index})
		if !ok {
			return nil, aead.ErrNotFound
		}
		v.startRouteCleanup()
		return release, nil
	}
	if v.exactUsers[match.CmdKey] != match.User {
		return nil, aead.ErrNotFound
	}
	if account := v.routeAccounts[match.User]; account != nil {
		release, ok := v.routeCache.authenticated(cacheCandidate{account: account, index: -1})
		if !ok {
			return nil, aead.ErrNotFound
		}
		v.startRouteCleanup()
		return release, nil
	}
	return func() {}, nil
}

func (v *TimedUserValidator) startRouteCleanup() {
	// Start outside Periodic: its immediate callback must not re-enter validator locks.
	v.cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-v.cleanupStop:
					return
				case <-ticker.C:
					v.routeCache.mu.Lock()
					v.routeCache.expireLocked(time.Now())
					v.routeCache.mu.Unlock()
				}
			}
		}()
	})
}

func (v *TimedUserValidator) Close() error {
	v.Lock()
	defer v.Unlock()
	if !v.closed {
		v.closed = true
		close(v.cleanupStop)
		v.routeCache.reconcile(nil)
		v.routeAccounts = nil
		v.routeAliasCount = 0
	}
	return nil
}

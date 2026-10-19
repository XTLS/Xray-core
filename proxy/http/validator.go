package http

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// PasswordAccount is the shape shared by the HTTP and SOCKS accounts: a username
// and a password. Both account types satisfy it through the getters protoc
// generates, so one validator serves both inbounds.
type PasswordAccount interface {
	GetUsername() string
	GetPassword() string
}

// AccountValidator holds the accounts of an inbound and allows changing them at
// runtime. The static map on ServerConfig is read without a lock on every
// handshake, so adding an account to it directly would race with the readers.
//
// Every handshake reads and almost nothing writes, so the map is replaced
// wholesale instead of guarded: readers load the current one without any lock,
// and a writer copies it under the mutex and swaps the pointer. A reader that
// loaded the old map finishes against a consistent snapshot.
type AccountValidator struct {
	mu     sync.Mutex // writers only
	byName atomic.Pointer[map[string]*protocol.MemoryUser]
}

// NewAccountValidator builds a validator from the accounts of a config. The map
// may be nil, in which case the validator starts out empty.
func NewAccountValidator(accounts map[string]string) *AccountValidator {
	byName := make(map[string]*protocol.MemoryUser, len(accounts))
	for username, password := range accounts {
		byName[username] = &protocol.MemoryUser{
			Account: &Account{Username: username, Password: password},
			Email:   username,
		}
	}
	v := new(AccountValidator)
	v.byName.Store(&byName)
	return v
}

// load returns the current snapshot. Never nil: the constructor stores one.
func (v *AccountValidator) load() map[string]*protocol.MemoryUser {
	return *v.byName.Load()
}

// clone copies the current snapshot for a writer to modify. Call under the mutex.
func (v *AccountValidator) clone() map[string]*protocol.MemoryUser {
	current := v.load()
	next := make(map[string]*protocol.MemoryUser, len(current)+1)
	for k, u := range current {
		next[k] = u
	}
	return next
}

// Add implements the add half of proxy.UserManager. An account without a
// username is rejected: the handshake looks accounts up by name, so such an
// entry could never be matched.
func (v *AccountValidator) Add(u *protocol.MemoryUser) error {
	if u == nil || u.Account == nil {
		return errors.New("user has no account")
	}
	account, ok := u.Account.(PasswordAccount)
	if !ok {
		return errors.New("account is not a username/password account")
	}
	username := account.GetUsername()
	if username == "" {
		return errors.New("account has no username")
	}
	if u.Email == "" {
		u.Email = username
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if _, found := v.load()[username]; found {
		return errors.New("user ", username, " already exists")
	}
	next := v.clone()
	next[username] = u
	v.byName.Store(&next)
	return nil
}

// Del removes an account by e-mail, falling back to the username. The API
// addresses users by e-mail, but accounts created from a config file carry the
// username in both fields, and an operator thinks in usernames.
func (v *AccountValidator) Del(key string) error {
	if key == "" {
		return errors.New("empty key")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	for username, u := range v.load() {
		if strings.EqualFold(u.Email, key) || strings.EqualFold(username, key) {
			next := v.clone()
			delete(next, username)
			v.byName.Store(&next)
			return nil
		}
	}
	return errors.New("user ", key, " not found")
}

// Has reports whether the pair is a known account. This is the hot path: every
// handshake calls it, so it takes the read lock only.
func (v *AccountValidator) Has(username, password string) bool {
	u, found := v.load()[username]
	if !found {
		return false
	}
	account, ok := u.Account.(PasswordAccount)
	if !ok {
		return false
	}
	return account.GetPassword() == password
}

// Get returns the user with this e-mail or username, or nil.
func (v *AccountValidator) Get(key string) *protocol.MemoryUser {
	if key == "" {
		return nil
	}

	for username, u := range v.load() {
		if strings.EqualFold(u.Email, key) || strings.EqualFold(username, key) {
			return u
		}
	}
	return nil
}

// GetAll returns a copy of the user list, so a caller cannot reach into the
// validator through the slice it got.
func (v *AccountValidator) GetAll() []*protocol.MemoryUser {
	current := v.load()
	users := make([]*protocol.MemoryUser, 0, len(current))
	for _, u := range current {
		users = append(users, u)
	}
	return users
}

// Count returns the number of accounts.
func (v *AccountValidator) Count() int64 {
	return int64(len(v.load()))
}

// Empty reports whether the inbound has no accounts at all. The HTTP server
// only demands authentication when at least one account exists, and that test
// has to see runtime additions too.
func (v *AccountValidator) Empty() bool {
	return len(v.load()) == 0
}

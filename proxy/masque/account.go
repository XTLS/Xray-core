package masque

import (
	"crypto/subtle"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{Password: a.Password}, nil
}

type MemoryAccount struct {
	Password string
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.Password == b.Password
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Password: a.Password}
}

type validator struct {
	mu    sync.RWMutex
	users map[string]*protocol.MemoryUser
}

func newValidator() *validator {
	return &validator{users: make(map[string]*protocol.MemoryUser)}
}

func (v *validator) add(user *protocol.MemoryUser) error {
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("not a MASQUE account")
	}
	if user.Email == "" || strings.Contains(user.Email, ":") {
		return errors.New("invalid email ", user.Email)
	}
	if account.Password == "" {
		return errors.New("empty password for ", user.Email)
	}
	email := strings.ToLower(user.Email)
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, found := v.users[email]; found {
		return errors.New("user ", user.Email, " already exists")
	}
	v.users[email] = user
	return nil
}

func (v *validator) delByEmail(email string) (*protocol.MemoryUser, error) {
	key := strings.ToLower(email)
	v.mu.Lock()
	defer v.mu.Unlock()
	user, found := v.users[key]
	if !found {
		return nil, errors.New("user ", email, " not found")
	}
	delete(v.users, key)
	return user, nil
}

func (v *validator) contains(user *protocol.MemoryUser) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.users[strings.ToLower(user.Email)] == user
}

func (v *validator) get(email, password string) *protocol.MemoryUser {
	v.mu.RLock()
	user := v.users[strings.ToLower(email)]
	v.mu.RUnlock()
	if user == nil || subtle.ConstantTimeCompare([]byte(user.Account.(*MemoryAccount).Password), []byte(password)) != 1 {
		return nil
	}
	return user
}

func (v *validator) getByEmail(email string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.users[strings.ToLower(email)]
}

func (v *validator) getAll() []*protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, user := range v.users {
		users = append(users, user)
	}
	return users
}

func (v *validator) count() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return int64(len(v.users))
}

package masque

import (
	"crypto/subtle"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{User: a.User, Pass: a.Pass}, nil
}

type MemoryAccount struct {
	User string
	Pass string
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.User == b.User && a.Pass == b.Pass
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{User: a.User, Pass: a.Pass}
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
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, found := v.users[account.User]; found {
		return errors.New("user ", account.User, " already exists")
	}
	v.users[account.User] = user
	return nil
}

func (v *validator) delByEmail(email string) (*protocol.MemoryUser, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for name, user := range v.users {
		if user.Email == email {
			delete(v.users, name)
			return user, nil
		}
	}
	return nil, errors.New("user ", email, " not found")
}

func (v *validator) contains(user *protocol.MemoryUser) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.users[user.Account.(*MemoryAccount).User] == user
}

func (v *validator) get(name, pass string) *protocol.MemoryUser {
	v.mu.RLock()
	user := v.users[name]
	v.mu.RUnlock()
	if user == nil || subtle.ConstantTimeCompare([]byte(user.Account.(*MemoryAccount).Pass), []byte(pass)) != 1 {
		return nil
	}
	return user
}

func (v *validator) getByEmail(email string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, user := range v.users {
		if user.Email == email {
			return user
		}
	}
	return nil
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

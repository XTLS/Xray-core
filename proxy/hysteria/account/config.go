package account

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"

	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Auth: a.Auth,
	}, nil
}

type MemoryAccount struct {
	Auth string
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Auth == account.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	emails map[string]struct{}
	users  map[string]*protocol.MemoryUser

	mutex sync.Mutex
}

func vlessRouteAuthKey(auth string) ([16]byte, bool) {
	var key [16]byte
	if len(auth) != 32 && len(auth) != 36 {
		return key, false
	}
	id, err := uuid.ParseString(auth)
	if err != nil {
		return key, false
	}
	copy(key[:], id.Bytes())
	key[6] = 0
	key[7] = 0
	return key, true
}

func VlessRouteFromAuth(auth string) net.Port {
	if len(auth) != 32 && len(auth) != 36 {
		return 0
	}
	id, err := uuid.ParseString(auth)
	if err != nil {
		return 0
	}
	return net.PortFromBytes(id.Bytes()[6:8])
}

func userWithAuth(user *protocol.MemoryUser, auth string) *protocol.MemoryUser {
	clone := *user
	clone.Account = &MemoryAccount{Auth: auth}
	return &clone
}

func NewValidator() *Validator {
	return &Validator{
		emails: make(map[string]struct{}),
		users:  make(map[string]*protocol.MemoryUser),
	}
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if u.Email != "" {
		if _, ok := v.emails[u.Email]; ok {
			return errors.New("User ", u.Email, " already exists.")
		}
		v.emails[u.Email] = struct{}{}
	}
	v.users[u.Account.(*MemoryAccount).Auth] = u

	return nil
}

func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	if _, ok := v.emails[email]; !ok {
		return errors.New("User ", email, " not found.")
	}
	delete(v.emails, email)
	for key, user := range v.users {
		if user.Email == email {
			delete(v.users, key)
			break
		}
	}

	return nil
}

func (v *Validator) Get(auth string) *protocol.MemoryUser {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if user := v.users[auth]; user != nil {
		return user
	}

	key, ok := vlessRouteAuthKey(auth)
	if !ok {
		return nil
	}
	for storedAuth, user := range v.users {
		storedKey, ok := vlessRouteAuthKey(storedAuth)
		if ok && storedKey == key {
			return userWithAuth(user, auth)
		}
	}
	return nil
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	if _, ok := v.emails[email]; ok {
		for _, user := range v.users {
			if user.Email == email {
				return user
			}
		}
	}

	return nil
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, user := range v.users {
		users = append(users, user)
	}

	return users
}

func (v *Validator) GetCount() int64 {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return int64(len(v.users))
}

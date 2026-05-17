package account

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"

	"google.golang.org/protobuf/proto"
)

// AsAccount converts the proto Account to a protocol.Account.
func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Username: a.Username,
		Password: a.Password,
	}, nil
}

// MemoryAccount is the parsed form of Account.
type MemoryAccount struct {
	Username string
	Password string
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Username == account.Username && a.Password == account.Password
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Username: a.Username,
		Password: a.Password,
	}
}

// Validator stores valid mieru users keyed by username and email.
type Validator struct {
	emails    map[string]struct{}
	usernames map[string]*protocol.MemoryUser

	mutex sync.Mutex
}

func NewValidator() *Validator {
	return &Validator{
		emails:    make(map[string]struct{}),
		usernames: make(map[string]*protocol.MemoryUser),
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
	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("invalid mieru account")
	}
	if acc.Username == "" {
		return errors.New("mieru username must not be empty")
	}
	if _, ok := v.usernames[acc.Username]; ok {
		return errors.New("mieru user ", acc.Username, " already exists.")
	}
	v.usernames[acc.Username] = u
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
	for key, user := range v.usernames {
		if user.Email == email {
			delete(v.usernames, key)
			break
		}
	}
	return nil
}

func (v *Validator) Get(username string) *protocol.MemoryUser {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return v.usernames[username]
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if _, ok := v.emails[email]; ok {
		for _, user := range v.usernames {
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
	users := make([]*protocol.MemoryUser, 0, len(v.usernames))
	for _, user := range v.usernames {
		users = append(users, user)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return int64(len(v.usernames))
}

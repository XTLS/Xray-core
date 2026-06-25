package account

import (
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"

	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	var VR net.Port
	if id, err := uuid.ParseString(a.Auth); err == nil {
		VR = net.PortFromBytes(id[6:8])
	}
	return &MemoryAccount{
		Auth: a.Auth,
		VR:   VR,
	}, nil
}

type MemoryAccount struct {
	Auth string
	VR   net.Port
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Auth == b.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	users sync.Map
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Add(user *protocol.MemoryUser) error {
	v.users.Store(user.Account.(*MemoryAccount).Auth, user)
	return nil
}

func (v *Validator) DelByEmail(email string) error {
	if user := v.GetByEmail(email); user != nil {
		v.users.Delete(user.Account.(*MemoryAccount).Auth)
	}
	return nil
}

func (v *Validator) Get(auth string) *protocol.MemoryUser {
	if value, ok := v.users.Load(auth); ok {
		return value.(*protocol.MemoryUser)
	}
	return nil
}

func (v *Validator) GetByEmail(email string) (user *protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (v *Validator) GetAll() (users []*protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (v *Validator) GetCount() (count int64) {
	v.users.Range(func(key, value any) bool {
		count++
		return true
	})
	return
}

func (v *Validator) NotEmpty() (not_empty bool) {
	v.users.Range(func(key, value any) bool {
		not_empty = true
		return false
	})
	return
}

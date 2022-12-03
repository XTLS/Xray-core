package shadowsocks_2022

import (
	"github.com/xtls/xray-core/common/protocol"
)

// MemoryAccount is an account type converted from Account.
type MemoryAccount struct {
	Key   string
	Email string
	Level int32
}

// AsAccount implements protocol.AsAccount.
func (u *User) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Key:   u.GetKey(),
		Email: u.GetEmail(),
		Level: u.GetLevel(),
	}, nil
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Key == account.Key
	}
	return false
}

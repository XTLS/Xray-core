package protocol

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
)

func (u *User) GetTypedAccount() (Account, error) {
	if u.GetAccount() == nil {
		return nil, errors.New("Account is missing").AtWarning()
	}

	rawAccount, err := u.Account.GetInstance()
	if err != nil {
		return nil, err
	}
	if asAccount, ok := rawAccount.(AsAccount); ok {
		return asAccount.AsAccount()
	}
	if account, ok := rawAccount.(Account); ok {
		return account, nil
	}
	return nil, errors.New("Unknown account type: ", u.Account.Type)
}

func (u *User) ToMemoryUser() (*MemoryUser, error) {
	account, err := u.GetTypedAccount()
	if err != nil {
		return nil, err
	}
	mu := &MemoryUser{
		Account:            account,
		Email:              u.Email,
		Level:              u.Level,
		UplinkSpeedLimit:   u.GetUplinkSpeedLimit(),
		DownlinkSpeedLimit: u.GetDownlinkSpeedLimit(),
	}
	mu.uplinkLimiter = globalLimiterRegistry.Get(mu.Email, "uplink", mu.UplinkSpeedLimit)
	mu.downlinkLimiter = globalLimiterRegistry.Get(mu.Email, "downlink", mu.DownlinkSpeedLimit)
	return mu, nil
}

func ToProtoUser(mu *MemoryUser) *User {
	if mu == nil {
		return nil
	}
	return &User{
		Account:            serial.ToTypedMessage(mu.Account.ToProto()),
		Email:              mu.Email,
		Level:              mu.Level,
		UplinkSpeedLimit:   mu.UplinkSpeedLimit,
		DownlinkSpeedLimit: mu.DownlinkSpeedLimit,
	}
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account Account
	Email   string
	Level   uint32
	UplinkSpeedLimit   uint64
	DownlinkSpeedLimit uint64

	limiterMu       sync.Mutex
	uplinkLimiter   *RateLimiter
	downlinkLimiter *RateLimiter
}

func (u *MemoryUser) GetUplinkLimiter() *RateLimiter {
	if u == nil {
		return nil
	}
	u.limiterMu.Lock()
	defer u.limiterMu.Unlock()
	if u.uplinkLimiter == nil {
		u.uplinkLimiter = globalLimiterRegistry.Get(u.Email, "uplink", u.UplinkSpeedLimit)
	}
	return u.uplinkLimiter
}

func (u *MemoryUser) GetDownlinkLimiter() *RateLimiter {
	if u == nil {
		return nil
	}
	u.limiterMu.Lock()
	defer u.limiterMu.Unlock()
	if u.downlinkLimiter == nil {
		u.downlinkLimiter = globalLimiterRegistry.Get(u.Email, "downlink", u.DownlinkSpeedLimit)
	}
	return u.downlinkLimiter
}

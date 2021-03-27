package protocol

import (
	"github.com/xtls/xray-core/features/policy"
	"golang.org/x/time/rate"
)

func (u *User) GetTypedAccount() (Account, error) {
	if u.GetAccount() == nil {
		return nil, newError("Account missing").AtWarning()
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
	return nil, newError("Unknown account type: ", u.Account.Type)
}

func (u *User) ToMemoryUser() (*MemoryUser, error) {
	account, err := u.GetTypedAccount()
	if err != nil {
		return nil, err
	}

	return &MemoryUser{
		Account: account,
		Email:   u.Email,
		Level:   u.Level,
	}, nil
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account         Account
	Email           string
	Level           uint32
	UplinkLimiter   *rate.Limiter
	DownlinkLimiter *rate.Limiter
}

func (u *MemoryUser) SetLimiter(pm policy.Manager) {
	p := pm.ForLevel(u.Level)
	if p.Speed.UplinkSpeed != 0 {
		u.UplinkLimiter = rate.NewLimiter(rate.Limit(p.Speed.UplinkSpeed/4), int(p.Speed.UplinkSpeed/4))
	}

	if p.Speed.DownlinkSpeed != 0 {
		u.DownlinkLimiter = rate.NewLimiter(rate.Limit(p.Speed.DownlinkSpeed/4), int(p.Speed.DownlinkSpeed/4))
	}
}

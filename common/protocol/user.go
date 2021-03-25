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
	InboundLimiter  *rate.Limiter
	OutboundLimiter *rate.Limiter
}

func (u *MemoryUser) SetLimiter(pm policy.Manager) {
	p := pm.ForLevel(u.Level)
	if p.Speed.Inbound != 0 {
		u.InboundLimiter = rate.NewLimiter(rate.Limit(p.Speed.Inbound/4), int(p.Speed.Inbound/4))
	}

	if p.Speed.Outbound != 0 {
		u.OutboundLimiter = rate.NewLimiter(rate.Limit(p.Speed.Outbound/4), int(p.Speed.Inbound/4))
	}
}

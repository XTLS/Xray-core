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
	return &MemoryUser{
		Account: account,
		Email:   u.Email,
		Level:   u.Level,
	}, nil
}

func ToProtoUser(mu *MemoryUser) *User {
	if mu == nil {
		return nil
	}
	return &User{
		Account: serial.ToTypedMessage(mu.Account.ToProto()),
		Email:   mu.Email,
		Level:   mu.Level,
	}
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account Account
	Email   string
	Level   uint32

	statNamesOnce sync.Once
	uplinkStat    string
	downlinkStat  string
	onlineStat    string
}

func (u *MemoryUser) initStatNames() {
	if u.Email == "" {
		return
	}
	u.uplinkStat = "user>>>" + u.Email + ">>>traffic>>>uplink"
	u.downlinkStat = "user>>>" + u.Email + ">>>traffic>>>downlink"
	u.onlineStat = "user>>>" + u.Email + ">>>online"
}

// TrafficUplinkStatName returns the stats counter name for user uplink traffic.
func (u *MemoryUser) TrafficUplinkStatName() string {
	u.statNamesOnce.Do(u.initStatNames)
	return u.uplinkStat
}

// TrafficDownlinkStatName returns the stats counter name for user downlink traffic.
func (u *MemoryUser) TrafficDownlinkStatName() string {
	u.statNamesOnce.Do(u.initStatNames)
	return u.downlinkStat
}

// OnlineStatName returns the stats counter name for user online tracking.
func (u *MemoryUser) OnlineStatName() string {
	u.statNamesOnce.Do(u.initStatNames)
	return u.onlineStat
}

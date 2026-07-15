package protocol

import (
	"encoding/json"

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

func (u *User) UnmarshalJSON(data []byte) error {
	type userJSON User
	aux := struct {
		*userJSON
		SpeedLimitUpMbpsCamel   *uint64 `json:"speedLimitUpMbps"`
		SpeedLimitDownMbpsCamel *uint64 `json:"speedLimitDownMbps"`
	}{
		userJSON: (*userJSON)(u),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.SpeedLimitUpMbpsCamel != nil {
		u.SpeedLimitUpMbps = *aux.SpeedLimitUpMbpsCamel
	}
	if aux.SpeedLimitDownMbpsCamel != nil {
		u.SpeedLimitDownMbps = *aux.SpeedLimitDownMbpsCamel
	}
	return nil
}

func (u *User) ToMemoryUser() (*MemoryUser, error) {
	account, err := u.GetTypedAccount()
	if err != nil {
		return nil, err
	}
	return &MemoryUser{
		Account:            account,
		Email:              u.Email,
		Level:              u.Level,
		SpeedLimitUpMbps:   u.SpeedLimitUpMbps,
		SpeedLimitDownMbps: u.SpeedLimitDownMbps,
	}, nil
}

func ToProtoUser(mu *MemoryUser) *User {
	if mu == nil {
		return nil
	}
	return &User{
		Account:            serial.ToTypedMessage(mu.Account.ToProto()),
		Email:              mu.Email,
		Level:              mu.Level,
		SpeedLimitUpMbps:   mu.SpeedLimitUpMbps,
		SpeedLimitDownMbps: mu.SpeedLimitDownMbps,
	}
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account Account
	Email   string
	Level   uint32

	// SpeedLimitUpMbps and SpeedLimitDownMbps are optional per-user limits.
	// Zero means unlimited.
	SpeedLimitUpMbps   uint64
	SpeedLimitDownMbps uint64
}

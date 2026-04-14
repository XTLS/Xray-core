package xtess

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse ID").Base(err).AtError()
	}
	return &MemoryAccount{
		ID:         protocol.NewID(id),
		Flow:       a.Flow,
		Encryption: a.Encryption,
		XorMode:    a.XorMode,
		Seconds:    a.Seconds,
		Padding:    a.Padding,
		Reverse:    a.Reverse,
	}, nil
}

type MemoryAccount struct {
	ID *protocol.ID

	Flow string

	Encryption string
	XorMode    uint32
	Seconds    uint32
	Padding    string

	Reverse *Reverse
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	xtessAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(xtessAccount.ID)
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Id:         a.ID.String(),
		Flow:       a.Flow,
		Encryption: a.Encryption,
		XorMode:    a.XorMode,
		Seconds:    a.Seconds,
		Padding:    a.Padding,
		Reverse:    a.Reverse,
	}
}


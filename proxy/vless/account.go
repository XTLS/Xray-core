package vless

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// AsAccount implements protocol.Account.AsAccount().
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse ID").Base(err)
	}
	if a.DeviceId != "" && !validDeviceID(a.DeviceId) {
		return nil, errors.New("invalid VLESS device ID")
	}
	if len(a.AllowedDeviceIds) > 0 && !a.EnforceDeviceId {
		return nil, errors.New("allowed VLESS device IDs require enforceDeviceId")
	}
	for _, deviceID := range a.AllowedDeviceIds {
		if !validDeviceID(deviceID) {
			return nil, errors.New("invalid allowed VLESS device ID")
		}
	}
	return &MemoryAccount{
		ID:               protocol.NewID(id),
		Flow:             a.Flow,       // needs parser here?
		Encryption:       a.Encryption, // needs parser here?
		XorMode:          a.XorMode,
		Seconds:          a.Seconds,
		Padding:          a.Padding,
		Reverse:          a.Reverse,
		Testpre:          a.Testpre,
		Testseed:         a.Testseed,
		DeviceID:         a.DeviceId,
		EnforceDeviceID:  a.EnforceDeviceId,
		AllowedDeviceIDs: a.AllowedDeviceIds,
	}, nil
}

// validDeviceID accepts a short, printable identifier without whitespace.
func validDeviceID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 33 || id[i] > 126 {
			return false
		}
	}
	return true
}

// MemoryAccount is an in-memory form of VLess account.
type MemoryAccount struct {
	// ID of the account.
	ID *protocol.ID
	// Flow of the account. May be "xtls-rprx-vision".
	Flow string

	Encryption string
	XorMode    uint32
	Seconds    uint32
	Padding    string

	Reverse *Reverse

	Testpre          uint32
	Testseed         []uint32
	DeviceID         string
	EnforceDeviceID  bool
	AllowedDeviceIDs []string
}

// AllowsDeviceID checks the server-side device allowlist for one VLESS request.
func (a *MemoryAccount) AllowsDeviceID(id string) bool {
	if !a.EnforceDeviceID {
		return true
	}
	if id == "" {
		return false
	}
	for _, allowed := range a.AllowedDeviceIDs {
		if id == allowed {
			return true
		}
	}
	return false
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	vlessAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(vlessAccount.ID)
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Id:               a.ID.String(),
		Flow:             a.Flow,
		Encryption:       a.Encryption,
		XorMode:          a.XorMode,
		Seconds:          a.Seconds,
		Padding:          a.Padding,
		Reverse:          a.Reverse,
		Testpre:          a.Testpre,
		Testseed:         a.Testseed,
		DeviceId:         a.DeviceID,
		EnforceDeviceId:  a.EnforceDeviceID,
		AllowedDeviceIds: a.AllowedDeviceIDs,
	}
}

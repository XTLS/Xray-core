package vmess

import (
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

// MemoryAccount is an in-memory form of VMess account.
type MemoryAccount struct {
	// ID is the main ID of the account.
	ID *protocol.ID
	// Security type of the account. Used for client connections.
	Security protocol.SecurityType

	AuthenticatedLengthExperiment bool
	NoTerminationSignal           bool
	UserRoute                     bool
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	vmessAccount, ok := account.(*MemoryAccount)
	if !ok || a.UserRoute != vmessAccount.UserRoute {
		return false
	}
	if a.UserRoute {
		left, right := a.ID.UUID(), vmessAccount.ID.UUID()
		left[6], left[7], right[6], right[7] = 0, 0, 0, 0
		return left == right
	}
	return a.ID.Equals(vmessAccount.ID)
}

// CmdKey separates route-enabled credentials from standard VMess credentials.
func (a *MemoryAccount) CmdKey() []byte {
	if !a.UserRoute {
		return a.ID.CmdKey()
	}
	id := a.ID.UUID()
	id[6], id[7] = 0, 0
	return aead.KDF16(protocol.NewID(id).CmdKey(), "VMess User Route v1")
}

func (a *MemoryAccount) ToProto() proto.Message {
	test := ""
	if a.AuthenticatedLengthExperiment {
		test = "AuthenticatedLength|"
	}
	if a.NoTerminationSignal {
		test = test + "NoTerminationSignal"
	}
	return &Account{
		Id:               a.ID.String(),
		TestsEnabled:     test,
		UserRoute:        a.UserRoute,
		SecuritySettings: &protocol.SecurityConfig{Type: a.Security},
	}
}

// AsAccount implements protocol.Account.
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse ID").Base(err)
	}
	protoID := protocol.NewID(id)
	var AuthenticatedLength, NoTerminationSignal bool
	if strings.Contains(a.TestsEnabled, "AuthenticatedLength") {
		AuthenticatedLength = true
	}
	if strings.Contains(a.TestsEnabled, "NoTerminationSignal") {
		NoTerminationSignal = true
	}
	return &MemoryAccount{
		ID:                            protoID,
		Security:                      a.SecuritySettings.GetSecurityType(),
		AuthenticatedLengthExperiment: AuthenticatedLength,
		NoTerminationSignal:           NoTerminationSignal,
		UserRoute:                     a.UserRoute,
	}, nil
}

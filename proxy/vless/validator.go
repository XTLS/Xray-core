package vless

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// Validator stores and looks up valid VLESS users. Implementations back it
// with in-process memory, an external Redis instance, or a REST API, which
// allows a node to stay stateless with respect to user configuration.
//
// GetAll and GetCount are implemented via the email index on the memory and
// redis backends, so a user added without an Email is invisible to those two
// calls even though Get/GetByEmail-by-uuid still resolves it.
type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

func ProcessUUID(id [16]byte) [16]byte {
	id[6] = 0
	id[7] = 0
	return id
}

package account

import (
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	var VR net.Port
	if id, err := uuid.Parse(a.Auth); err == nil {
		VR = net.PortFromBytes(id[6:8])
	}
	return &MemoryAccount{
		Auth: a.Auth,
		VR:   VR,
	}, nil
}

type MemoryAccount struct {
	Auth string
	VR   net.Port
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Auth == b.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	users sync.Map
	ids   sync.Map
	mu    sync.Mutex

	// Connections authenticated with each auth, closed when that auth is
	// removed and not added back within removeGrace (an update may be a
	// remove followed by an add).
	connMu sync.Mutex
	conns  map[string]map[uint64]func()
	nextID uint64
}

const removeGrace = 2 * time.Second

// Track registers closeFn for a connection authenticated with auth. The
// returned func unregisters it.
func (v *Validator) Track(auth string, closeFn func()) (untrack func()) {
	v.connMu.Lock()
	defer v.connMu.Unlock()
	if v.conns == nil {
		v.conns = make(map[string]map[uint64]func())
	}
	if v.conns[auth] == nil {
		v.conns[auth] = make(map[uint64]func())
	}
	v.nextID++
	id := v.nextID
	v.conns[auth][id] = closeFn
	return func() {
		v.connMu.Lock()
		defer v.connMu.Unlock()
		if m := v.conns[auth]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(v.conns, auth)
			}
		}
	}
}

func (v *Validator) closeIfStillAbsent(auth string) {
	if v.Get(auth) != nil {
		return
	}
	v.connMu.Lock()
	fns := make([]func(), 0, len(v.conns[auth]))
	for _, fn := range v.conns[auth] {
		fns = append(fns, fn)
	}
	v.connMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Add(user *protocol.MemoryUser) (err error) {
	v.mu.Lock()
	v.users.Store(user.Account.(*MemoryAccount).Auth, user)
	if id, err := uuid.Parse(user.Account.(*MemoryAccount).Auth); err == nil {
		id[6] = 0
		id[7] = 0
		v.ids.Store(id, user)
	}
	v.mu.Unlock()
	return
}

func (v *Validator) DelByEmail(email string) (err error) {
	v.mu.Lock()
	if user := v.GetByEmail(email); user != nil {
		auth := user.Account.(*MemoryAccount).Auth
		v.users.Delete(auth)
		if id, err := uuid.Parse(auth); err == nil {
			id[6] = 0
			id[7] = 0
			v.ids.Delete(id)
		}
		time.AfterFunc(removeGrace, func() { v.closeIfStillAbsent(auth) })
	}
	v.mu.Unlock()
	return
}

func (v *Validator) Get(auth string) (user *protocol.MemoryUser) {
	if id, err := uuid.Parse(auth); err == nil {
		if user = v.GetByID(id); user != nil {
			VR := net.PortFromBytes(id[6:8])
			if user.Account.(*MemoryAccount).VR != VR {
				user = &protocol.MemoryUser{
					Email: user.Email,
					Level: user.Level,
					Account: &MemoryAccount{
						Auth: auth,
						VR:   VR,
					},
				}
			}
		}
		return
	}
	if value, ok := v.users.Load(auth); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByID(id uuid.UUID) (user *protocol.MemoryUser) {
	id[6] = 0
	id[7] = 0
	if value, ok := v.ids.Load(id); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByEmail(email string) (user *protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (v *Validator) GetAll() (users []*protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (v *Validator) GetCount() (count int64) {
	v.users.Range(func(key, value any) bool {
		count++
		return true
	})
	return
}

func (v *Validator) NotEmpty() (not_empty bool) {
	v.users.Range(func(key, value any) bool {
		not_empty = true
		return false
	})
	return
}

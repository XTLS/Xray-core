package olcrtc

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator is the olcrtc inbound's dynamic user store.
//
// olcrtc's tunnel is already gated by the shared room key (the cryptographic
// secret every legitimate client holds). A "user" here is therefore an
// allow-listed *identity* — used for authorization, per-user accounting, speed
// limiting and revocation — keyed by the token the client echoes in its
// handshake. In this build the token is the user's email/username; a dedicated
// per-user secret is a planned upgrade (see README).
//
// It follows the sync.Map-backed pattern used by the VLESS/Trojan validators so
// it satisfies proxy.UserManager and is fully drivable at runtime through
// HandlerService (AlterInbound), with no users needed in static config.
type Validator struct {
	users sync.Map // lower(email) -> *protocol.MemoryUser
	count atomic.Int64
}

// NewValidator returns an empty user store. An empty store means "open mode":
// any client holding the room key is admitted (preserving the pre-user-auth
// behaviour). Once at least one user is added, the store enforces the allow list.
func NewValidator() *Validator { return &Validator{} }

// Add inserts a user. Email must be non-empty and unique (case-insensitive); it
// is the key clients present in their handshake. The account, if any, is ignored
// — the room key is the cryptographic gate — so any placeholder account carried
// by the API request is accepted.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u == nil || u.Email == "" {
		return errors.New("olcrtc: user email must not be empty")
	}
	key := strings.ToLower(u.Email)
	if _, loaded := v.users.LoadOrStore(key, u); loaded {
		return errors.New("olcrtc: user ", u.Email, " already exists")
	}
	v.count.Add(1)
	return nil
}

// Del removes a user by email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("olcrtc: email must not be empty")
	}
	key := strings.ToLower(email)
	if _, loaded := v.users.LoadAndDelete(key); !loaded {
		return errors.New("olcrtc: user ", email, " not found")
	}
	v.count.Add(-1)
	return nil
}

// Get resolves the client-presented token (the email/username) to a user, or nil.
func (v *Validator) Get(token string) *protocol.MemoryUser {
	if token == "" {
		return nil
	}
	if u, ok := v.users.Load(strings.ToLower(token)); ok {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// GetByEmail is an alias of Get kept for parity with other validators.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser { return v.Get(email) }

// GetAll returns a snapshot of every registered user.
func (v *Validator) GetAll() []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, 0, v.count.Load())
	v.users.Range(func(_, val any) bool {
		users = append(users, val.(*protocol.MemoryUser))
		return true
	})
	return users
}

// GetCount returns the number of registered users.
func (v *Validator) GetCount() int64 { return v.count.Load() }

// Empty reports whether no users are registered (open mode).
func (v *Validator) Empty() bool { return v.count.Load() == 0 }

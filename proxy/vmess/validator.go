package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

// TimedUserValidator is a user Validator based on time.
type TimedUserValidator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	aeadDecoderHolder   *aead.AuthIDDecoderHolder
	exactUsers          map[[16]byte]*protocol.MemoryUser
	routeIDs            map[*protocol.MemoryUser]uint32
	nextRouteID         uint32
	nextRouteGeneration uint64
	routeSource         routing.UserRouteProvider
	inboundTag          string
	routeSnapshot       routing.UserRouteRules
	routesDirty         bool
	routeError          error
	routeAccounts       map[*protocol.MemoryUser]*cacheAccount
	routeAliasCount     int
	routeCache          *onlineCache
	routeScans          chan struct{}
	cleanupOnce         sync.Once
	cleanupStop         chan struct{}
	closed              bool
}

// NewTimedUserValidator creates a new TimedUserValidator.
func NewTimedUserValidator() *TimedUserValidator {
	tuv := &TimedUserValidator{
		users:             make([]*protocol.MemoryUser, 0, 16),
		aeadDecoderHolder: aead.NewAuthIDDecoderHolder(),
		exactUsers:        make(map[[16]byte]*protocol.MemoryUser),
		routeIDs:          make(map[*protocol.MemoryUser]uint32),
		routeCache:        newOnlineCache(nil, routeCacheBudget, 2*time.Minute, time.Now),
		routeScans:        make(chan struct{}, 2),
		cleanupStop:       make(chan struct{}),
	}
	return tuv
}

func (v *TimedUserValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()
	if v.closed {
		return errors.New("VMess validator closed")
	}

	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("account type is incorrect")
	}
	var cmdkeyfl [16]byte
	copy(cmdkeyfl[:], account.CmdKey())
	if account.UserRoute && v.aeadDecoderHolder.HasUser(cmdkeyfl) {
		return errors.New("duplicate VMess userRoute identity (UUID bytes 7 and 8 do not identify a user)")
	}
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("VMESSBSKDF"))
		hashkdf.Write(account.ID.Bytes())
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	v.users = append(v.users, u)
	v.aeadDecoderHolder.AddUser(cmdkeyfl, u)
	v.exactUsers[cmdkeyfl] = u
	v.nextRouteID++
	v.routeIDs[u] = v.nextRouteID
	v.routesDirty = true

	return nil
}

func (v *TimedUserValidator) GetUsers() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

func (v *TimedUserValidator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

func (v *TimedUserValidator) GetAEAD(userHash []byte) (*protocol.MemoryUser, bool, error) {
	match, err := v.MatchAEAD(userHash)
	if err != nil {
		return nil, false, err
	}
	return match.User, true, nil
}

func (v *TimedUserValidator) Remove(email string) bool {
	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			var cmdkeyfl [16]byte
			copy(cmdkeyfl[:], u.Account.(*MemoryAccount).CmdKey())
			v.aeadDecoderHolder.RemoveUser(cmdkeyfl)
			delete(v.exactUsers, cmdkeyfl)
			v.routeCache.remove(v.routeIDs[u])
			delete(v.routeAccounts, u)
			delete(v.routeIDs, u)
			v.routesDirty = true
			break
		}
	}
	if idx == -1 {
		return false
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return true
}

func (v *TimedUserValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

var ErrNotFound = errors.New("Not Found")

var ErrTainted = errors.New("ErrTainted")

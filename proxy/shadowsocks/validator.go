package shadowsocks

import (
	"crypto/cipher"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	email sync.Map
	users sync.Map
}

// Add a Shadowsocks user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return newError("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(string(u.Account.(*MemoryAccount).Key), u)
	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return newError("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return newError("User ", e, " not found.")
	}
	v.email.Delete(le)
	v.users.Delete(u.(*protocol.MemoryUser).Account.(*MemoryAccount).Key)
	return nil
}

// Get a Shadowsocks user and the user's cipher, nil,nil if user doesn't exist.
func (v *Validator) Get(bs []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	var aeadCipher *AEADCipher
	subkey := make([]byte, 32)
	length := make([]byte, 16)

	v.users.Range(func(key, user interface{}) bool {
		account := user.(*protocol.MemoryUser).Account.(*MemoryAccount)
		aeadCipher = account.Cipher.(*AEADCipher)
		ivLen = aeadCipher.IVSize()
		subkey = subkey[:aeadCipher.KeyBytes]
		hkdfSHA1(account.Key, bs[:ivLen], subkey)
		aead = aeadCipher.AEADAuthCreator(subkey)
		_, err = aead.Open(length[:0], length[4:16], bs[ivLen:ivLen+18], nil)
		if err == nil {
			u = user.(*protocol.MemoryUser)
			return false
		}
		return true
	})

	return
}

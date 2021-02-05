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
	account := u.Account.(*MemoryAccount)

	if !account.Cipher.IsAEAD() && v.Count() > 0 {
		return newError("The cipher do not support Single-port Multi-user")
	}

	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return newError("User ", u.Email, " already exists.")
		}
	}

	v.users.Store(string(account.Key)+"&"+account.GetCipherName(), u)
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
	account := u.(*protocol.MemoryUser).Account.(*MemoryAccount)
	v.email.Delete(le)
	v.users.Delete(string(account.Key) + "&" + account.GetCipherName())
	return nil
}

// Count the number of Shadowsocks users
func (v *Validator) Count() int {
	length := 0
	v.users.Range(func(_, _ interface{}) bool {
		length++

		return true
	})
	return length
}

// Get a Shadowsocks user and the user's cipher.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	var dataSize int

	switch command {
	case protocol.RequestCommandTCP:
		dataSize = 16
	case protocol.RequestCommandUDP:
		dataSize = 8192
	}

	var aeadCipher *AEADCipher
	subkey := make([]byte, 32)
	data := make([]byte, dataSize)

	v.users.Range(func(key, user interface{}) bool {
		account := user.(*protocol.MemoryUser).Account.(*MemoryAccount)
		aeadCipher = account.Cipher.(*AEADCipher)
		ivLen = aeadCipher.IVSize()
		subkey = subkey[:aeadCipher.KeyBytes]
		hkdfSHA1(account.Key, bs[:ivLen], subkey)
		aead = aeadCipher.AEADAuthCreator(subkey)

		switch command {
		case protocol.RequestCommandTCP:
			ret, err = aead.Open(data[:0], data[4:16], bs[ivLen:ivLen+18], nil)
		case protocol.RequestCommandUDP:
			ret, err = aead.Open(data[:0], data[8180:8192], bs[ivLen:], nil)
		}

		if err == nil {
			u = user.(*protocol.MemoryUser)
			return false
		}
		return true
	})

	return
}

// Get the only user without authentication
func (v *Validator) GetOnlyUser() (u *protocol.MemoryUser, ivLen int32) {
	v.users.Range(func(_, user interface{}) bool {
		u = user.(*protocol.MemoryUser)
		return false
	})
	ivLen = u.Account.(*MemoryAccount).Cipher.IVSize()

	return
}

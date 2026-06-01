package salamander

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/xtls/xray-core/common"
	"golang.org/x/crypto/blake2b"
)

const (
	smPSKMinLen = 4
	smSaltLen   = 8
	smKeyLen    = blake2b.Size256
)

var ErrPSKTooShort = fmt.Errorf("PSK must be at least %d bytes", smPSKMinLen)

// SalamanderObfuscator is an obfuscator that obfuscates each packet with
// the BLAKE2b-256 hash of a pre-shared key combined with a random salt.
// Packet format: [8-byte salt][payload]
type SalamanderObfuscator struct {
	PSK     []byte

	lk       sync.Mutex
	keyInput []byte
}

func NewSalamanderObfuscator(psk []byte) (*SalamanderObfuscator, error) {
	if len(psk) < smPSKMinLen {
		return nil, ErrPSKTooShort
	}
	pskCopy := append([]byte(nil), psk...)
	keyInput := make([]byte, len(pskCopy)+smSaltLen)
	copy(keyInput, pskCopy)
	return &SalamanderObfuscator{
		PSK:      pskCopy,
		keyInput: keyInput,
	}, nil
}

func (o *SalamanderObfuscator) Obfuscate(in, out []byte) int {
	outLen := len(in) + smSaltLen
	if len(out) < outLen {
		return 0
	}
	common.Must2(rand.Read(out[:smSaltLen]))
	o.lk.Lock()
	key := o.keyLocked(out[:smSaltLen])
	o.lk.Unlock()
	for i, c := range in {
		out[i+smSaltLen] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *SalamanderObfuscator) Deobfuscate(in, out []byte) int {
	outLen := len(in) - smSaltLen
	if outLen <= 0 || len(out) < outLen {
		return 0
	}
	o.lk.Lock()
	key := o.keyLocked(in[:smSaltLen])
	o.lk.Unlock()
	for i, c := range in[smSaltLen:] {
		out[i] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *SalamanderObfuscator) keyLocked(salt []byte) [smKeyLen]byte {
	copy(o.keyInput[len(o.PSK):], salt[:smSaltLen])
	return blake2b.Sum256(o.keyInput)
}

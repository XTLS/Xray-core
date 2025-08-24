package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"lukechampine.com/blake3"
)

type CommonConn struct {
	net.Conn
	Client    *ClientInstance
	UnitedKey []byte
	PreWrite  []byte
	GCM       *GCM
	PeerGCM   *GCM
	PeerCache []byte
}

func (c *CommonConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var data []byte
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > 8192 {
			b = b[:8192] // for avoiding another copy() in peer's Read()
		}
		n += len(b)
		data = make([]byte, 5+len(b)+16)
		EncodeHeader(data, len(b)+16)
		aead := c.GCM
		if bytes.Equal(c.GCM.Nonce[:], MaxNonce) {
			aead = nil
		}
		c.GCM.Seal(data[:5], nil, b, data[:5])
		if aead == nil {
			c.GCM = NewGCM(data[5:], c.UnitedKey)
		}
		if c.PreWrite != nil {
			data = append(c.PreWrite, data...)
			c.PreWrite = nil
		}
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (c *CommonConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.PeerGCM == nil { // client's 0-RTT
		serverRandom := make([]byte, 32)
		if _, err := io.ReadFull(c.Conn, serverRandom); err != nil {
			return 0, err
		}
		c.PeerGCM = NewGCM(serverRandom, c.UnitedKey)
		if xorConn, ok := c.Conn.(*XorConn); ok {
			xorConn.PeerCTR = NewCTR(c.UnitedKey, serverRandom[16:])
		}
	}
	if len(c.PeerCache) != 0 {
		n := copy(b, c.PeerCache)
		c.PeerCache = c.PeerCache[n:]
		return n, nil
	}
	h, l, err := ReadAndDecodeHeader(c.Conn) // l: 17~17000
	if err != nil {
		if c.Client != nil && strings.HasPrefix(err.Error(), "invalid header: ") { // client's 0-RTT
			c.Client.RWLock.Lock()
			if bytes.Equal(c.UnitedKey[:32], c.Client.PfsKey) {
				c.Client.Expire = time.Now() // expired
			}
			c.Client.RWLock.Unlock()
			return 0, errors.New("new handshake needed")
		}
		return 0, err
	}
	c.Client = nil
	peerData := make([]byte, l)
	if _, err := io.ReadFull(c.Conn, peerData); err != nil {
		return 0, err
	}
	dst := peerData[:l-16]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	var peerAEAD *GCM
	if bytes.Equal(c.PeerGCM.Nonce[:], MaxNonce) {
		peerAEAD = NewGCM(peerData, c.UnitedKey)
	}
	_, err = c.PeerGCM.Open(dst[:0], nil, peerData, h)
	if peerAEAD != nil {
		c.PeerGCM = peerAEAD
	}
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.PeerCache = dst[copy(b, dst):]
		dst = b // for len(dst)
	}
	return len(dst), nil
}

type GCM struct {
	cipher.AEAD
	Nonce [12]byte
}

func NewGCM(ctx, key []byte) *GCM {
	k := make([]byte, 32)
	blake3.DeriveKey(k, string(ctx), key)
	block, _ := aes.NewCipher(k)
	aead, _ := cipher.NewGCM(block)
	return &GCM{AEAD: aead}
	//chacha20poly1305.New()
}

func (a *GCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if nonce == nil {
		nonce = IncreaseNonce(a.Nonce[:])
	}
	return a.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

func (a *GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if nonce == nil {
		nonce = IncreaseNonce(a.Nonce[:])
	}
	return a.AEAD.Open(dst, nonce, ciphertext, additionalData)
}

func IncreaseNonce(nonce []byte) []byte {
	for i := range 12 {
		nonce[11-i]++
		if nonce[11-i] != 0 {
			break
		}
	}
	return nonce
}

var MaxNonce = bytes.Repeat([]byte{255}, 12)

func EncodeLength(l int) []byte {
	return []byte{byte(l >> 8), byte(l)}
}

func DecodeLength(b []byte) int {
	return int(b[0])<<8 | int(b[1])
}

func EncodeHeader(h []byte, l int) {
	h[0] = 23
	h[1] = 3
	h[2] = 3
	h[3] = byte(l >> 8)
	h[4] = byte(l)
}

func DecodeHeader(h []byte) (l int, err error) {
	l = int(h[3])<<8 | int(h[4])
	if h[0] != 23 || h[1] != 3 || h[2] != 3 {
		l = 0
	}
	if l < 17 || l > 17000 { // TODO: TLSv1.3 max length
		err = errors.New("invalid header: ", fmt.Sprintf("%v", h[:5])) // DO NOT CHANGE: relied by client's Read()
	}
	return
}

func ReadAndDecodeHeader(conn net.Conn) (h []byte, l int, err error) {
	h = make([]byte, 5)
	if _, err = io.ReadFull(conn, h); err != nil {
		return
	}
	l, err = DecodeHeader(h)
	return
}

func ReadAndDiscardPaddings(conn net.Conn) (h []byte, l int, err error) {
	for {
		if h, l, err = ReadAndDecodeHeader(conn); err != nil {
			return
		}
		if _, err = io.ReadFull(conn, make([]byte, l)); err != nil {
			return
		}
	}
}

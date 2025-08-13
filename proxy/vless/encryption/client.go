package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

var ClientCipher byte

func init() {
	if protocol.HasAESGCMHardwareSupport {
		ClientCipher = 1
	}
}

type ClientInstance struct {
	sync.RWMutex
	nfsEKey      *mlkem.EncapsulationKey768
	nfsEKeyBytes []byte
	xor          uint32
	minutes      time.Duration
	expire       time.Time
	baseKey      []byte
	ticket       []byte
}

type ClientConn struct {
	net.Conn
	instance  *ClientInstance
	baseKey   []byte
	ticket    []byte
	random    []byte
	aead      cipher.AEAD
	nonce     []byte
	peerAead  cipher.AEAD
	peerNonce []byte
	peerCache []byte
}

func (i *ClientInstance) Init(nfsEKeyBytes []byte, xor uint32, minutes time.Duration) (err error) {
	i.nfsEKey, err = mlkem.NewEncapsulationKey768(nfsEKeyBytes)
	if xor > 0 {
		i.nfsEKeyBytes = nfsEKeyBytes
		i.xor = xor
	}
	i.minutes = minutes
	return
}

func (i *ClientInstance) Handshake(conn net.Conn) (net.Conn, error) {
	if i.nfsEKey == nil {
		return nil, errors.New("uninitialized")
	}
	if i.xor > 0 {
		conn = NewXorConn(conn, i.nfsEKeyBytes)
	}
	c := &ClientConn{Conn: conn}

	if i.minutes > 0 {
		i.RLock()
		if time.Now().Before(i.expire) {
			c.instance = i
			c.baseKey = i.baseKey
			c.ticket = i.ticket
			i.RUnlock()
			return c, nil
		}
		i.RUnlock()
	}

	pfsDKeySeed := make([]byte, 64)
	rand.Read(pfsDKeySeed)
	pfsDKey, _ := mlkem.NewDecapsulationKey768(pfsDKeySeed)
	pfsEKeyBytes := pfsDKey.EncapsulationKey().Bytes()
	nfsKey, encapsulatedNfsKey := i.nfsEKey.Encapsulate()
	paddingLen := crypto.RandBetween(100, 1000)

	clientHello := make([]byte, 5+1+1184+1088+5+paddingLen)
	EncodeHeader(clientHello, 1, 1+1184+1088)
	clientHello[5] = ClientCipher
	copy(clientHello[5+1:], pfsEKeyBytes)
	copy(clientHello[5+1+1184:], encapsulatedNfsKey)
	EncodeHeader(clientHello[5+1+1184+1088:], 23, int(paddingLen))
	rand.Read(clientHello[5+1+1184+1088+5:])

	if n, err := c.Conn.Write(clientHello); n != len(clientHello) || err != nil {
		return nil, err
	}
	// client can send more padding / NFS AEAD messages if needed

	_, t, l, err := ReadAndDecodeHeader(c.Conn)
	if err != nil {
		return nil, err
	}
	if t != 1 {
		return nil, errors.New("unexpected type ", t, ", expect server hello")
	}

	peerServerHello := make([]byte, 1088+21)
	if l != len(peerServerHello) {
		return nil, errors.New("unexpected length ", l, " for server hello")
	}
	if _, err := io.ReadFull(c.Conn, peerServerHello); err != nil {
		return nil, err
	}
	encapsulatedPfsKey := peerServerHello[:1088]
	c.ticket = peerServerHello[1088:]

	pfsKey, err := pfsDKey.Decapsulate(encapsulatedPfsKey)
	if err != nil {
		return nil, err
	}
	c.baseKey = append(pfsKey, nfsKey...)

	nonce := [12]byte{ClientCipher}
	VLESS, _ := NewAead(ClientCipher, c.baseKey, encapsulatedPfsKey, encapsulatedNfsKey).Open(nil, nonce[:], c.ticket, pfsEKeyBytes)
	if !bytes.Equal(VLESS, []byte("VLESS")) {
		return nil, errors.New("invalid server").AtError()
	}

	if i.minutes > 0 {
		i.Lock()
		i.expire = time.Now().Add(i.minutes)
		i.baseKey = c.baseKey
		i.ticket = c.ticket
		i.Unlock()
	}

	return c, nil
}

func (c *ClientConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var data []byte
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > 8192 {
			b = b[:8192] // for avoiding another copy() in server's Read()
		}
		n += len(b)
		if c.aead == nil {
			c.random = make([]byte, 32)
			rand.Read(c.random)
			c.aead = NewAead(ClientCipher, c.baseKey, c.random, c.ticket)
			c.nonce = make([]byte, 12)
			data = make([]byte, 5+21+32+5+len(b)+16)
			EncodeHeader(data, 0, 21+32)
			copy(data[5:], c.ticket)
			copy(data[5+21:], c.random)
			EncodeHeader(data[5+21+32:], 23, len(b)+16)
			c.aead.Seal(data[:5+21+32+5], c.nonce, b, data[5+21+32:5+21+32+5])
		} else {
			data = make([]byte, 5+len(b)+16)
			EncodeHeader(data, 23, len(b)+16)
			c.aead.Seal(data[:5], c.nonce, b, data[:5])
			if bytes.Equal(c.nonce, MaxNonce) {
				c.aead = NewAead(ClientCipher, c.baseKey, data[5:], data[:5])
			}
		}
		IncreaseNonce(c.nonce)
		if n, err := c.Conn.Write(data); n != len(data) || err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (c *ClientConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.peerAead == nil {
		var t byte
		var l int
		var err error
		if c.instance == nil { // 1-RTT
			for {
				if _, t, l, err = ReadAndDecodeHeader(c.Conn); err != nil {
					return 0, err
				}
				if t != 23 {
					break
				}
				if _, err := io.ReadFull(c.Conn, make([]byte, l)); err != nil {
					return 0, err
				}
			}
		} else {
			h := make([]byte, 5)
			if _, err := io.ReadFull(c.Conn, h); err != nil {
				return 0, err
			}
			if t, l, err = DecodeHeader(h); err != nil {
				c.instance.Lock()
				if bytes.Equal(c.ticket, c.instance.ticket) {
					c.instance.expire = time.Now() // expired
				}
				c.instance.Unlock()
				return 0, errors.New("new handshake needed")
			}
		}
		if t != 0 {
			return 0, errors.New("unexpected type ", t, ", expect random hello")
		}
		peerRandomHello := make([]byte, 32)
		if l != len(peerRandomHello) {
			return 0, errors.New("unexpected length ", l, " for random hello")
		}
		if _, err := io.ReadFull(c.Conn, peerRandomHello); err != nil {
			return 0, err
		}
		if c.random == nil {
			return 0, errors.New("empty c.random")
		}
		c.peerAead = NewAead(ClientCipher, c.baseKey, peerRandomHello, c.random)
		c.peerNonce = make([]byte, 12)
	}
	if len(c.peerCache) != 0 {
		n := copy(b, c.peerCache)
		c.peerCache = c.peerCache[n:]
		return n, nil
	}
	h, t, l, err := ReadAndDecodeHeader(c.Conn) // l: 17~17000
	if err != nil {
		return 0, err
	}
	if t != 23 {
		return 0, errors.New("unexpected type ", t, ", expect encrypted data")
	}
	peerData := make([]byte, l)
	if _, err := io.ReadFull(c.Conn, peerData); err != nil {
		return 0, err
	}
	dst := peerData[:l-16]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	var peerAead cipher.AEAD
	if bytes.Equal(c.peerNonce, MaxNonce) {
		peerAead = NewAead(ClientCipher, c.baseKey, peerData, h)
	}
	_, err = c.peerAead.Open(dst[:0], c.peerNonce, peerData, h)
	if peerAead != nil {
		c.peerAead = peerAead
	}
	IncreaseNonce(c.peerNonce)
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.peerCache = dst[copy(b, dst):]
		dst = b // for len(dst)
	}
	return len(dst), nil
}

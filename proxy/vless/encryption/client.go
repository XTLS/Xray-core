package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"io"
	"net"
	"strings"
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
	nfsEKey *mlkem.EncapsulationKey768
	hash11  [11]byte // no more capacity
	xorMode uint32
	xorPKey *ecdh.PublicKey
	minutes time.Duration
	expire  time.Time
	baseKey []byte
	ticket  []byte
}

type ClientConn struct {
	net.Conn
	instance  *ClientInstance
	baseKey   []byte
	ticket    []byte
	random    []byte
	aead      cipher.AEAD
	nonce     []byte
	peerAEAD  cipher.AEAD
	peerNonce []byte
	PeerCache []byte
}

func (i *ClientInstance) Init(nfsEKeyBytes, xorPKeyBytes []byte, xorMode, minutes uint32) (err error) {
	if i.nfsEKey != nil {
		err = errors.New("already initialized")
		return
	}
	if i.nfsEKey, err = mlkem.NewEncapsulationKey768(nfsEKeyBytes); err != nil {
		return
	}
	if xorMode > 0 {
		i.xorMode = xorMode
		if i.xorPKey, err = ecdh.X25519().NewPublicKey(xorPKeyBytes); err != nil {
			return
		}
		hash32 := sha3.Sum256(nfsEKeyBytes)
		copy(i.hash11[:], hash32[:])
	}
	i.minutes = time.Duration(minutes) * time.Minute
	return
}

func (i *ClientInstance) Handshake(conn net.Conn) (*ClientConn, error) {
	if i.nfsEKey == nil {
		return nil, errors.New("uninitialized")
	}
	if i.xorMode > 0 {
		conn, _ = NewXorConn(conn, i.xorMode, i.xorPKey, nil)
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
	nfsAEAD := NewAEAD(ClientCipher, nfsKey, pfsEKeyBytes, encapsulatedNfsKey)

	clientHello := make([]byte, 5+11+1+1184+1088+crypto.RandBetween(100, 1000))
	EncodeHeader(clientHello, 1, 11+1+1184+1088)
	copy(clientHello[5:], i.hash11[:])
	clientHello[5+11] = ClientCipher
	copy(clientHello[5+11+1:], pfsEKeyBytes)
	copy(clientHello[5+11+1+1184:], encapsulatedNfsKey)
	padding := clientHello[5+11+1+1184+1088:]
	rand.Read(padding) // important
	EncodeHeader(padding, 23, len(padding)-5)
	nfsAEAD.Seal(padding[:5], clientHello[5:5+11+1], padding[5:len(padding)-16], padding[:5])

	if _, err := c.Conn.Write(clientHello); err != nil {
		return nil, err
	}
	// client can send more NFS AEAD paddings / messages if needed

	_, t, l, err := ReadAndDiscardPaddings(c.Conn, nil, nil) // allow paddings before server hello
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
	c.ticket = append(i.hash11[:], peerServerHello[1088:]...)

	pfsKey, err := pfsDKey.Decapsulate(encapsulatedPfsKey)
	if err != nil {
		return nil, err
	}
	c.baseKey = append(pfsKey, nfsKey...)

	VLESS, _ := NewAEAD(ClientCipher, c.baseKey, encapsulatedPfsKey, encapsulatedNfsKey).Open(nil, append(i.hash11[:], ClientCipher), c.ticket[11:], pfsEKeyBytes)
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
			data = make([]byte, 5+32+32+5+len(b)+16)
			EncodeHeader(data, 0, 32+32)
			copy(data[5:], c.ticket)
			c.random = make([]byte, 32)
			rand.Read(c.random)
			copy(data[5+32:], c.random)
			EncodeHeader(data[5+32+32:], 23, len(b)+16)
			c.aead = NewAEAD(ClientCipher, c.baseKey, c.random, c.ticket)
			c.nonce = make([]byte, 12)
			c.aead.Seal(data[:5+32+32+5], c.nonce, b, data[5+32+32:5+32+32+5])
		} else {
			data = make([]byte, 5+len(b)+16)
			EncodeHeader(data, 23, len(b)+16)
			c.aead.Seal(data[:5], c.nonce, b, data[:5])
			if bytes.Equal(c.nonce, MaxNonce) {
				c.aead = NewAEAD(ClientCipher, c.baseKey, data[5:], data[:5])
			}
		}
		IncreaseNonce(c.nonce)
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (c *ClientConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.peerAEAD == nil {
		_, t, l, err := ReadAndDiscardPaddings(c.Conn, nil, nil) // allow paddings before random hello
		if err != nil {
			if c.instance != nil && strings.HasPrefix(err.Error(), "invalid header: ") { // 0-RTT
				c.instance.Lock()
				if bytes.Equal(c.ticket, c.instance.ticket) {
					c.instance.expire = time.Now() // expired
				}
				c.instance.Unlock()
				return 0, errors.New("new handshake needed")
			}
			return 0, err
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
		c.peerAEAD = NewAEAD(ClientCipher, c.baseKey, peerRandomHello, c.random)
		c.peerNonce = make([]byte, 12)
	}
	if len(c.PeerCache) != 0 {
		n := copy(b, c.PeerCache)
		c.PeerCache = c.PeerCache[n:]
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
	var peerAEAD cipher.AEAD
	if bytes.Equal(c.peerNonce, MaxNonce) {
		peerAEAD = NewAEAD(ClientCipher, c.baseKey, peerData, h)
	}
	_, err = c.peerAEAD.Open(dst[:0], c.peerNonce, peerData, h)
	if peerAEAD != nil {
		c.peerAEAD = peerAEAD
	}
	IncreaseNonce(c.peerNonce)
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.PeerCache = dst[copy(b, dst):]
		dst = b // for len(dst)
	}
	return len(dst), nil
}

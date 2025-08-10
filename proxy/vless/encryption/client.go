package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/hkdf"
)

var ClientCipher byte

func init() {
	if !protocol.HasAESGCMHardwareSupport {
		ClientCipher = 1
	}
}

type ClientInstance struct {
	sync.RWMutex
	eKeyNfs *mlkem.EncapsulationKey768
	minutes time.Duration
	expire  time.Time
	baseKey []byte
	reuse   []byte
}

type ClientConn struct {
	net.Conn
	instance  *ClientInstance
	baseKey   []byte
	reuse     []byte
	random    []byte
	aead      cipher.AEAD
	nonce     []byte
	peerAead  cipher.AEAD
	peerNonce []byte
	peerCache []byte
}

func (i *ClientInstance) Init(eKeyNfsData []byte, minutes time.Duration) (err error) {
	i.eKeyNfs, err = mlkem.NewEncapsulationKey768(eKeyNfsData)
	i.minutes = minutes
	return
}

func (i *ClientInstance) Handshake(conn net.Conn) (net.Conn, error) {
	if i.eKeyNfs == nil {
		return nil, errors.New("uninitialized")
	}
	c := &ClientConn{Conn: conn}

	if i.minutes > 0 {
		i.RLock()
		if time.Now().Before(i.expire) {
			c.instance = i
			c.baseKey = i.baseKey
			c.reuse = i.reuse
			i.RUnlock()
			return c, nil
		}
		i.RUnlock()
	}

	nfsKey, encapsulatedNfsKey := i.eKeyNfs.Encapsulate()
	seed := make([]byte, 64)
	rand.Read(seed)
	dKeyPfs, _ := mlkem.NewDecapsulationKey768(seed)
	eKeyPfs := dKeyPfs.EncapsulationKey().Bytes()
	padding := crypto.RandBetween(100, 1000)

	clientHello := make([]byte, 1088+1184+1+5+padding)
	copy(clientHello, encapsulatedNfsKey)
	copy(clientHello[1088:], eKeyPfs)
	clientHello[2272] = ClientCipher
	encodeHeader(clientHello[2273:], int(padding))

	if _, err := c.Conn.Write(clientHello); err != nil {
		return nil, err
	}
	// we can send more padding if needed

	peerServerHello := make([]byte, 1088+21)
	if _, err := io.ReadFull(c.Conn, peerServerHello); err != nil {
		return nil, err
	}
	encapsulatedPfsKey := peerServerHello[:1088]
	c.reuse = peerServerHello[1088:]

	pfsKey, err := dKeyPfs.Decapsulate(encapsulatedPfsKey)
	if err != nil {
		return nil, err
	}
	c.baseKey = append(nfsKey, pfsKey...)

	authKey := make([]byte, 32)
	hkdf.New(sha256.New, c.baseKey, encapsulatedNfsKey, eKeyPfs).Read(authKey)
	nonce := make([]byte, 12)
	VLESS, _ := newAead(ClientCipher, authKey).Open(nil, nonce, c.reuse, encapsulatedPfsKey)
	if !bytes.Equal(VLESS, []byte("VLESS")) { // TODO: more message
		return nil, errors.New("invalid server").AtError()
	}

	if i.minutes > 0 {
		i.Lock()
		i.expire = time.Now().Add(i.minutes)
		i.baseKey = c.baseKey
		i.reuse = c.reuse
		i.Unlock()
	}

	return c, nil
}

func (c *ClientConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var data []byte
	if c.aead == nil {
		c.random = make([]byte, 32)
		rand.Read(c.random)
		key := make([]byte, 32)
		hkdf.New(sha256.New, c.baseKey, c.random, c.reuse).Read(key)
		c.aead = newAead(ClientCipher, key)
		c.nonce = make([]byte, 12)

		data = make([]byte, 21+32+5+len(b)+16)
		copy(data, c.reuse)
		copy(data[21:], c.random)
		encodeHeader(data[53:], len(b)+16)
		c.aead.Seal(data[:58], c.nonce, b, data[53:58])
	} else {
		data = make([]byte, 5+len(b)+16)
		encodeHeader(data, len(b)+16)
		c.aead.Seal(data[:5], c.nonce, b, data[:5])
	}
	increaseNonce(c.nonce)
	if _, err := c.Conn.Write(data); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ClientConn) Read(b []byte) (int, error) { // after first Write()
	if len(b) == 0 {
		return 0, nil
	}
	peerHeader := make([]byte, 5)
	if c.peerAead == nil {
		if c.instance == nil {
			for {
				if _, err := io.ReadFull(c.Conn, peerHeader); err != nil {
					return 0, err
				}
				peerPadding, _ := decodeHeader(peerHeader)
				if peerPadding == 0 {
					break
				}
				if _, err := io.ReadFull(c.Conn, make([]byte, peerPadding)); err != nil {
					return 0, err
				}
			}
		} else {
			if _, err := io.ReadFull(c.Conn, peerHeader); err != nil {
				return 0, err
			}
		}
		peerRandom := make([]byte, 32)
		copy(peerRandom, peerHeader)
		if _, err := io.ReadFull(c.Conn, peerRandom[5:]); err != nil {
			return 0, err
		}
		if c.random == nil {
			return 0, errors.New("can not Read() first")
		}
		peerKey := make([]byte, 32)
		hkdf.New(sha256.New, c.baseKey, peerRandom, c.random).Read(peerKey)
		c.peerAead = newAead(ClientCipher, peerKey)
		c.peerNonce = make([]byte, 12)
	}
	if len(c.peerCache) != 0 {
		n := copy(b, c.peerCache)
		c.peerCache = c.peerCache[n:]
		return n, nil
	}
	if _, err := io.ReadFull(c.Conn, peerHeader); err != nil {
		return 0, err
	}
	peerLength, err := decodeHeader(peerHeader) // 17~17000
	if err != nil {
		if c.instance != nil {
			c.instance.Lock()
			if bytes.Equal(c.reuse, c.instance.reuse) {
				c.instance.expire = time.Now() // expired
			}
			c.instance.Unlock()
		}
		return 0, err
	}
	peerData := make([]byte, peerLength)
	if _, err := io.ReadFull(c.Conn, peerData); err != nil {
		return 0, err
	}
	dst := peerData[:peerLength-16]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // max=8192 is recommended for peer
	}
	_, err = c.peerAead.Open(dst[:0], c.peerNonce, peerData, peerHeader)
	increaseNonce(c.peerNonce)
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.peerCache = dst[copy(b, dst):]
		dst = b // for len(dst)
	}
	return len(dst), nil
}

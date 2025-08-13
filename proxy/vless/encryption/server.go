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
)

type ServerSession struct {
	expire  time.Time
	cipher  byte
	baseKey []byte
	randoms sync.Map
}

type ServerInstance struct {
	sync.RWMutex
	nfsDKey       *mlkem.DecapsulationKey768
	nfsEKeySha256 [32]byte
	xor           uint32
	minutes       time.Duration
	sessions      map[[21]byte]*ServerSession
	closed        bool
}

type ServerConn struct {
	net.Conn
	cipher     byte
	baseKey    []byte
	ticket     []byte
	peerRandom []byte
	peerAead   cipher.AEAD
	peerNonce  []byte
	peerCache  []byte
	aead       cipher.AEAD
	nonce      []byte
}

func (i *ServerInstance) Init(nfsDKeySeed []byte, xor uint32, minutes time.Duration) (err error) {
	i.nfsDKey, err = mlkem.NewDecapsulationKey768(nfsDKeySeed)
	if xor > 0 {
		i.nfsEKeySha256 = sha256.Sum256(i.nfsDKey.EncapsulationKey().Bytes())
		i.xor = xor
	}
	if minutes > 0 {
		i.minutes = minutes
		i.sessions = make(map[[21]byte]*ServerSession)
		go func() {
			for {
				time.Sleep(time.Minute)
				i.Lock()
				if i.closed {
					i.Unlock()
					return
				}
				now := time.Now()
				for ticket, session := range i.sessions {
					if now.After(session.expire) {
						delete(i.sessions, ticket)
					}
				}
				i.Unlock()
			}
		}()
	}
	return
}

func (i *ServerInstance) Close() (err error) {
	i.Lock()
	i.closed = true
	i.Unlock()
	return
}

func (i *ServerInstance) Handshake(conn net.Conn) (net.Conn, error) {
	if i.nfsDKey == nil {
		return nil, errors.New("uninitialized")
	}
	if i.xor > 0 {
		conn = NewXorConn(conn, i.nfsEKeySha256[:])
	}
	c := &ServerConn{Conn: conn}

	_, t, l, err := ReadAndDecodeHeader(c.Conn)
	if err != nil {
		return nil, err
	}
	if t == 23 {
		return nil, errors.New("unexpected data")
	}

	if t == 0 {
		if i.minutes == 0 {
			return nil, errors.New("0-RTT is not allowed")
		}
		peerTicketHello := make([]byte, 21+32)
		if l != len(peerTicketHello) {
			return nil, errors.New("unexpected length ", l, " for ticket hello")
		}
		if _, err := io.ReadFull(c.Conn, peerTicketHello); err != nil {
			return nil, err
		}
		i.RLock()
		s := i.sessions[[21]byte(peerTicketHello)]
		i.RUnlock()
		if s == nil {
			noise := make([]byte, crypto.RandBetween(100, 1000))
			rand.Read(noise)
			c.Conn.Write(noise) // make client do new handshake
			return nil, errors.New("expired ticket")
		}
		if _, replay := s.randoms.LoadOrStore([32]byte(peerTicketHello[21:]), true); replay {
			return nil, errors.New("replay detected")
		}
		c.cipher = s.cipher
		c.baseKey = s.baseKey
		c.ticket = peerTicketHello[:21]
		c.peerRandom = peerTicketHello[21:]
		return c, nil
	}

	peerClientHello := make([]byte, 1+1184+1088)
	if l != len(peerClientHello) {
		return nil, errors.New("unexpected length ", l, " for client hello")
	}
	if _, err := io.ReadFull(c.Conn, peerClientHello); err != nil {
		return nil, err
	}
	c.cipher = peerClientHello[0]
	pfsEKeyBytes := peerClientHello[1:1185]
	encapsulatedNfsKey := peerClientHello[1185:2273]

	pfsEKey, err := mlkem.NewEncapsulationKey768(pfsEKeyBytes)
	if err != nil {
		return nil, err
	}
	nfsKey, err := i.nfsDKey.Decapsulate(encapsulatedNfsKey)
	if err != nil {
		return nil, err
	}
	pfsKey, encapsulatedPfsKey := pfsEKey.Encapsulate()
	c.baseKey = append(pfsKey, nfsKey...)

	nonce := [12]byte{c.cipher}
	c.ticket = NewAead(c.cipher, c.baseKey, encapsulatedPfsKey, encapsulatedNfsKey).Seal(nil, nonce[:], []byte("VLESS"), pfsEKeyBytes)

	paddingLen := crypto.RandBetween(100, 1000)

	serverHello := make([]byte, 5+1088+21+5+paddingLen)
	EncodeHeader(serverHello, 1, 1088+21)
	copy(serverHello[5:], encapsulatedPfsKey)
	copy(serverHello[5+1088:], c.ticket)
	EncodeHeader(serverHello[5+1088+21:], 23, int(paddingLen))
	rand.Read(serverHello[5+1088+21+5:])

	if _, err := c.Conn.Write(serverHello); err != nil {
		return nil, err
	}
	// server can send more padding / PFS AEAD messages if needed

	if i.minutes > 0 {
		i.Lock()
		i.sessions[[21]byte(c.ticket)] = &ServerSession{
			expire:  time.Now().Add(i.minutes),
			cipher:  c.cipher,
			baseKey: c.baseKey,
		}
		i.Unlock()
	}

	return c, nil
}

func (c *ServerConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.peerAead == nil {
		if c.peerRandom == nil { // from 1-RTT
			var t byte
			var l int
			var err error
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
			if t != 0 {
				return 0, errors.New("unexpected type ", t, ", expect ticket hello")
			}
			peerTicketHello := make([]byte, 21+32)
			if l != len(peerTicketHello) {
				return 0, errors.New("unexpected length ", l, " for ticket hello")
			}
			if _, err := io.ReadFull(c.Conn, peerTicketHello); err != nil {
				return 0, err
			}
			if !bytes.Equal(peerTicketHello[:21], c.ticket) {
				return 0, errors.New("naughty boy")
			}
			c.peerRandom = peerTicketHello[21:]
		}
		c.peerAead = NewAead(c.cipher, c.baseKey, c.peerRandom, c.ticket)
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
		peerAead = NewAead(c.cipher, c.baseKey, peerData, h)
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

func (c *ServerConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var data []byte
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > 8192 {
			b = b[:8192] // for avoiding another copy() in client's Read()
		}
		n += len(b)
		if c.aead == nil {
			if c.peerRandom == nil {
				return 0, errors.New("empty c.peerRandom")
			}
			data = make([]byte, 5+32+5+len(b)+16)
			EncodeHeader(data, 0, 32)
			rand.Read(data[5 : 5+32])
			c.aead = NewAead(c.cipher, c.baseKey, data[5:5+32], c.peerRandom)
			c.nonce = make([]byte, 12)
			EncodeHeader(data[5+32:], 23, len(b)+16)
			c.aead.Seal(data[:5+32+5], c.nonce, b, data[5+32:5+32+5])
		} else {
			data = make([]byte, 5+len(b)+16)
			EncodeHeader(data, 23, len(b)+16)
			c.aead.Seal(data[:5], c.nonce, b, data[:5])
			if bytes.Equal(c.nonce, MaxNonce) {
				c.aead = NewAead(c.cipher, c.baseKey, data[5:], data[:5])
			}
		}
		IncreaseNonce(c.nonce)
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

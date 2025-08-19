package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
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
	nfsDKey  *mlkem.DecapsulationKey768
	hash11   [11]byte // no more capacity
	xorKey   []byte
	minutes  time.Duration
	sessions map[[32]byte]*ServerSession
	closed   bool
}

type ServerConn struct {
	net.Conn
	cipher     byte
	baseKey    []byte
	ticket     []byte
	peerRandom []byte
	peerAead   cipher.AEAD
	peerNonce  []byte
	PeerCache  []byte
	aead       cipher.AEAD
	nonce      []byte
}

func (i *ServerInstance) Init(nfsDKeySeed []byte, xor uint32, minutes time.Duration) (err error) {
	if i.nfsDKey != nil {
		err = errors.New("already initialized")
		return
	}
	i.nfsDKey, err = mlkem.NewDecapsulationKey768(nfsDKeySeed)
	if err != nil {
		return
	}
	hash32 := sha3.Sum256(i.nfsDKey.EncapsulationKey().Bytes())
	copy(i.hash11[:], hash32[:])
	if xor > 0 {
		xorKey := sha3.Sum256(i.nfsDKey.EncapsulationKey().Bytes())
		i.xorKey = xorKey[:]
	}
	if minutes > 0 {
		i.minutes = minutes
		i.sessions = make(map[[32]byte]*ServerSession)
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

func (i *ServerInstance) Handshake(conn net.Conn) (*ServerConn, error) {
	if i.nfsDKey == nil {
		return nil, errors.New("uninitialized")
	}
	if i.xorKey != nil {
		conn = NewXorConn(conn, i.xorKey)
	}
	c := &ServerConn{Conn: conn}

	_, t, l, err := ReadAndDiscardPaddings(c.Conn) // allow paddings before client/ticket hello
	if err != nil {
		return nil, err
	}

	if t == 0 {
		if i.minutes == 0 {
			return nil, errors.New("0-RTT is not allowed")
		}
		peerTicketHello := make([]byte, 32+32)
		if l != len(peerTicketHello) {
			return nil, errors.New("unexpected length ", l, " for ticket hello")
		}
		if _, err := io.ReadFull(c.Conn, peerTicketHello); err != nil {
			return nil, err
		}
		if !bytes.Equal(peerTicketHello[:11], i.hash11[:]) {
			return nil, errors.New("unexpected hash11: ", fmt.Sprintf("%v", peerTicketHello[:11]))
		}
		i.RLock()
		s := i.sessions[[32]byte(peerTicketHello)]
		i.RUnlock()
		if s == nil {
			noises := make([]byte, crypto.RandBetween(100, 1000))
			var err error
			for err == nil {
				rand.Read(noises)
				_, _, err = DecodeHeader(noises)
			}
			c.Conn.Write(noises) // make client do new handshake
			return nil, errors.New("expired ticket")
		}
		if _, replay := s.randoms.LoadOrStore([32]byte(peerTicketHello[32:]), true); replay {
			return nil, errors.New("replay detected")
		}
		c.cipher = s.cipher
		c.baseKey = s.baseKey
		c.ticket = peerTicketHello[:32]
		c.peerRandom = peerTicketHello[32:]
		return c, nil
	}

	peerClientHello := make([]byte, 11+1+1184+1088)
	if l != len(peerClientHello) {
		return nil, errors.New("unexpected length ", l, " for client hello")
	}
	if _, err := io.ReadFull(c.Conn, peerClientHello); err != nil {
		return nil, err
	}
	if !bytes.Equal(peerClientHello[:11], i.hash11[:]) {
		return nil, errors.New("unexpected hash11: ", fmt.Sprintf("%v", peerClientHello[:11]))
	}
	c.cipher = peerClientHello[11]
	pfsEKeyBytes := peerClientHello[11+1 : 11+1+1184]
	encapsulatedNfsKey := peerClientHello[11+1+1184:]

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

	c.ticket = append(i.hash11[:], NewAead(c.cipher, c.baseKey, encapsulatedPfsKey, encapsulatedNfsKey).Seal(nil, peerClientHello[:12], []byte("VLESS"), pfsEKeyBytes)...)

	paddingLen := crypto.RandBetween(100, 1000)

	serverHello := make([]byte, 5+1088+21+5+paddingLen)
	EncodeHeader(serverHello, 1, 1088+21)
	copy(serverHello[5:], encapsulatedPfsKey)
	copy(serverHello[5+1088:], c.ticket[11:])
	EncodeHeader(serverHello[5+1088+21:], 23, int(paddingLen))
	rand.Read(serverHello[5+1088+21+5:])

	if _, err := c.Conn.Write(serverHello); err != nil {
		return nil, err
	}
	// server can send more paddings / PFS AEAD messages if needed

	if i.minutes > 0 {
		i.Lock()
		i.sessions[[32]byte(c.ticket)] = &ServerSession{
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
		if c.peerRandom == nil { // 1-RTT's 0-RTT
			_, t, l, err := ReadAndDiscardPaddings(c.Conn) // allow paddings before ticket hello
			if err != nil {
				return 0, err
			}
			if t != 0 {
				return 0, errors.New("unexpected type ", t, ", expect ticket hello")
			}
			peerTicketHello := make([]byte, 32+32)
			if l != len(peerTicketHello) {
				return 0, errors.New("unexpected length ", l, " for ticket hello")
			}
			if _, err := io.ReadFull(c.Conn, peerTicketHello); err != nil {
				return 0, err
			}
			if !bytes.Equal(peerTicketHello[:32], c.ticket) {
				return 0, errors.New("naughty boy")
			}
			c.peerRandom = peerTicketHello[32:]
		}
		c.peerAead = NewAead(c.cipher, c.baseKey, c.peerRandom, c.ticket)
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
		c.PeerCache = dst[copy(b, dst):]
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
			EncodeHeader(data[5+32:], 23, len(b)+16)
			c.aead = NewAead(c.cipher, c.baseKey, data[5:5+32], c.peerRandom)
			c.nonce = make([]byte, 12)
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

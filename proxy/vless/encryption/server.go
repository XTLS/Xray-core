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
	"golang.org/x/crypto/hkdf"
)

type ServerSession struct {
	expire  time.Time
	cipher  byte
	baseKey []byte
	randoms sync.Map
}

type ServerInstance struct {
	sync.RWMutex
	nfsDKey      *mlkem.DecapsulationKey768
	nfsEKeyBytes []byte
	xor          uint32
	minutes      time.Duration
	sessions     map[[21]byte]*ServerSession
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
		i.nfsEKeyBytes = i.nfsDKey.EncapsulationKey().Bytes()
		i.xor = xor
	}
	if minutes > 0 {
		i.minutes = minutes
		i.sessions = make(map[[21]byte]*ServerSession)
		go func() {
			for {
				time.Sleep(time.Minute)
				now := time.Now()
				i.Lock()
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

func (i *ServerInstance) Handshake(conn net.Conn) (net.Conn, error) {
	if i.nfsDKey == nil {
		return nil, errors.New("uninitialized")
	}
	if i.xor > 0 {
		conn = NewXorConn(conn, i.nfsEKeyBytes)
	}
	c := &ServerConn{Conn: conn}

	peerTicketHello := make([]byte, 21+32)
	if _, err := io.ReadFull(c.Conn, peerTicketHello); err != nil {
		return nil, err
	}
	if i.minutes > 0 {
		i.RLock()
		s := i.sessions[[21]byte(peerTicketHello)]
		i.RUnlock()
		if s != nil {
			if _, replay := s.randoms.LoadOrStore([32]byte(peerTicketHello[21:]), true); !replay {
				c.cipher = s.cipher
				c.baseKey = s.baseKey
				c.ticket = peerTicketHello[:21]
				c.peerRandom = peerTicketHello[21:]
				return c, nil
			}
		}
	}

	peerHeader := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, peerHeader); err != nil {
		return nil, err
	}
	if l, _ := decodeHeader(peerHeader); l != 0 {
		noise := make([]byte, crypto.RandBetween(100, 1000))
		rand.Read(noise)
		c.Conn.Write(noise) // make client do new handshake
		return nil, errors.New("invalid ticket")
	}

	peerClientHello := make([]byte, 1+1184+1088)
	copy(peerClientHello, peerTicketHello)
	copy(peerClientHello[53:], peerHeader)
	if _, err := io.ReadFull(c.Conn, peerClientHello[58:]); err != nil {
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

	authKey := make([]byte, 32)
	hkdf.New(sha256.New, c.baseKey, encapsulatedPfsKey, encapsulatedNfsKey).Read(authKey)
	nonce := [12]byte{c.cipher}
	c.ticket = newAead(c.cipher, authKey).Seal(nil, nonce[:], []byte("VLESS"), pfsEKeyBytes)

	paddingLen := crypto.RandBetween(100, 1000)

	serverHello := make([]byte, 1088+21+5+paddingLen)
	copy(serverHello, encapsulatedPfsKey)
	copy(serverHello[1088:], c.ticket)
	encodeHeader(serverHello[1109:], int(paddingLen))
	rand.Read(serverHello[1114:])

	if _, err := c.Conn.Write(serverHello); err != nil {
		return nil, err
	}
	// we can send more padding if needed

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
	peerHeader := make([]byte, 5)
	if c.peerAead == nil {
		if c.peerRandom == nil {
			for {
				if _, err := io.ReadFull(c.Conn, peerHeader); err != nil {
					return 0, err
				}
				peerPaddingLen, _ := decodeHeader(peerHeader)
				if peerPaddingLen == 0 {
					break
				}
				if _, err := io.ReadFull(c.Conn, make([]byte, peerPaddingLen)); err != nil {
					return 0, err
				}
			}
			peerTicket := make([]byte, 21)
			copy(peerTicket, peerHeader)
			if _, err := io.ReadFull(c.Conn, peerTicket[5:]); err != nil {
				return 0, err
			}
			if !bytes.Equal(peerTicket, c.ticket) {
				return 0, errors.New("naughty boy")
			}
			c.peerRandom = make([]byte, 32)
			if _, err := io.ReadFull(c.Conn, c.peerRandom); err != nil {
				return 0, err
			}
		}
		peerKey := make([]byte, 32)
		hkdf.New(sha256.New, c.baseKey, c.peerRandom, c.ticket).Read(peerKey)
		c.peerAead = newAead(c.cipher, peerKey)
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
		return 0, err
	}
	peerData := make([]byte, peerLength)
	if _, err := io.ReadFull(c.Conn, peerData); err != nil {
		return 0, err
	}
	dst := peerData[:peerLength-16]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	_, err = c.peerAead.Open(dst[:0], c.peerNonce, peerData, peerHeader)
	increaseNonce(c.peerNonce)
	if err != nil {
		return 0, errors.New("error")
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
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > 8192 {
			b = b[:8192] // for avoiding another copy() in client's Read()
		}
		n += len(b)
		var data []byte
		if c.aead == nil {
			if c.peerRandom == nil {
				return 0, errors.New("empty c.peerRandom")
			}
			data = make([]byte, 32+5+len(b)+16)
			rand.Read(data[:32])
			key := make([]byte, 32)
			hkdf.New(sha256.New, c.baseKey, data[:32], c.peerRandom).Read(key)
			c.aead = newAead(c.cipher, key)
			c.nonce = make([]byte, 12)
			encodeHeader(data[32:], len(b)+16)
			c.aead.Seal(data[:37], c.nonce, b, data[32:37])
		} else {
			data = make([]byte, 5+len(b)+16)
			encodeHeader(data, len(b)+16)
			c.aead.Seal(data[:5], c.nonce, b, data[:5])
		}
		increaseNonce(c.nonce)
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

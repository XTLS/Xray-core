package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"lukechampine.com/blake3"
)

type ServerSession struct {
	Expire  time.Time
	PfsKey  []byte
	NfsKeys sync.Map
}

type ServerInstance struct {
	NfsSKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	XorMode       uint32
	Seconds       uint32

	RWLock   sync.RWMutex
	Sessions map[[16]byte]*ServerSession
	Closed   bool
}

func (i *ServerInstance) Init(nfsSKeysBytes [][]byte, xorMode, seconds uint32) (err error) {
	if i.NfsSKeys != nil {
		err = errors.New("already initialized")
		return
	}
	l := len(nfsSKeysBytes)
	if l == 0 {
		err = errors.New("empty nfsSKeysBytes")
		return
	}
	i.NfsSKeys = make([]any, l)
	i.NfsPKeysBytes = make([][]byte, l)
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsSKeysBytes {
		if len(k) == 32 {
			if i.NfsSKeys[j], err = ecdh.X25519().NewPrivateKey(k); err != nil {
				return
			}
			i.NfsPKeysBytes[j] = i.NfsSKeys[j].(*ecdh.PrivateKey).PublicKey().Bytes()
			i.RelaysLength += 32 + 32
		} else {
			if i.NfsSKeys[j], err = mlkem.NewDecapsulationKey768(k); err != nil {
				return
			}
			i.NfsPKeysBytes[j] = i.NfsSKeys[j].(*mlkem.DecapsulationKey768).EncapsulationKey().Bytes()
			i.RelaysLength += 1088 + 32
		}
		i.Hash32s[j] = blake3.Sum256(i.NfsPKeysBytes[j])
	}
	i.RelaysLength -= 32
	i.XorMode = xorMode
	if seconds > 0 {
		i.Seconds = seconds
		i.Sessions = make(map[[16]byte]*ServerSession)
		go func() {
			for {
				time.Sleep(time.Minute)
				i.RWLock.Lock()
				if i.Closed {
					i.RWLock.Unlock()
					return
				}
				now := time.Now()
				for ticket, session := range i.Sessions {
					if now.After(session.Expire) {
						delete(i.Sessions, ticket)
					}
				}
				i.RWLock.Unlock()
			}
		}()
	}
	return
}

func (i *ServerInstance) Close() (err error) {
	i.RWLock.Lock()
	i.Closed = true
	i.RWLock.Unlock()
	return
}

func (i *ServerInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.NfsSKeys == nil {
		return nil, errors.New("uninitialized")
	}
	c := NewCommonConn(conn)

	ivAndRelays := make([]byte, 16+i.RelaysLength)
	if _, err := io.ReadFull(conn, ivAndRelays); err != nil {
		return nil, err
	}
	iv := ivAndRelays[:16]
	relays := ivAndRelays[16:]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // recover this relay
		}
		var index = 32
		if _, ok := k.(*mlkem.DecapsulationKey768); ok {
			index = 1088
		}
		if i.XorMode > 0 {
			NewCTR(i.NfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // we don't use buggy elligator, because we have PSK :)
		}
		if k, ok := k.(*ecdh.PrivateKey); ok {
			publicKey, err := ecdh.X25519().NewPublicKey(relays[:index])
			if err != nil {
				return nil, err
			}
			nfsKey, err = k.ECDH(publicKey)
			if err != nil {
				return nil, err
			}
		}
		if k, ok := k.(*mlkem.DecapsulationKey768); ok {
			var err error
			nfsKey, err = k.Decapsulate(relays[:index])
			if err != nil {
				return nil, err
			}
		}
		if j == len(i.NfsSKeys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:32])
		if !bytes.Equal(relays[:32], i.Hash32s[j+1][:]) {
			return nil, errors.New("unexpected hash32: ", fmt.Sprintf("%v", relays[:32]))
		}
		relays = relays[32:]
	}
	nfsGCM := NewGCM(iv, nfsKey)

	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := nfsGCM.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := DecodeLength(encryptedLength[:2])

	if length == 32 {
		if i.Seconds == 0 {
			return nil, errors.New("0-RTT is not allowed")
		}
		encryptedTicket := make([]byte, 32)
		if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
			return nil, err
		}
		ticket, err := nfsGCM.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, err
		}
		i.RWLock.RLock()
		s := i.Sessions[[16]byte(ticket)]
		i.RWLock.RUnlock()
		if s == nil {
			noises := make([]byte, crypto.RandBetween(1268, 2268)) // matches 1-RTT's server hello length for "random", though it is not important, just for example
			var err error
			for err == nil {
				rand.Read(noises)
				_, err = DecodeHeader(noises)
			}
			conn.Write(noises) // make client do new handshake
			return nil, errors.New("expired ticket")
		}
		if _, loaded := s.NfsKeys.LoadOrStore([32]byte(nfsKey), true); loaded { // prevents bad client also
			return nil, errors.New("replay detected")
		}
		c.UnitedKey = append(s.PfsKey, nfsKey...) // the same nfsKey links the upload & download (prevents server -> client's another request)
		c.PreWrite = make([]byte, 16)
		rand.Read(c.PreWrite) // always trust yourself, not the client (also prevents being parsed as TLS thus causing false interruption for "native" and "xorpub")
		c.GCM = NewGCM(c.PreWrite, c.UnitedKey)
		c.PeerGCM = NewGCM(encryptedTicket, c.UnitedKey) // unchangeable ctx (prevents server -> server), and different ctx length for upload / download (prevents client -> client)
		if i.XorMode == 2 {
			c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, c.PreWrite), NewCTR(c.UnitedKey, iv), 16, 0) // it doesn't matter if the attacker sends client's iv back to the client
		}
		return c, nil
	}

	if length < 1184+32+16 { // client may send more public keys in the future's version
		return nil, errors.New("too short length")
	}
	encryptedPfsPublicKey := make([]byte, length)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	if _, err := nfsGCM.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil); err != nil {
		return nil, err
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey[:1184])
	if err != nil {
		return nil, err
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[1184 : 1184+32])
	if err != nil {
		return nil, err
	}
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 32+32) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	pfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	c.UnitedKey = append(pfsKey, nfsKey...)
	c.GCM = NewGCM(pfsPublicKey, c.UnitedKey)
	c.PeerGCM = NewGCM(encryptedPfsPublicKey[:1184+32], c.UnitedKey)
	ticket := make([]byte, 16)
	rand.Read(ticket)
	copy(ticket, EncodeLength(int(i.Seconds*4/5)))

	pfsKeyExchangeLength := 1088 + 32 + 16
	encryptedTicketLength := 32
	paddingLength := int(crypto.RandBetween(100, 1000))
	serverHello := make([]byte, pfsKeyExchangeLength+encryptedTicketLength+paddingLength)
	nfsGCM.Seal(serverHello[:0], MaxNonce, pfsPublicKey, nil)
	c.GCM.Seal(serverHello[:pfsKeyExchangeLength], nil, ticket, nil)
	padding := serverHello[pfsKeyExchangeLength+encryptedTicketLength:]
	c.GCM.Seal(padding[:0], nil, EncodeLength(paddingLength-18), nil)
	c.GCM.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	if _, err := conn.Write(serverHello); err != nil {
		return nil, err
	}
	// padding can be sent in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control

	if i.Seconds > 0 {
		i.RWLock.Lock()
		i.Sessions[[16]byte(ticket)] = &ServerSession{
			Expire: time.Now().Add(time.Duration(i.Seconds) * time.Second),
			PfsKey: pfsKey,
		}
		i.RWLock.Unlock()
	}

	// important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := nfsGCM.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	encryptedPadding := make([]byte, DecodeLength(encryptedLength[:2]))
	if _, err := io.ReadFull(conn, encryptedPadding); err != nil {
		return nil, err
	}
	if _, err := nfsGCM.Open(encryptedPadding[:0], nil, encryptedPadding, nil); err != nil {
		return nil, err
	}

	if i.XorMode == 2 {
		c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, ticket), NewCTR(c.UnitedKey, iv), 0, 0)
	}
	return c, nil
}

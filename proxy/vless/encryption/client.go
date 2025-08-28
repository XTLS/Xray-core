package encryption

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"lukechampine.com/blake3"
)

type ClientInstance struct {
	NfsPKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	XorMode       uint32
	Seconds       uint32

	RWLock sync.RWMutex
	Expire time.Time
	PfsKey []byte
	Ticket []byte
}

func (i *ClientInstance) Init(nfsPKeysBytes [][]byte, xorMode, seconds uint32) (err error) {
	if i.NfsPKeys != nil {
		err = errors.New("already initialized")
		return
	}
	l := len(nfsPKeysBytes)
	if l == 0 {
		err = errors.New("empty nfsPKeysBytes")
		return
	}
	i.NfsPKeys = make([]any, l)
	i.NfsPKeysBytes = nfsPKeysBytes
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsPKeysBytes {
		if len(k) == 32 {
			if i.NfsPKeys[j], err = ecdh.X25519().NewPublicKey(k); err != nil {
				return
			}
			i.RelaysLength += 32 + 32
		} else {
			if i.NfsPKeys[j], err = mlkem.NewEncapsulationKey768(k); err != nil {
				return
			}
			i.RelaysLength += 1088 + 32
		}
		i.Hash32s[j] = blake3.Sum256(k)
	}
	i.RelaysLength -= 32
	i.XorMode = xorMode
	i.Seconds = seconds
	return
}

func (i *ClientInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.NfsPKeys == nil {
		return nil, errors.New("uninitialized")
	}
	c := NewCommonConn(conn)

	ivAndRealysLength := 16 + i.RelaysLength
	pfsKeyExchangeLength := 18 + 1184 + 32 + 16
	paddingLength := int(crypto.RandBetween(100, 1000))
	clientHello := make([]byte, ivAndRealysLength+pfsKeyExchangeLength+paddingLength)

	iv := clientHello[:16]
	rand.Read(iv)
	relays := clientHello[16:ivAndRealysLength]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsPKeys {
		var index = 32
		if k, ok := k.(*ecdh.PublicKey); ok {
			privateKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			copy(relays, privateKey.PublicKey().Bytes())
			var err error
			nfsKey, err = privateKey.ECDH(k)
			if err != nil {
				return nil, err
			}
		}
		if k, ok := k.(*mlkem.EncapsulationKey768); ok {
			var ciphertext []byte
			nfsKey, ciphertext = k.Encapsulate()
			copy(relays, ciphertext)
			index = 1088
		}
		if i.XorMode > 0 { // this xor can (others can't) be recovered by client's config, revealing an X25519 public key / ML-KEM-768 ciphertext, that's why "native" values
			NewCTR(i.NfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // make X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // make this relay irreplaceable
		}
		if j == len(i.NfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], i.Hash32s[j+1][:])
		relays = relays[index+32:]
	}
	nfsGCM := NewGCM(iv, nfsKey)

	if i.Seconds > 0 {
		i.RWLock.RLock()
		if time.Now().Before(i.Expire) {
			c.Client = i
			c.UnitedKey = append(i.PfsKey, nfsKey...) // different unitedKey for each connection
			nfsGCM.Seal(clientHello[:ivAndRealysLength], nil, EncodeLength(32), nil)
			nfsGCM.Seal(clientHello[:ivAndRealysLength+18], nil, i.Ticket, nil)
			i.RWLock.RUnlock()
			c.PreWrite = clientHello[:ivAndRealysLength+18+32]
			c.GCM = NewGCM(clientHello[ivAndRealysLength+18:ivAndRealysLength+18+32], c.UnitedKey)
			if i.XorMode == 2 {
				c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), nil, len(c.PreWrite), 16)
			}
			return c, nil
		}
		i.RWLock.RUnlock()
	}

	pfsKeyExchange := clientHello[ivAndRealysLength : ivAndRealysLength+pfsKeyExchangeLength]
	nfsGCM.Seal(pfsKeyExchange[:0], nil, EncodeLength(pfsKeyExchangeLength-18), nil)
	mlkem768DKey, _ := mlkem.GenerateKey768()
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsGCM.Seal(pfsKeyExchange[:18], nil, pfsPublicKey, nil)

	padding := clientHello[ivAndRealysLength+pfsKeyExchangeLength:]
	nfsGCM.Seal(padding[:0], nil, EncodeLength(paddingLength-18), nil)
	nfsGCM.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	if _, err := conn.Write(clientHello); err != nil {
		return nil, err
	}
	// padding can be sent in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control

	encryptedPfsPublicKey := make([]byte, 1088+32+16)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	nfsGCM.Open(encryptedPfsPublicKey[:0], MaxNonce, encryptedPfsPublicKey, nil)
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey[:1088])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[1088 : 1088+32])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 32+32) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	c.UnitedKey = append(pfsKey, nfsKey...)
	c.GCM = NewGCM(pfsPublicKey, c.UnitedKey)
	c.PeerGCM = NewGCM(encryptedPfsPublicKey[:1088+32], c.UnitedKey)

	encryptedTicket := make([]byte, 32)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	if _, err := c.PeerGCM.Open(encryptedTicket[:0], nil, encryptedTicket, nil); err != nil {
		return nil, err
	}
	seconds := DecodeLength(encryptedTicket)

	if i.Seconds > 0 && seconds > 0 {
		i.RWLock.Lock()
		i.Expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.PfsKey = pfsKey
		i.Ticket = encryptedTicket[:16]
		i.RWLock.Unlock()
	}

	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := c.PeerGCM.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := DecodeLength(encryptedLength[:2])
	c.PeerPadding = make([]byte, length) // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern

	if i.XorMode == 2 {
		c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), NewCTR(c.UnitedKey, encryptedTicket[:16]), 0, length)
	}
	return c, nil
}

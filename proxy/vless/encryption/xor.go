package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha3"
	"io"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

type XorConn struct {
	net.Conn
	Divide bool

	head     []byte
	key      []byte
	ctr      cipher.Stream
	peerCtr  cipher.Stream
	isHeader bool
	skipNext bool

	out_after0 bool
	out_header []byte
	out_skip   int

	in_after0 bool
	in_header []byte
	in_skip   int
}

func NewCTR(key, iv []byte, isServer bool) cipher.Stream {
	info := "CLIENT"
	if isServer {
		info = "SERVER" // avoids attackers sending traffic back to the client, though the encryption layer has its own protection
	}
	key, _ = hkdf.Key(sha3.New256, key, iv, info, 32) // avoids using pKey directly if attackers sent the basepoint, or whaterver they like
	block, _ := aes.NewCipher(key)
	return cipher.NewCTR(block, iv)
}

func NewXorConn(conn net.Conn, mode uint32, pKey *ecdh.PublicKey, sKey *ecdh.PrivateKey) (*XorConn, error) {
	if mode == 0 || (pKey == nil && sKey == nil) || (pKey != nil && sKey != nil) {
		return nil, errors.New("invalid parameters")
	}
	c := &XorConn{
		Conn:       conn,
		Divide:     mode == 1,
		isHeader:   true,
		out_header: make([]byte, 0, 5), // important
		in_header:  make([]byte, 0, 5), // important
	}
	if pKey != nil {
		c.head = make([]byte, 16+32)
		rand.Read(c.head)
		eSKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
		NewCTR(pKey.Bytes(), c.head[:16], false).XORKeyStream(c.head[16:], eSKey.PublicKey().Bytes()) // make X25519 public key distinguishable from random bytes
		c.key, _ = eSKey.ECDH(pKey)
		c.ctr = NewCTR(c.key, c.head[:16], false)
	}
	if sKey != nil {
		peerHead := make([]byte, 16+32)
		if _, err := io.ReadFull(c.Conn, peerHead); err != nil {
			return nil, err
		}
		NewCTR(sKey.PublicKey().Bytes(), peerHead[:16], false).XORKeyStream(peerHead[16:], peerHead[16:]) // we don't use buggy elligator, because we have PSK :)
		ePKey, err := ecdh.X25519().NewPublicKey(peerHead[16:])
		if err != nil {
			return nil, err
		}
		key, err := sKey.ECDH(ePKey)
		if err != nil {
			return nil, err
		}
		c.peerCtr = NewCTR(key, peerHead[:16], false)
		c.head = make([]byte, 16)
		rand.Read(c.head)                 // make sure the server always replies random bytes even when received replays, though it is not important
		c.ctr = NewCTR(key, c.head, true) // the same key links the upload & download, though the encryption layer has its own link
	}
	return c, nil
	//chacha20.NewUnauthenticatedCipher()
}

func (c *XorConn) Write(b []byte) (int, error) { // whole one/two records
	if len(b) == 0 {
		return 0, nil
	}
	if !c.out_after0 {
		t, l, _ := DecodeHeader(b)
		if t == 23 { // single 23
			l = 5
		} else { // 1/0 + 23, or noises only
			l += 10
			if t == 0 {
				c.out_after0 = true
				if c.Divide {
					l -= 5
				}
			}
		}
		c.ctr.XORKeyStream(b[:l], b[:l]) // caller MUST discard b
		l = len(b)
		if c.head != nil {
			b = append(c.head, b...)
			c.head = nil
		}
		if _, err := c.Conn.Write(b); err != nil {
			return 0, err
		}
		return l, nil
	}
	if c.Divide {
		return c.Conn.Write(b)
	}
	for p := b; ; { // for XTLS
		if len(p) <= c.out_skip {
			c.out_skip -= len(p)
			break
		}
		p = p[c.out_skip:]
		c.out_skip = 0
		need := 5 - len(c.out_header)
		if len(p) < need {
			c.out_header = append(c.out_header, p...)
			c.ctr.XORKeyStream(p, p)
			break
		}
		_, c.out_skip, _ = DecodeHeader(append(c.out_header, p[:need]...))
		c.out_header = c.out_header[:0]
		c.ctr.XORKeyStream(p[:need], p[:need])
		p = p[need:]
	}
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *XorConn) Read(b []byte) (int, error) { // 5-bytes, data, 5-bytes...
	if len(b) == 0 {
		return 0, nil
	}
	if !c.in_after0 || !c.isHeader {
		if c.peerCtr == nil { // for client
			peerIv := make([]byte, 16)
			if _, err := io.ReadFull(c.Conn, peerIv); err != nil {
				return 0, err
			}
			c.peerCtr = NewCTR(c.key, peerIv, true)
		}
		if _, err := io.ReadFull(c.Conn, b); err != nil {
			return 0, err
		}
		if c.skipNext {
			c.skipNext = false
			return len(b), nil
		}
		c.peerCtr.XORKeyStream(b, b)
		if c.isHeader { // always 5-bytes
			if t, _, _ := DecodeHeader(b); t == 23 {
				c.skipNext = true
			} else {
				c.isHeader = false
				if t == 0 {
					c.in_after0 = true
				}
			}
		} else {
			c.isHeader = true
		}
		return len(b), nil
	}
	if c.Divide {
		return c.Conn.Read(b)
	}
	n, err := c.Conn.Read(b)
	for p := b[:n]; ; { // for XTLS
		if len(p) <= c.in_skip {
			c.in_skip -= len(p)
			break
		}
		p = p[c.in_skip:]
		c.in_skip = 0
		need := 5 - len(c.in_header)
		if len(p) < need {
			c.peerCtr.XORKeyStream(p, p)
			c.in_header = append(c.in_header, p...)
			break
		}
		c.peerCtr.XORKeyStream(p[:need], p[:need])
		_, c.in_skip, _ = DecodeHeader(append(c.in_header, p[:need]...))
		c.in_header = c.in_header[:0]
		p = p[need:]
	}
	return n, err
}

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

type XorConn struct {
	net.Conn
	key      []byte
	ctr      cipher.Stream
	peerCtr  cipher.Stream
	isHeader bool
	skipNext bool
}

func NewXorConn(conn net.Conn, key []byte) *XorConn {
	return &XorConn{Conn: conn, key: key[:16]}
	//chacha20.NewUnauthenticatedCipher()
}

func (c *XorConn) Write(b []byte) (int, error) { // two records at most
	if len(b) == 0 {
		return 0, nil
	}
	var iv []byte
	if c.ctr == nil {
		block, _ := aes.NewCipher(c.key)
		iv = make([]byte, 16)
		rand.Read(iv)
		c.ctr = cipher.NewCTR(block, iv)
	}
	t, l, _ := DecodeHeader(b)
	if t != 23 {
		l += 10 // 5+l+5
	} else {
		l = 5
	}
	c.ctr.XORKeyStream(b[:l], b[:l]) // caller MUST discard b
	if iv != nil {
		b = append(iv, b...)
	}
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	if iv != nil {
		b = b[16:] // for len(b)
	}
	return len(b), nil
}

func (c *XorConn) Read(b []byte) (int, error) { // 5-bytes, data, 5-bytes...
	if len(b) == 0 {
		return 0, nil
	}
	if c.peerCtr == nil {
		peerIv := make([]byte, 16)
		if _, err := io.ReadFull(c.Conn, peerIv); err != nil {
			return 0, err
		}
		block, _ := aes.NewCipher(c.key)
		c.peerCtr = cipher.NewCTR(block, peerIv)
		c.isHeader = true
	}
	if _, err := io.ReadFull(c.Conn, b); err != nil {
		return 0, err
	}
	if c.skipNext {
		c.skipNext = false
		return len(b), nil
	}
	c.peerCtr.XORKeyStream(b, b)
	if c.isHeader {
		if t, _, _ := DecodeHeader(b); t == 23 { // always 5-bytes
			c.skipNext = true
		} else {
			c.isHeader = false
		}
	} else {
		c.isHeader = true
	}
	return len(b), nil
}

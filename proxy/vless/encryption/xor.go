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
	key     []byte
	ctr     cipher.Stream
	peerCtr cipher.Stream
}

func NewXorConn(conn net.Conn, key []byte) *XorConn {
	return &XorConn{Conn: conn, key: key[:16]}
}

func (c *XorConn) Write(b []byte) (int, error) {
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
	c.ctr.XORKeyStream(b, b) // caller MUST discard b
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

func (c *XorConn) Read(b []byte) (int, error) {
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
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.peerCtr.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

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

	out_after0 bool
	out_header []byte
	out_skip   int

	in_after0 bool
	in_header []byte
	in_skip   int
}

func NewXorConn(conn net.Conn, key []byte) *XorConn {
	return &XorConn{Conn: conn, key: key}
	//chacha20.NewUnauthenticatedCipher()
}

func (c *XorConn) Write(b []byte) (int, error) { // whole one/two records
	if len(b) == 0 {
		return 0, nil
	}
	if !c.out_after0 {
		var iv []byte
		if c.ctr == nil {
			block, _ := aes.NewCipher(c.key)
			iv = make([]byte, 16)
			rand.Read(iv)
			c.ctr = cipher.NewCTR(block, iv)
		}
		t, l, _ := DecodeHeader(b)
		if t == 23 { // single 23
			l = 5
		} else { // 1/0 + 23, or noises only
			l += 10
			if t == 0 {
				c.out_after0 = true
				c.out_header = make([]byte, 0, 5) // important
			}
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
		if c.isHeader { // always 5-bytes
			if t, _, _ := DecodeHeader(b); t == 23 {
				c.skipNext = true
			} else {
				c.isHeader = false
				if t == 0 {
					c.in_after0 = true
					c.in_header = make([]byte, 0, 5) // important
				}
			}
		} else {
			c.isHeader = true
		}
		return len(b), nil
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

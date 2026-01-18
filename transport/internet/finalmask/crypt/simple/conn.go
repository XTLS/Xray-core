package simple

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type simple struct{}

func (*simple) NonceSize() int {
	return 0
}

func (*simple) Overhead() int {
	return 6
}

func (a *simple) Seal(dst, nonce, plain, extra []byte) []byte {
	dst = append(dst, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[4:], uint16(len(plain)))
	dst = append(dst, plain...)

	fnvHash := fnv.New32a()
	common.Must2(fnvHash.Write(dst[4:]))
	fnvHash.Sum(dst[:0])

	dstLen := len(dst)
	xtra := 4 - dstLen%4
	if xtra != 4 {
		dst = append(dst, make([]byte, xtra)...)
	}
	xorfwd(dst)
	if xtra != 4 {
		dst = dst[:dstLen]
	}
	return dst
}

func (a *simple) Open(dst, nonce, cipherText, extra []byte) ([]byte, error) {
	dst = append(dst, cipherText...)
	dstLen := len(dst)
	xtra := 4 - dstLen%4
	if xtra != 4 {
		dst = append(dst, make([]byte, xtra)...)
	}
	xorbkd(dst)
	if xtra != 4 {
		dst = dst[:dstLen]
	}

	fnvHash := fnv.New32a()
	common.Must2(fnvHash.Write(dst[4:]))
	if binary.BigEndian.Uint32(dst[:4]) != fnvHash.Sum32() {
		return nil, errors.New("invalid auth")
	}

	length := binary.BigEndian.Uint16(dst[4:6])
	if len(dst)-6 != int(length) {
		return nil, errors.New("invalid auth")
	}

	return dst[6:], nil
}

type simpleConn struct {
	conn net.PacketConn
	aead cipher.AEAD
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &simpleConn{
		conn: raw,
		aead: &simple{},
	}, nil
}

func (c *simpleConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	if len(p) <= nonceSize+overhead {
		return 0, addr, errors.New("aead len(p)")
	}
	out, err := c.aead.Open(p[nonceSize:nonceSize], p[:nonceSize], p[nonceSize:n], nil)
	if err != nil {
		return 0, addr, errors.New("aead open").Base(err)
	}

	n = copy(p, out)
	if n != len(out) {
		return 0, addr, io.ErrShortBuffer
	}
	return n, addr, err
}

func (c *simpleConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	nonceSize := c.aead.NonceSize()
	common.Must2(b.ReadFullFrom(rand.Reader, int32(nonceSize)))
	nonce := b.BytesFrom(int32(-nonceSize))

	encrypted := b.Extend(int32(c.aead.Overhead() + len(p)))
	encrypted = c.aead.Seal(encrypted[:0], nonce, p, nil)

	return c.conn.WriteTo(b.Bytes(), addr)
}

func (c *simpleConn) Close() error {
	return c.conn.Close()
}

func (c *simpleConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *simpleConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *simpleConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *simpleConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

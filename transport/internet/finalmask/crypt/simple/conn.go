package simple

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
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
	first     bool
	leaveSize int32

	conn net.PacketConn
	aead cipher.AEAD
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &simpleConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		aead: &simple{},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *simpleConn) Size() int32 {
	return int32(c.aead.NonceSize()) + int32(c.aead.Overhead())
}

func (c *simpleConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) && (len(p) != 8192) {
		b := buf.StackNew()
		defer b.Release()
		bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
	}

	n, addr, err = c.conn.ReadFrom(bufp)
	if err != nil {
		return n, addr, err
	}

	nonceSize := c.aead.NonceSize()
	nonce := bufp[:c.leaveSize+int32(nonceSize)]
	ciphertext := bufp[int32(nonceSize):n]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, addr, errors.New("aead open").Base(err)
	}

	nn := copy(p, plaintext)
	if nn != len(plaintext) {
		return 0, addr, errors.New("nn != len(plaintext)")
	}

	return nn, addr, nil
}

func (c *simpleConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	data := p
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) {
		if len(p) != 8192 {
			b := buf.StackNew()
			defer b.Release()
			bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
		}
		copy(bufp[c.leaveSize+c.Size():], p)
	} else {
		data = p[c.leaveSize+c.Size():]
	}

	nonceSize := c.aead.NonceSize()
	nonce := bufp[c.leaveSize : c.leaveSize+int32(nonceSize)]
	common.Must2(rand.Read(nonce))
	plaintext := data
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	nn := copy(bufp[c.leaveSize+int32(nonceSize):], ciphertext)
	if nn != len(ciphertext) {
		return 0, errors.New("nn != len(ciphertext)")
	}
	nn += int(c.leaveSize) + nonceSize

	if _, err := c.conn.WriteTo(bufp[:nn], addr); err != nil {
		return 0, err
	}

	return len(p), nil
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

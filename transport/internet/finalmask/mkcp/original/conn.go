package original

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type simple struct{}

func NewSimple() *simple {
	return &simple{}
}

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
	net.PacketConn
	aead cipher.AEAD
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &simpleConn{
		PacketConn: raw,
		aead:       &simple{},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *simpleConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if n < c.aead.Overhead() {
		errors.LogDebug(context.Background(), addr, " mask read err aead short lenth ", n)
		return 0, addr, nil
	}

	ciphertext := buf[:n]
	opened, err := c.aead.Open(nil, nil, ciphertext, nil)
	if err != nil {
		errors.LogDebug(context.Background(), addr, " mask read err aead open ", err)
		return 0, addr, nil
	}

	if len(opened) > len(p) {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", len(opened))
		return 0, addr, nil
	}

	copy(p, opened)

	return n - c.aead.Overhead(), addr, nil
}

func (c *simpleConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.aead.Overhead()+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", c.aead.Overhead()+len(p), " ", finalmask.UDPSize)
		return 0, io.ErrShortWrite
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:c.aead.Overhead()+len(p)]
		copy(buf[c.aead.Overhead():], p)
		p = buf[c.aead.Overhead() : c.aead.Overhead()+len(p)]
	}

	_ = c.aead.Seal(buf[:0], nil, p, nil)

	_, err = c.PacketConn.WriteTo(buf[:c.aead.Overhead()+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

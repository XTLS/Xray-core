package original

import (
	"crypto/cipher"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
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
	first     bool
	leaveSize int32

	conn net.PacketConn
	aead cipher.AEAD

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &simpleConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		aead: &simple{},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *simpleConn) Size() int32 {
	return int32(c.aead.NonceSize()) + int32(c.aead.Overhead())
}

func (c *simpleConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
		}

		ciphertext := c.readBuf[:n]
		opened, err := c.aead.Open(nil, nil, ciphertext, nil)
		if err != nil {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead open").Base(err)
		}

		copy(p, opened)

		c.readMutex.Unlock()
		return n - int(c.Size()), addr, nil
	}

	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
	}

	ciphertext := p[:n]
	opened, err := c.aead.Open(nil, nil, ciphertext, nil)
	if err != nil {
		c.readMutex.Unlock()
		return 0, addr, errors.New("aead open").Base(err)
	}

	copy(p, opened)

	return n - int(c.Size()), addr, nil
}

func (c *simpleConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		plaintext := c.writeBuf[c.leaveSize+c.Size() : n]
		sealed := c.aead.Seal(nil, nil, plaintext, nil)
		copy(c.writeBuf[c.leaveSize:], sealed)

		nn, err := c.conn.WriteTo(c.writeBuf[:n], addr)

		if err != nil {
			c.writeMutex.Unlock()
			return 0, err
		}

		if nn != n {
			c.writeMutex.Unlock()
			return 0, errors.New("nn != n")
		}

		c.writeMutex.Unlock()
		return len(p), nil
	}

	plaintext := p[c.leaveSize+c.Size():]
	sealed := c.aead.Seal(nil, nil, plaintext, nil)
	copy(p[c.leaveSize:], sealed)

	return c.conn.WriteTo(p, addr)
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

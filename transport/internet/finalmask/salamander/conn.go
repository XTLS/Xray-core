package salamander

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type obfsPacketConn struct {
	first     bool
	leaveSize int32

	conn net.PacketConn
	obfs *SalamanderObfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}

	conn := &obfsPacketConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		obfs: ob,
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

func (c *obfsPacketConn) Size() int32 {
	return smSaltLen
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("salamander").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("salamander").Base(io.ErrShortBuffer)
		}

		c.obfs.Deobfuscate(c.readBuf[:n], p)

		c.readMutex.Unlock()
		return n - int(c.Size()), addr, err
	}

	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("salamander").Base(io.ErrShortBuffer)
	}

	c.obfs.Deobfuscate(p[:n], p)

	return n - int(c.Size()), addr, err
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.obfs.Obfuscate(c.writeBuf[c.leaveSize+c.Size():n], c.writeBuf[c.leaveSize:n])

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

	c.obfs.Obfuscate(p[c.leaveSize+c.Size():], p[c.leaveSize:])

	return c.conn.WriteTo(p, addr)
}

func (c *obfsPacketConn) Close() error {
	return c.conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

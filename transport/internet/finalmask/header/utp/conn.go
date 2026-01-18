package utp

import (
	"encoding/binary"
	"io"
	"net"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

type utp struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*utp) Size() int32 {
	return 4
}

func (h *utp) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, h.connectionID)
	b[2] = h.header
	b[3] = h.extension
}

type utpConn struct {
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *utp

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &utpConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &utp{
			header:       1,
			extension:    0,
			connectionID: dice.RollUint16(),
		},
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

func (c *utpConn) Size() int32 {
	return c.header.Size()
}

func (c *utpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		copy(p, c.readBuf[c.Size():n])

		c.readMutex.Unlock()
		return n - int(c.Size()), addr, err
	}

	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
	}

	copy(p, p[c.Size():n])

	return n - int(c.Size()), addr, err
}

func (c *utpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.header.Serialize(c.writeBuf[c.leaveSize : c.leaveSize+c.Size()])

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

	c.header.Serialize(p[c.leaveSize : c.leaveSize+c.Size()])

	return c.conn.WriteTo(p, addr)
}

func (c *utpConn) Close() error {
	return c.conn.Close()
}

func (c *utpConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *utpConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *utpConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *utpConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

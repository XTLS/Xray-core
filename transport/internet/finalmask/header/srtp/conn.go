package srtp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

const header = 0xB5E8

type srtp struct {
	header uint16
	number uint16

	mutex sync.Mutex
}

func (*srtp) Size() int32 {
	return 4
}

func (h *srtp) Serialize(b []byte) {
	h.mutex.Lock()
	number := h.number
	h.number++
	h.mutex.Unlock()
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], number)
}

type srtpConn struct {
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *srtp
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &srtpConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &srtp{
			header: header,
			number: dice.RollUint16(),
		},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *srtpConn) Size() int32 {
	return c.header.Size()
}

func (c *srtpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

	if n < int(c.Size()) {
		return 0, addr, errors.New("header size error")
	}

	nn := copy(p, bufp[c.Size():n])
	if nn == 0 {
		return 0, addr, errors.New("nn == 0")
	}

	return nn, addr, nil
}

func (c *srtpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) {
		if len(p) != 8192 {
			b := buf.StackNew()
			defer b.Release()
			bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
		}
		copy(bufp[c.leaveSize+c.Size():], p)
	}

	c.header.Serialize(bufp[c.leaveSize : c.leaveSize+c.Size()])

	if _, err := c.conn.WriteTo(bufp, addr); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *srtpConn) Close() error {
	return c.conn.Close()
}

func (c *srtpConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *srtpConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *srtpConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *srtpConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

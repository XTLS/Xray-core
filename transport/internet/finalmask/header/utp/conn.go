package utp

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

const header = 1
const extension = 0

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
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &utpConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &utp{
			header:       header,
			extension:    extension,
			connectionID: dice.RollUint16(),
		},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *utpConn) Size() int32 {
	return c.header.Size()
}

func (c *utpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *utpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

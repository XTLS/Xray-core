package wireguard

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type wireguare struct{}

func (*wireguare) Size() int32 {
	return 4
}

func (h *wireguare) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

type wireguareConn struct {
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *wireguare
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &wireguareConn{
		first:     first,
		leaveSize: leaveSize,

		conn:   raw,
		header: &wireguare{},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *wireguareConn) Size() int32 {
	return c.header.Size()
}

func (c *wireguareConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *wireguareConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

func (c *wireguareConn) Close() error {
	return c.conn.Close()
}

func (c *wireguareConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wireguareConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *wireguareConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wireguareConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

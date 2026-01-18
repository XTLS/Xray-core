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
	conn   net.PacketConn
	header *wireguare
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &wireguareConn{
		conn:   raw,
		header: &wireguare{},
	}, nil
}

func (c *wireguareConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if len(p) <= int(c.header.Size()) {
		return 0, addr, errors.New("wireguare len(p)")
	}

	n = copy(p, p[c.header.Size():n])
	return n, addr, err
}

func (c *wireguareConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	c.header.Serialize(b.Extend(c.header.Size()))
	b.Write(p)

	return c.conn.WriteTo(b.Bytes(), addr)
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

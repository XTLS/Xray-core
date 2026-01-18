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
	conn   net.PacketConn
	header *utp
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &utpConn{
		conn: raw,
		header: &utp{
			header:       header,
			extension:    extension,
			connectionID: dice.RollUint16(),
		},
	}, nil
}

func (c *utpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if len(p) <= int(c.header.Size()) {
		return 0, addr, errors.New("utp len(p)")
	}

	n = copy(p, p[c.header.Size():n])
	return n, addr, err
}

func (c *utpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	c.header.Serialize(b.Extend(c.header.Size()))
	b.Write(p)

	return c.conn.WriteTo(b.Bytes(), addr)
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

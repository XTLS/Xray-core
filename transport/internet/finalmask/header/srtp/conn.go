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
	conn   net.PacketConn
	header *srtp
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &srtpConn{
		conn: raw,
		header: &srtp{
			header: header,
			number: dice.RollUint16(),
		},
	}, nil
}

func (c *srtpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if len(p) <= int(c.header.Size()) {
		return 0, addr, errors.New("srtp len(p)")
	}

	n = copy(p, p[c.header.Size():n])
	return n, addr, err
}

func (c *srtpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	c.header.Serialize(b.Extend(c.header.Size()))
	b.Write(p)

	return c.conn.WriteTo(b.Bytes(), addr)
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

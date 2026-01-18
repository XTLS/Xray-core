package wechat

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

type wechat struct {
	sn uint32

	mutex sync.Mutex
}

func (*wechat) Size() int32 {
	return 13
}

func (h *wechat) Serialize(b []byte) {
	h.mutex.Lock()
	sn := h.sn
	h.sn++
	h.mutex.Unlock()

	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], sn)
	b[6] = 0x00
	b[7] = 0x10
	b[8] = 0x11
	b[9] = 0x18
	b[10] = 0x30
	b[11] = 0x22
	b[12] = 0x30
}

type wechatConn struct {
	conn   net.PacketConn
	header *wechat
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &wechatConn{
		conn: raw,
		header: &wechat{
			sn: uint32(dice.RollUint16()),
		},
	}, nil
}

func (c *wechatConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if len(p) <= int(c.header.Size()) {
		return 0, addr, errors.New("wechat len(p)")
	}

	n = copy(p, p[c.header.Size():n])
	return n, addr, err
}

func (c *wechatConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	c.header.Serialize(b.Extend(c.header.Size()))
	b.Write(p)

	return c.conn.WriteTo(b.Bytes(), addr)
}

func (c *wechatConn) Close() error {
	return c.conn.Close()
}

func (c *wechatConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wechatConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *wechatConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wechatConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

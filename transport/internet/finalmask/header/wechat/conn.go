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
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *wechat
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &wechatConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &wechat{
			sn: uint32(dice.RollUint16()),
		},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *wechatConn) Size() int32 {
	return c.header.Size()
}

func (c *wechatConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *wechatConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

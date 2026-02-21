package wechat

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type wechat struct {
	sn uint32
}

func (*wechat) Size() int {
	return 13
}

func (h *wechat) Serialize(b []byte) {
	h.sn++
	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], h.sn)
	b[6] = 0x00
	b[7] = 0x10
	b[8] = 0x11
	b[9] = 0x18
	b[10] = 0x30
	b[11] = 0x22
	b[12] = 0x30
}

type wechatConn struct {
	net.PacketConn
	header *wechat
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &wechatConn{
		PacketConn: raw,
		header: &wechat{
			sn: uint32(dice.RollUint16()),
		},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *wechatConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if n < c.header.Size() {
		errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
		return 0, addr, nil
	}

	if len(p) < n-c.header.Size() {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-c.header.Size())
		return 0, addr, io.ErrShortBuffer
	}

	copy(p, buf[c.header.Size():n])

	return n - c.header.Size(), addr, nil
}

func (c *wechatConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.header.Size()+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", c.header.Size()+len(p), " ", finalmask.UDPSize)
		return 0, io.ErrShortWrite
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:c.header.Size()+len(p)]
	}

	copy(buf[c.header.Size():], p)
	c.header.Serialize(buf)

	_, err = c.PacketConn.WriteTo(buf[:c.header.Size()+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

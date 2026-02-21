package wireguard

import (
	"context"
	"io"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type wireguare struct{}

func (*wireguare) Size() int {
	return 4
}

func (h *wireguare) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

type wireguareConn struct {
	net.PacketConn
	header *wireguare
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &wireguareConn{
		PacketConn: raw,
		header:     &wireguare{},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *wireguareConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *wireguareConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

package srtp

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type srtp struct {
	header uint16
	number uint16
}

func (*srtp) Size() int {
	return 4
}

func (h *srtp) Serialize(b []byte) {
	h.number++
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], h.number)
}

type srtpConn struct {
	net.PacketConn
	header *srtp
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &srtpConn{
		PacketConn: raw,
		header: &srtp{
			header: 0xB5E8,
			number: dice.RollUint16(),
		},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *srtpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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
		return 0, addr, nil
	}

	copy(p, buf[c.header.Size():n])

	return n - c.header.Size(), addr, nil
}

func (c *srtpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

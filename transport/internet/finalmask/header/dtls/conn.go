package dtls

import (
	"context"
	"io"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type dtls struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func (*dtls) Size() int {
	return 1 + 2 + 2 + 6 + 2
}

func (h *dtls) Serialize(b []byte) {
	b[0] = 23
	b[1] = 254
	b[2] = 253
	b[3] = byte(h.epoch >> 8)
	b[4] = byte(h.epoch)
	b[5] = 0
	b[6] = 0
	b[7] = byte(h.sequence >> 24)
	b[8] = byte(h.sequence >> 16)
	b[9] = byte(h.sequence >> 8)
	b[10] = byte(h.sequence)
	h.sequence++
	b[11] = byte(h.length >> 8)
	b[12] = byte(h.length)
	h.length += 17
	if h.length > 100 {
		h.length -= 50
	}
}

type dtlsConn struct {
	net.PacketConn
	header *dtls
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &dtlsConn{
		PacketConn: raw,
		header: &dtls{
			epoch:    dice.RollUint16(),
			sequence: 0,
			length:   17,
		},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *dtlsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *dtlsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

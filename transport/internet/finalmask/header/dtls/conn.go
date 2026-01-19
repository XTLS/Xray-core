package dtls

import (
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

type dtls struct {
	epoch    uint16
	length   uint16
	sequence uint32

	mutex sync.Mutex
}

func (*dtls) Size() int32 {
	return 1 + 2 + 2 + 6 + 2
}

func (h *dtls) Serialize(b []byte) {
	h.mutex.Lock()
	sequence := h.sequence
	h.sequence++

	length := h.length
	h.length += 17
	if h.length > 100 {
		h.length -= 50
	}
	h.mutex.Unlock()

	b[0] = 23
	b[1] = 254
	b[2] = 253
	b[3] = byte(h.epoch >> 8)
	b[4] = byte(h.epoch)
	b[5] = 0
	b[6] = 0
	b[7] = byte(sequence >> 24)
	b[8] = byte(sequence >> 16)
	b[9] = byte(sequence >> 8)
	b[10] = byte(sequence)
	b[11] = byte(length >> 8)
	b[12] = byte(length)
}

type dtlsConn struct {
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *dtls
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return &dtlsConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &dtls{
			epoch:    dice.RollUint16(),
			sequence: 0,
			length:   17,
		},
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *dtlsConn) Size() int32 {
	return c.header.Size()
}

func (c *dtlsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *dtlsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

func (c *dtlsConn) Close() error {
	return c.conn.Close()
}

func (c *dtlsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *dtlsConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *dtlsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *dtlsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

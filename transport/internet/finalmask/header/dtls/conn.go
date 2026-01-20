package dtls

import (
	"io"
	"net"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

type dtls struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func (*dtls) Size() int32 {
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
	first     bool
	leaveSize int32

	conn   net.PacketConn
	header *dtls

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &dtlsConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		header: &dtls{
			epoch:    dice.RollUint16(),
			sequence: 0,
			length:   17,
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *dtlsConn) Size() int32 {
	return c.header.Size()
}

func (c *dtlsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		copy(p, c.readBuf[c.Size():n])

		c.readMutex.Unlock()
		return n - int(c.Size()), addr, err
	}

	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
	}

	copy(p, p[c.Size():n])

	return n - int(c.Size()), addr, err
}

func (c *dtlsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.header.Serialize(c.writeBuf[c.leaveSize : c.leaveSize+c.Size()])

		nn, err := c.conn.WriteTo(c.writeBuf[:n], addr)

		if err != nil {
			c.writeMutex.Unlock()
			return 0, err
		}

		if nn != n {
			c.writeMutex.Unlock()
			return 0, errors.New("nn != n")
		}

		c.writeMutex.Unlock()
		return len(p), nil
	}

	c.header.Serialize(p[c.leaveSize : c.leaveSize+c.Size()])

	return c.conn.WriteTo(p, addr)
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

package srtp

import (
	"context"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	sync "sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

type srtp struct {
	header uint16
	number uint16
}

func (*srtp) Size() int32 {
	return 4
}

func (h *srtp) Serialize(b []byte) {
	h.number++
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], h.number)
}

type srtpConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	header *srtp

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &srtpConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		header: &srtp{
			header: 0xB5E8,
			number: dice.RollUint16(),
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

func (c *srtpConn) Size() int32 {
	return c.header.Size()
}

func (c *srtpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		for {
			n, addr, err = c.PacketConn.ReadFrom(c.readBuf)
			if err != nil {
				var ne net.Error
				if go_errors.As(err, &ne) {
					c.readMutex.Unlock()
					return n, addr, err
				}
				errors.LogDebug(context.Background(), addr, " mask read err ", err)
				continue
			}

			if n < int(c.Size()) {
				errors.LogDebug(context.Background(), addr, " mask read err short lenth")
				continue
			}

			copy(p, c.readBuf[c.Size():n])

			if len(p) < n-int(c.Size()) {
				c.readMutex.Unlock()
				return len(p), addr, io.ErrShortBuffer
			}

			c.readMutex.Unlock()
			return n - int(c.Size()), addr, nil
		}
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("short lenth")
	}

	copy(p, p[c.Size():n])

	return n - int(c.Size()), addr, nil
}

func (c *srtpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.header.Serialize(c.writeBuf[c.leaveSize : c.leaveSize+c.Size()])

		nn, err := c.PacketConn.WriteTo(c.writeBuf[:n], addr)

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

	return c.PacketConn.WriteTo(p, addr)
}

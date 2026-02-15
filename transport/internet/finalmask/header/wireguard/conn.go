package wireguard

import (
	"context"
	go_errors "errors"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type wireguare struct{}

func (*wireguare) Size() int32 {
	return 4
}

func (h *wireguare) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

type wireguareConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	header *wireguare

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &wireguareConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		header:     &wireguare{},
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

func (c *wireguareConn) Size() int32 {
	return c.header.Size()
}

func (c *wireguareConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

			if len(p) < n-int(c.Size()) {
				c.readMutex.Unlock()
				return 0, nil, io.ErrShortBuffer
			}

			copy(p, c.readBuf[c.Size():n])

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

func (c *wireguareConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

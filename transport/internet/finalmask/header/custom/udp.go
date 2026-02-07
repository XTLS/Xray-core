package custom

import (
	"hash/crc32"
	"io"
	"net"
	sync "sync"

	"github.com/xtls/xray-core/common/errors"
)

type udpCustomClient struct {
	client   []byte
	server   []byte
	checksum uint32

	clientSize int32
	serverSize int32
}

func (h *udpCustomClient) Serialize(b []byte) {
	copy(b, h.client)
}

type udpCustomClientConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	header *udpCustomClient

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClientUDP(c *UDPConfig, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &udpCustomClientConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		header: &udpCustomClient{
			client:   c.Client,
			server:   c.Server,
			checksum: crc32.ChecksumIEEE(c.Server),

			clientSize: int32(len(c.Client)),
			serverSize: int32(len(c.Server)),
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func (c *udpCustomClientConn) Size() int32 {
	return c.header.clientSize
}

func (c *udpCustomClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.PacketConn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.header.serverSize) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.header.serverSize) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if c.header.checksum != crc32.ChecksumIEEE(c.readBuf[:c.header.serverSize]) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("checksum mismatch")
		}

		copy(p, c.readBuf[c.header.serverSize:n])

		c.readMutex.Unlock()
		return n - int(c.header.serverSize), addr, err
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.header.serverSize) {
		return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
	}

	if c.header.checksum != crc32.ChecksumIEEE(p[:c.header.serverSize]) {
		return 0, addr, errors.New("checksum mismatch")
	}

	copy(p, p[c.header.serverSize:n])

	return n - int(c.header.serverSize), addr, err
}

func (c *udpCustomClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

type udpCustomServer struct {
	client   []byte
	server   []byte
	checksum uint32

	clientSize int32
	serverSize int32
}

func (h *udpCustomServer) Serialize(b []byte) {
	copy(b, h.server)
}

type udpCustomServerConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	header *udpCustomServer

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnServerUDP(c *UDPConfig, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	conn := &udpCustomServerConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		header: &udpCustomServer{
			client:   c.Client,
			server:   c.Server,
			checksum: crc32.ChecksumIEEE(c.Client),

			clientSize: int32(len(c.Client)),
			serverSize: int32(len(c.Server)),
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func (c *udpCustomServerConn) Size() int32 {
	return c.header.serverSize
}

func (c *udpCustomServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.PacketConn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.header.clientSize) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.header.clientSize) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
		}

		if c.header.checksum != crc32.ChecksumIEEE(c.readBuf[:c.header.clientSize]) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("checksum mismatch")
		}

		copy(p, c.readBuf[c.header.clientSize:n])

		c.readMutex.Unlock()
		return n - int(c.header.clientSize), addr, err
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.header.clientSize) {
		return 0, addr, errors.New("header").Base(io.ErrShortBuffer)
	}

	if c.header.checksum != crc32.ChecksumIEEE(p[:c.header.clientSize]) {
		return 0, addr, errors.New("checksum mismatch")
	}

	copy(p, p[c.header.clientSize:n])

	return n - int(c.header.clientSize), addr, err
}

func (c *udpCustomServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

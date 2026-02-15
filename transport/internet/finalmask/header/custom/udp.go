package custom

import (
	"bytes"
	"context"
	"crypto/rand"
	go_errors "errors"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type udpCustomClient struct {
	client []*UDPItem
	server []*UDPItem
	merged []byte
}

func (h *udpCustomClient) Serialize(b []byte) {
	index := 0
	for _, item := range h.client {
		if item.Rand > 0 {
			common.Must2(rand.Read(h.merged[index : index+int(item.Rand)]))
			index += int(item.Rand)
		} else {
			index += len(item.Packet)
		}
	}
	copy(b, h.merged)
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
			client: c.Client,
			server: c.Server,
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	index := 0
	for _, item := range conn.header.client {
		if item.Rand > 0 {
			conn.header.merged = append(conn.header.merged, make([]byte, item.Rand)...)
			index += int(item.Rand)
		} else {
			conn.header.merged = append(conn.header.merged, item.Packet...)
			index += len(item.Packet)
		}
	}

	return conn, nil
}

func (c *udpCustomClientConn) Size() int32 {
	return int32(len(c.header.merged))
}

func (c *udpCustomClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

			index := 0
			mismatch := false
			for _, item := range c.header.server {
				length := max(int(item.Rand), len(item.Packet))
				if index+length > n {
					mismatch = true
					break
				}
				if len(item.Packet) > 0 && !bytes.Equal(item.Packet, c.readBuf[index:index+length]) {
					mismatch = true
					break
				}
				index += length
			}

			if mismatch {
				errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
				continue
			}

			if len(p) < n-index {
				c.readMutex.Unlock()
				return 0, nil, io.ErrShortBuffer
			}

			copy(p, c.readBuf[index:n])

			c.readMutex.Unlock()
			return n - index, addr, nil
		}
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	index := 0
	for _, item := range c.header.server {
		length := max(int(item.Rand), len(item.Packet))
		if index+length > n {
			return 0, addr, errors.New("header mismatch")
		}
		if len(item.Packet) > 0 && !bytes.Equal(item.Packet, p[index:index+length]) {
			return 0, addr, errors.New("header mismatch")
		}
		index += length
	}

	copy(p, p[index:n])

	return n - index, addr, nil
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
	client []*UDPItem
	server []*UDPItem
	merged []byte
}

func (h *udpCustomServer) Serialize(b []byte) {
	index := 0
	for _, item := range h.server {
		if item.Rand > 0 {
			common.Must2(rand.Read(h.merged[index : index+int(item.Rand)]))
			index += int(item.Rand)
		} else {
			index += len(item.Packet)
		}
	}
	copy(b, h.merged)
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
			client: c.Client,
			server: c.Server,
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	index := 0
	for _, item := range conn.header.server {
		if item.Rand > 0 {
			conn.header.merged = append(conn.header.merged, make([]byte, item.Rand)...)
			index += int(item.Rand)
		} else {
			conn.header.merged = append(conn.header.merged, item.Packet...)
			index += len(item.Packet)
		}
	}

	return conn, nil
}

func (c *udpCustomServerConn) Size() int32 {
	return int32(len(c.header.merged))
}

func (c *udpCustomServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

			index := 0
			mismatch := false
			for _, item := range c.header.client {
				length := max(int(item.Rand), len(item.Packet))
				if index+length > n {
					mismatch = true
					break
				}
				if len(item.Packet) > 0 && !bytes.Equal(item.Packet, c.readBuf[index:index+length]) {
					mismatch = true
					break
				}
				index += length
			}

			if mismatch {
				errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
				continue
			}

			if len(p) < n-index {
				c.readMutex.Unlock()
				return 0, nil, io.ErrShortBuffer
			}

			copy(p, c.readBuf[index:n])

			c.readMutex.Unlock()
			return n - index, addr, nil
		}
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	index := 0
	for _, item := range c.header.client {
		length := max(int(item.Rand), len(item.Packet))
		if index+length > n {
			return 0, addr, errors.New("header mismatch")
		}
		if len(item.Packet) > 0 && !bytes.Equal(item.Packet, p[index:index+length]) {
			return 0, addr, errors.New("header mismatch")
		}
		index += length
	}

	copy(p, p[index:n])

	return n - index, addr, nil
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

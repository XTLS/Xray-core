package custom

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
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

func (h *udpCustomClient) Match(b []byte) bool {
	if len(b) < len(h.merged) {
		return false
	}

	data := b
	match := true

	for _, item := range h.server {
		length := max(int(item.Rand), len(item.Packet))

		if len(item.Packet) > 0 && !bytes.Equal(item.Packet, data[:length]) {
			match = false
			break
		}

		data = data[length:]
	}

	return match
}

type udpCustomClientConn struct {
	net.PacketConn
	header *udpCustomClient
}

func NewConnClientUDP(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
	conn := &udpCustomClientConn{
		PacketConn: raw,
		header: &udpCustomClient{
			client: c.Client,
			server: c.Server,
		},
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

func (c *udpCustomClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if !c.header.Match(buf[:n]) {
		errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
		return 0, addr, nil
	}

	if len(p) < n-len(c.header.merged) {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-len(c.header.merged))
		return 0, addr, nil
	}

	copy(p, buf[len(c.header.merged):n])

	return n - len(c.header.merged), addr, nil
}

func (c *udpCustomClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(c.header.merged)+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", len(c.header.merged)+len(p), " ", finalmask.UDPSize)
		return 0, nil
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:len(c.header.merged)+len(p)]
	}

	copy(buf[len(c.header.merged):], p)
	c.header.Serialize(buf)

	_, err = c.PacketConn.WriteTo(buf[:len(c.header.merged)+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
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

func (h *udpCustomServer) Match(b []byte) bool {
	if len(b) < len(h.merged) {
		return false
	}

	data := b
	match := true

	for _, item := range h.client {
		length := max(int(item.Rand), len(item.Packet))

		if len(item.Packet) > 0 && !bytes.Equal(item.Packet, data[:length]) {
			match = false
			break
		}

		data = data[length:]
	}

	return match
}

type udpCustomServerConn struct {
	net.PacketConn
	header *udpCustomServer
}

func NewConnServerUDP(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
	conn := &udpCustomServerConn{
		PacketConn: raw,
		header: &udpCustomServer{
			client: c.Client,
			server: c.Server,
		},
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

func (c *udpCustomServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if !c.header.Match(buf[:n]) {
		errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
		return 0, addr, nil
	}

	if len(p) < n-len(c.header.merged) {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-len(c.header.merged))
		return 0, addr, nil
	}

	copy(p, buf[len(c.header.merged):n])

	return n - len(c.header.merged), addr, nil
}

func (c *udpCustomServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(c.header.merged)+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", len(c.header.merged)+len(p), " ", finalmask.UDPSize)
		return 0, nil
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:len(c.header.merged)+len(p)]
	}

	copy(buf[len(c.header.merged):], p)
	c.header.Serialize(buf)

	_, err = c.PacketConn.WriteTo(buf[:len(c.header.merged)+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

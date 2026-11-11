package lua

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type maskPacketConn struct {
	net.PacketConn
	engine *engine
	role   string

	noise []scriptPacket
	sent  map[string]bool
	mu    sync.Mutex
}

func newPacketConn(c *Config, raw net.PacketConn, role string) (net.PacketConn, error) {
	engine, err := c.engine()
	if err != nil {
		return nil, errors.New("failed to initialize the script ", c.Script).Base(err)
	}
	if !engine.hasAny(packetHooks) {
		return raw, nil
	}

	return &maskPacketConn{
		PacketConn: raw,
		engine:     engine,
		role:       role,
		sent:       make(map[string]bool),
	}, nil
}

func (c *maskPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !c.engine.has(readHook) {
		return c.PacketConn.ReadFrom(p)
	}

	b := p
	if len(b) < finalmask.UDPSize {
		buffer := buf.New()
		buffer.Resize(0, finalmask.UDPSize)
		b = buffer.Bytes()
		defer buffer.Release()
	}

	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}

		strip, err := c.engine.strip(c.role, address(addr), b[:n])
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "[mask] drop packet from ", addr, " with size ", n)
			continue
		}

		copy(p, b[strip:n])
		return n - strip, addr, nil
	}
}

func (c *maskPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.engine.has(noiseHook) {
		c.sendNoise(addr)
	}

	if !c.engine.has(writeHook) {
		return c.PacketConn.WriteTo(p, addr)
	}

	buffer := buf.New()
	buffer.Resize(0, finalmask.UDPSize)
	b := buffer.Bytes()
	defer buffer.Release()

	header, err := c.engine.header(c.role, address(addr), nil)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}
	if len(header)+len(p) > len(b) {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p), " > the header does not fit")
		return 0, nil
	}
	copy(b, header)
	copy(b[len(header):], p)
	if _, err := c.PacketConn.WriteTo(b[:len(header)+len(p)], addr); err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, err
	}

	return len(p), nil
}

func (c *maskPacketConn) sendNoise(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := address(addr)
	if c.sent[key] {
		return
	}
	c.sent[key] = true

	packets, err := c.engine.packets(c.role, key, c.noise[:0])
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "the script produced no noise")
		return
	}
	c.noise = packets
	for _, packet := range packets {
		c.PacketConn.WriteTo(packet.packet, addr)
		time.Sleep(packet.delay)
	}
}

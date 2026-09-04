package noise

import (
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type noiseConn struct {
	net.PacketConn
	config *Config
	m      map[string]time.Time
	mu     sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &noiseConn{
		PacketConn: raw,
		config:     c,
		m:          make(map[string]time.Time),
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.m[addr.String()]

	if t.IsZero() || (c.config.ResetMax > 0 && time.Now().After(t)) {
		for _, item := range c.config.Items {
			if item.RandMax > 0 {
				buf := make([]byte, crypto.RandBetween(item.RandMin, item.RandMax))
				crypto.RandBytesBetween(buf, byte(item.RandRangeMin), byte(item.RandRangeMax))
				c.PacketConn.WriteTo(buf, addr)
			} else {
				c.PacketConn.WriteTo(item.Packet, addr)
			}
			time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
		}
	}

	c.m[addr.String()] = time.Now().Add(time.Duration(crypto.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)

	return c.PacketConn.WriteTo(p, addr)
}

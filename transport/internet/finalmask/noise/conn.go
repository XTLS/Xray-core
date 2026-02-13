package noise

import (
	"crypto/rand"
	"net"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type noiseConn struct {
	net.PacketConn
	config *Config
	m      map[string]struct{}
	stop   chan struct{}
	once   sync.Once
	mutex  sync.RWMutex
}

func NewConnClient(c *Config, raw net.PacketConn, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("noise requires being at the outermost level")
	}

	conn := &noiseConn{
		PacketConn: raw,
		config:     c,
		m:          make(map[string]struct{}),
		stop:       make(chan struct{}),
	}

	if conn.config.ResetMax > 0 {
		go conn.reset()
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, end bool) (net.PacketConn, error) {
	return NewConnClient(c, raw, end)
}

func (c *noiseConn) reset() {
	ticker := time.NewTicker(time.Duration(crypto.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			c.m = make(map[string]struct{})
			c.mutex.Unlock()
			ticker.Reset(time.Duration(crypto.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)
		case <-c.stop:
			return
		}
	}
}

func (c *noiseConn) Size() int32 {
	return 0
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.RLock()
	_, ready := c.m[addr.String()]
	c.mutex.RUnlock()

	switch c.config.ApplyTo {
	case "ipv4":
		if v6udp(addr) {
			ready = true
		}
	case "ipv6":
		if v4udp(addr) {
			ready = true
		}
	}

	if !ready {
		c.mutex.Lock()
		_, ready = c.m[addr.String()]
		if !ready {
			for _, item := range c.config.Items {
				if item.RandMax > 0 {
					item.Packet = make([]byte, crypto.RandBetween(item.RandMin, item.RandMax))
					common.Must2(rand.Read(item.Packet))
				}
				c.PacketConn.WriteTo(item.Packet, addr)
				time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
			}
			c.m[addr.String()] = struct{}{}
		}
		c.mutex.Unlock()
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *noiseConn) Close() error {
	c.once.Do(func() {
		close(c.stop)
	})
	return c.PacketConn.Close()
}

func v4udp(addr net.Addr) bool {
	if v, ok := addr.(*net.UDPAddr); ok {
		return v.IP.To4() != nil
	}
	return false
}

func v6udp(addr net.Addr) bool {
	if v, ok := addr.(*net.UDPAddr); ok {
		return v.IP.To16() != nil && v.IP.To4() == nil
	}
	return false
}

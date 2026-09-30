package noise

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
)

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type noiseConn struct {
	net.PacketConn
	config  *Config
	m       map[string]time.Time
	mu      sync.Mutex
	counter atomic.Uint32
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

func (c *noiseConn) buildPacket(item *Item) []byte {
	if len(item.Segments) == 0 {
		if item.RandMax > 0 {
			buf := make([]byte, crypto.RandBetween(item.RandMin, item.RandMax))
			crypto.RandBytesBetween(buf, byte(item.RandRangeMin), byte(item.RandRangeMax))
			return buf
		}
		return item.Packet
	}
	var out []byte
	for _, seg := range item.Segments {
		out = append(out, c.buildSegment(seg)...)
	}
	return out
}

func (c *noiseConn) buildSegment(seg *Segment) []byte {
	switch seg.Kind {
	case Segment_BYTES:
		return seg.Bytes
	case Segment_TIMESTAMP:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
		return b
	case Segment_COUNTER:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, c.counter.Add(1))
		return b
	case Segment_NONCE:
		b := make([]byte, 8)
		common.Must2(rand.Read(b))
		return b
	default:
		size := crypto.RandBetween(seg.MinSize, seg.MaxSize+1)
		if size <= 0 {
			return nil
		}
		buf := make([]byte, size)
		switch seg.Kind {
		case Segment_RANDOM_ASCII:
			common.Must2(rand.Read(buf))
			for i := range buf {
				buf[i] = asciiLetters[int(buf[i])%len(asciiLetters)]
			}
		case Segment_RANDOM_DIGIT:
			common.Must2(rand.Read(buf))
			for i := range buf {
				buf[i] = '0' + buf[i]%10
			}
		default:
			common.Must2(rand.Read(buf))
		}
		return buf
	}
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.m[addr.String()]

	if t.IsZero() || (c.config.ResetMax > 0 && time.Now().After(t)) {
		for _, item := range c.config.Items {
			c.PacketConn.WriteTo(c.buildPacket(item), addr)
			time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
		}
	}

	c.m[addr.String()] = time.Now().Add(time.Duration(crypto.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)

	return c.PacketConn.WriteTo(p, addr)
}

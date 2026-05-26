package salamander

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type salamanderConn struct {
	net.PacketConn
	obfs *SalamanderObfuscator
}

func NewSalamanderConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, err
	}
	return &salamanderConn{
		PacketConn: raw,
		obfs:       ob,
	}, nil
}

func NewSalamanderConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewSalamanderConnClient(c, raw)
}

func (c *salamanderConn) Size() int {
	return smSaltLen
}

func (c *salamanderConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.obfs.Deobfuscate(p, p[smSaltLen:])
	return len(p) - smSaltLen, nil, nil
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.obfs.Obfuscate(p[smSaltLen:], p)
	return len(p), nil
}

const (
	geckoReassemblyTTL = 8 * time.Second
	geckoMaxReassembly = 4096
	geckoMaxPerSource  = 8

	geckoBufferSize = 2048

	geckoDefaultMinPacket = 512
	geckoDefaultMaxPacket = 1200
)

type reassemblyKey struct {
	addr  string
	msgID uint8
}

type reassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

type geckoConn struct {
	net.PacketConn
	obfs           *SalamanderObfuscator
	minPkt, maxPkt int

	msgID atomic.Uint32

	mu         sync.Mutex
	reassembly map[reassemblyKey]*reassemblyEntry
	perSource  map[string]int

	closeCh   chan struct{}
	closeOnce sync.Once
}

func NewGeckoConnClient(c *GeckoConfig, raw net.PacketConn) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, err
	}
	minPkt, maxPkt := c.MinPacketSize, c.MaxPacketSize
	if minPkt == 0 {
		minPkt = geckoDefaultMinPacket
	}
	if maxPkt == 0 {
		maxPkt = geckoDefaultMaxPacket
	}
	if minPkt <= 0 || minPkt > maxPkt || maxPkt > geckoBufferSize {
		return nil, errors.New("gecko: invalid min/max packet size")
	}
	g := &geckoConn{
		PacketConn: raw,
		obfs:       ob,
		minPkt:     int(minPkt),
		maxPkt:     int(maxPkt),
		reassembly: make(map[reassemblyKey]*reassemblyEntry),
		perSource:  make(map[string]int),
		closeCh:    make(chan struct{}),
	}
	go g.gcLoop()
	return g, nil
}

func NewGeckoConnServer(c *GeckoConfig, raw net.PacketConn) (net.PacketConn, error) {
	return NewGeckoConnClient(c, raw)
}

func (c *geckoConn) readObfs(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if n < smSaltLen {
			continue
		}
		c.obfs.Deobfuscate(p[:n], p)
		return n - smSaltLen, addr, nil
	}
}

func (c *geckoConn) writeObfs(p []byte, addr net.Addr) (n int, err error) {
	b := buf.New()
	b.Resize(0, int32(len(p)+smSaltLen))
	defer b.Release()
	c.obfs.Obfuscate(b.Bytes(), p)
	return c.PacketConn.WriteTo(b.Bytes(), addr)
}

func (g *geckoConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	chunks := randomFragmentChunks()
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgID.Add(1))
	for i := range chunks {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		buf := make([]byte, geckoHeaderSize+int(padLen)+len(chunk))
		n, err := encodeFrame(frameHeader{
			padLen:      padLen,
			msgID:       msgID,
			chunkIdx:    uint8(i),
			totalChunks: uint8(chunks),
		}, chunk, buf)
		if err != nil {
			return 0, err
		}
		if _, err := g.writeObfs(buf[:n], addr); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (g *geckoConn) randomPadLen(chunkLen int) uint16 {
	base := smSaltLen + geckoHeaderSize + chunkLen
	lo := max(g.minPkt, base)
	if lo > g.maxPkt {
		return 0
	}
	return uint16(lo - base + randIntn(g.maxPkt-lo+1))
}

func (g *geckoConn) acceptChunk(addr net.Addr, h frameHeader, payload []byte) ([]byte, bool) {
	key := reassemblyKey{addr: addr.String(), msgID: h.msgID}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, exists := g.reassembly[key]
	if !exists {
		// Per-source cap.
		if g.perSource[key.addr] >= geckoMaxPerSource {
			return nil, false
		}
		// Global cap with eviction.
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		e = &reassemblyEntry{
			chunks:   make([][]byte, h.totalChunks),
			total:    h.totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = e
		g.perSource[key.addr]++
	} else if e.total != h.totalChunks {
		// Inconsistent chunk count; drop.
		return nil, false
	}
	if int(h.chunkIdx) >= len(e.chunks) || e.chunks[h.chunkIdx] != nil {
		// Bad index or duplicate; drop.
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.chunks[h.chunkIdx] = cp
	e.received++
	if e.received < int(e.total) {
		return nil, false
	}

	total := 0
	for _, c := range e.chunks {
		total += len(c)
	}
	out := make([]byte, total)
	off := 0
	for _, c := range e.chunks {
		off += copy(out[off:], c)
	}
	g.dropEntryLocked(key)
	return out, true
}

func (g *geckoConn) gcLoop() {
	t := time.NewTicker(geckoReassemblyTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-g.closeCh:
			return
		case now := <-t.C:
			g.gcExpired(now)
		}
	}
}

func (g *geckoConn) gcExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.reassembly {
		if now.After(e.deadline) {
			g.dropEntryLocked(k)
		}
	}
}

func (g *geckoConn) dropEntryLocked(k reassemblyKey) {
	if _, ok := g.reassembly[k]; !ok {
		return
	}
	delete(g.reassembly, k)
	g.perSource[k.addr]--
	if g.perSource[k.addr] <= 0 {
		delete(g.perSource, k.addr)
	}
}

func (g *geckoConn) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldestDeadline time.Time
	first := true
	for k, e := range g.reassembly {
		if first || e.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = e.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

func (g *geckoConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&0x80 != 0 {
		// QUIC long header, do fragmentation.
		return g.writeFragmented(p, addr)
	}
	// QUIC short header (data), pass through.
	return g.writeObfs(p, addr)
}

func (g *geckoConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b := buf.New()
	b.Resize(0, finalmask.UDPSize)
	buf := b.Bytes()
	defer b.Release()
	for {
		n, addr, err := g.readObfs(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= 0 {
			continue
		}
		// Top bit set → Gecko fragment frame; clear → short-header packet
		// or garbage, passed through for QUIC to handle.
		if buf[0]&0x80 == 0 {
			return copy(p, buf[:n]), addr, nil
		}
		h, payload, decErr := decodeFrame(buf[:n])
		if decErr != nil {
			// Malformed frame; drop silently.
			continue
		}
		out, ready := g.acceptChunk(addr, h, payload)
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *geckoConn) Close() error {
	g.closeOnce.Do(func() { close(g.closeCh) })
	return g.PacketConn.Close()
}

func randomFragmentChunks() int {
	return geckoMinFragmentChunks + randIntn(geckoMaxFragmentChunks-geckoMinFragmentChunks+1)
}

func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

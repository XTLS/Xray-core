package noise

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakePacketConn struct {
	mu      sync.Mutex
	written [][]byte
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, bytes.Clone(p))
	return len(p), nil
}

func (c *fakePacketConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *fakePacketConn) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *fakePacketConn) Close() error                             { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error              { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error          { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error         { return nil }

func newConn() *noiseConn {
	return &noiseConn{PacketConn: &fakePacketConn{}, config: &Config{}, m: make(map[string]time.Time)}
}

func TestBuildSegmentBytes(t *testing.T) {
	c := newConn()
	got := c.buildSegment(&Segment{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}})
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, got)
}

func TestBuildSegmentTimestamp(t *testing.T) {
	c := newConn()
	before := time.Now().Unix()
	got := c.buildSegment(&Segment{Kind: Segment_TIMESTAMP})
	require.Len(t, got, 4)
	ts := int64(binary.BigEndian.Uint32(got))
	require.GreaterOrEqual(t, ts, before)
	require.LessOrEqual(t, ts, time.Now().Unix())
}

func TestBuildSegmentCounter(t *testing.T) {
	c := newConn()
	first := binary.BigEndian.Uint32(c.buildSegment(&Segment{Kind: Segment_COUNTER}))
	second := binary.BigEndian.Uint32(c.buildSegment(&Segment{Kind: Segment_COUNTER}))
	require.Equal(t, uint32(1), first)
	require.Equal(t, uint32(2), second)
}

func TestBuildSegmentNonce(t *testing.T) {
	c := newConn()
	a := c.buildSegment(&Segment{Kind: Segment_NONCE})
	b := c.buildSegment(&Segment{Kind: Segment_NONCE})
	require.Len(t, a, 8)
	require.Len(t, b, 8)
	require.NotEqual(t, a, b)
}

func TestBuildSegmentRandomSizes(t *testing.T) {
	c := newConn()
	for range 200 {
		require.Len(t, c.buildSegment(&Segment{Kind: Segment_RANDOM, MinSize: 24, MaxSize: 24}), 24)

		n := len(c.buildSegment(&Segment{Kind: Segment_RANDOM, MinSize: 20, MaxSize: 32}))
		require.GreaterOrEqual(t, n, 20)
		require.LessOrEqual(t, n, 32)

		for _, b := range c.buildSegment(&Segment{Kind: Segment_RANDOM_ASCII, MinSize: 40, MaxSize: 40}) {
			require.True(t, (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'), "not a letter: %q", b)
		}
		for _, b := range c.buildSegment(&Segment{Kind: Segment_RANDOM_DIGIT, MinSize: 40, MaxSize: 40}) {
			require.True(t, b >= '0' && b <= '9', "not a digit: %q", b)
		}
	}
}

func TestBuildPacketComposite(t *testing.T) {
	c := newConn()
	item := &Item{Segments: []*Segment{
		{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}},
		{Kind: Segment_TIMESTAMP},
		{Kind: Segment_RANDOM, MinSize: 24, MaxSize: 24},
	}}
	got := c.buildPacket(item)
	require.Len(t, got, 4+4+24)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, got[:4])
}

func TestBuildPacketLegacy(t *testing.T) {
	c := newConn()
	require.Equal(t, []byte{1, 2, 3}, c.buildPacket(&Item{Packet: []byte{1, 2, 3}}))
	require.Len(t, c.buildPacket(&Item{RandMin: 16, RandMax: 17}), 16)
}

func TestWriteToSendsNoiseThenPayload(t *testing.T) {
	raw := &fakePacketConn{}
	c := &noiseConn{
		PacketConn: raw,
		m:          make(map[string]time.Time),
		config: &Config{Items: []*Item{
			{Segments: []*Segment{{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}}, {Kind: Segment_RANDOM, MinSize: 8, MaxSize: 8}}},
			{RandMin: 40, RandMax: 41},
		}},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	payload := []byte("real-handshake")
	_, err := c.WriteTo(payload, addr)
	require.NoError(t, err)

	sent := raw.packets()
	require.Len(t, sent, 3)
	require.Len(t, sent[0], 12)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, sent[0][:4])
	require.Len(t, sent[1], 40)
	require.Equal(t, payload, sent[2])

	_, err = c.WriteTo(payload, addr)
	require.NoError(t, err)
	require.Len(t, raw.packets(), 4)
}

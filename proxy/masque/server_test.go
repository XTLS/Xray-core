package masque

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"golang.zx2c4.com/wireguard/tun"
)

type fakeTunnelConn struct {
	mu      sync.Mutex
	reads   chan []byte
	written [][]byte
	closed  bool
	stall   chan struct{}
}

func newFakeTunnelConn() *fakeTunnelConn {
	return &fakeTunnelConn{reads: make(chan []byte, 16)}
}

func (c *fakeTunnelConn) Read(b []byte) (int, error) {
	p, ok := <-c.reads
	if !ok {
		return 0, io.EOF
	}
	return copy(b, p), nil
}

func (c *fakeTunnelConn) Write(b []byte) (int, error) {
	if c.stall != nil {
		<-c.stall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, bytes.Clone(b))
	return len(b), nil
}

func (c *fakeTunnelConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.reads)
	}
	return nil
}

func (c *fakeTunnelConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *fakeTunnelConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeTunnelConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeTunnelConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeTunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeTunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeTunnelConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeDevice struct {
	mu      sync.Mutex
	reads   chan []byte
	written [][]byte
	closed  bool
}

func (d *fakeDevice) File() *os.File           { return nil }
func (d *fakeDevice) MTU() (int, error)        { return 1280, nil }
func (d *fakeDevice) Name() (string, error)    { return "fake", nil }
func (d *fakeDevice) Events() <-chan tun.Event { return nil }
func (d *fakeDevice) BatchSize() int           { return 1 }

func (d *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	p, ok := <-d.reads
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], p)
	return 1, nil
}

func (d *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, b := range bufs {
		d.written = append(d.written, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

func (d *fakeDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.reads)
	}
	return nil
}

func (d *fakeDevice) packets() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.written
}

func ipPacket(src, dst string) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if s.Is4() {
		b := make([]byte, 20)
		b[0] = 0x45
		b[8] = 64
		copy(b[12:16], s.AsSlice())
		copy(b[16:20], d.AsSlice())
		return b
	}
	b := make([]byte, 40)
	b[0] = 0x60
	b[7] = 64
	copy(b[8:24], s.AsSlice())
	copy(b[24:40], d.AsSlice())
	return b
}

func newTestServer(t *testing.T) (*Server, *fakeDevice) {
	t.Helper()
	pool4, err := newAddressPool(netip.MustParsePrefix("10.14.0.1/24"))
	require.NoError(t, err)
	pool6, err := newAddressPool(netip.MustParsePrefix("fd14::1/64"))
	require.NoError(t, err)
	dev := &fakeDevice{reads: make(chan []byte, tunnelQueueSize*2)}
	s := &Server{
		mtu:     1280,
		dev:     dev,
		pools:   []*addressPool{pool4, pool6},
		local:   []netip.Addr{netip.MustParseAddr("10.14.0.1"), netip.MustParseAddr("fd14::1")},
		tunnels: make(map[netip.Addr]*serverTunnel),
	}
	return s, dev
}

func addTunnel(t *testing.T, s *Server) (*serverTunnel, *fakeTunnelConn) {
	t.Helper()
	return addUserTunnel(t, s, &protocol.MemoryUser{})
}

func addUserTunnel(t *testing.T, s *Server, user *protocol.MemoryUser) (*serverTunnel, *fakeTunnelConn) {
	t.Helper()
	conn := newFakeTunnelConn()
	tunnel := newServerTunnel(conn, user)
	for _, pool := range s.pools {
		addr, ok := pool.allocate()
		require.True(t, ok)
		tunnel.addrs = append(tunnel.addrs, addr)
	}
	require.True(t, s.register(tunnel))
	go s.writeToTunnel(tunnel)
	t.Cleanup(tunnel.close)
	return tunnel, conn
}

func TestServerRoutesTunnelPackets(t *testing.T) {
	s, dev := newTestServer(t)
	a, aConn := addTunnel(t, s)
	b, bConn := addTunnel(t, s)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.14.0.2"), netip.MustParseAddr("fd14::2")}, a.addrs)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.14.0.3"), netip.MustParseAddr("fd14::3")}, b.addrs)

	toB := ipPacket("10.14.0.2", "10.14.0.3")
	toB6 := ipPacket("fd14::2", "fd14::3")
	toServer := ipPacket("10.14.0.2", "10.14.0.1")
	toInternet := ipPacket("fd14::2", "2001:db8::1")
	for _, p := range [][]byte{
		toB,
		toB6,
		ipPacket("10.14.0.2", "10.14.0.9"),
		ipPacket("fd14::2", "fd14::99"),
		ipPacket("fd14::2", "fe80::1"),
		ipPacket("fd14::2", "ff02::1"),
		ipPacket("10.14.0.2", "224.0.0.251"),
		ipPacket("10.14.0.2", "10.14.0.2"),
		toServer,
		toInternet,
	} {
		aConn.reads <- p
	}
	aConn.Close()
	require.NoError(t, s.readFromTunnel(a))

	require.Eventually(t, func() bool { return len(bConn.packets()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, [][]byte{toB, toB6}, bConn.packets())
	require.Equal(t, [][]byte{toServer, toInternet}, dev.packets())
	require.Empty(t, aConn.packets())
}

func TestServerRoutesStackPackets(t *testing.T) {
	s, dev := newTestServer(t)
	_, aConn := addTunnel(t, s)
	_, bConn := addTunnel(t, s)
	require.NoError(t, s.Start())

	toA := ipPacket("192.0.2.1", "10.14.0.2")
	toB := ipPacket("2001:db8::1", "fd14::3")
	dev.reads <- toA
	dev.reads <- ipPacket("192.0.2.1", "10.14.0.9")
	dev.reads <- toB
	require.Eventually(t, func() bool {
		return len(aConn.packets()) == 1 && len(bConn.packets()) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, [][]byte{toA}, aConn.packets())
	require.Equal(t, [][]byte{toB}, bConn.packets())

	require.NoError(t, s.Close())
	require.True(t, aConn.isClosed())
	require.True(t, bConn.isClosed())
	require.False(t, s.register(&serverTunnel{}))
}

func TestServerSlowTunnelDoesNotBlockOthers(t *testing.T) {
	s, dev := newTestServer(t)
	_, aConn := addTunnel(t, s)
	_, bConn := addTunnel(t, s)
	aConn.stall = make(chan struct{})
	defer close(aConn.stall)
	require.NoError(t, s.Start())
	defer s.Close()

	for range tunnelQueueSize + 10 {
		dev.reads <- ipPacket("192.0.2.1", "10.14.0.2")
	}
	toB := ipPacket("192.0.2.1", "10.14.0.3")
	dev.reads <- toB
	require.Eventually(t, func() bool { return len(bConn.packets()) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, [][]byte{toB}, bConn.packets())
}

func TestServerClosesTunnelConnections(t *testing.T) {
	s, _ := newTestServer(t)
	a, _ := addTunnel(t, s)
	conn := newFakeTunnelConn()
	require.True(t, a.track(conn))
	other := newFakeTunnelConn()
	require.True(t, a.track(other))
	a.untrack(other)

	s.release(a)
	require.True(t, conn.isClosed())
	require.False(t, other.isClosed())
	require.False(t, a.track(newFakeTunnelConn()))
	require.False(t, a.send(buf.New()))
}

func TestServerReleasesAddresses(t *testing.T) {
	s, _ := newTestServer(t)
	a, _ := addTunnel(t, s)
	s.release(a)
	require.Nil(t, s.lookup(netip.MustParseAddr("10.14.0.2")))
	b, _ := addTunnel(t, s)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.14.0.3"), netip.MustParseAddr("fd14::3")}, b.addrs)
	for range 250 {
		addTunnel(t, s)
	}
	c, _ := addTunnel(t, s)
	require.Equal(t, netip.MustParseAddr("10.14.0.254"), c.addrs[0])
	addr, ok := s.pools[0].allocate()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("10.14.0.2"), addr)
	_, ok = s.pools[0].allocate()
	require.False(t, ok)
}

func TestServerRemoveUserClosesTunnels(t *testing.T) {
	s, _ := newTestServer(t)
	s.validator = newValidator()
	alice := &protocol.MemoryUser{Email: "a@example.com", Account: &MemoryAccount{Password: "p"}}
	bob := &protocol.MemoryUser{Email: "b@example.com", Account: &MemoryAccount{Password: "p"}}
	require.NoError(t, s.AddUser(context.Background(), alice))
	require.NoError(t, s.AddUser(context.Background(), bob))
	_, aConn := addUserTunnel(t, s, alice)
	_, bConn := addUserTunnel(t, s, bob)

	require.NoError(t, s.RemoveUser(context.Background(), "a@example.com"))
	require.True(t, aConn.isClosed())
	require.False(t, bConn.isClosed())
	require.Error(t, s.RemoveUser(context.Background(), "a@example.com"))
	require.Nil(t, s.validator.get("a@example.com", "p"))
	require.Equal(t, bob, s.validator.get("b@example.com", "p"))
}

func TestPacketDestination(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[16:20], []byte{192, 0, 2, 1})
	addr, ok := packetDestination(v4)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), addr)

	v6 := make([]byte, 40)
	v6[0] = 0x60
	dst := netip.MustParseAddr("2001:db8::1").As16()
	copy(v6[24:40], dst[:])
	addr, ok = packetDestination(v6)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), addr)

	for _, b := range [][]byte{nil, v4[:19], v6[:39], {0x50}} {
		_, ok = packetDestination(b)
		require.False(t, ok)
	}
}

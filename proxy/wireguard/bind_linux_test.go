package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

type testCounter struct{ v atomic.Int64 }

func (c *testCounter) Value() int64      { return c.v.Load() }
func (c *testCounter) Set(n int64) int64 { return c.v.Swap(n) }
func (c *testCounter) Add(n int64) int64 { return c.v.Add(n) - n }

// gsoRecorder records the messages it is asked to send, and passes them on
// to next, or fails the ones with UDP_SEGMENT with failErr.
type gsoRecorder struct {
	next    msgWriter
	failErr error
	sizes   [][2]int // message length and segment size, 0 without UDP_SEGMENT
}

func (r *gsoRecorder) WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (int, int, error) {
	seg := 0
	if len(oob) > 0 {
		seg = int(binary.NativeEndian.Uint16(oob[unix.CmsgLen(0):]))
		if r.failErr != nil {
			return 0, 0, os.NewSyscallError("sendmsg", r.failErr)
		}
	}
	r.sizes = append(r.sizes, [2]int{len(b), seg})
	if r.next == nil {
		return len(b), len(oob), nil
	}
	return r.next.WriteMsgUDPAddrPort(b, oob, addr)
}

// testBufs returns datagrams of the given sizes in buffers with spare room,
// like wireguard-go's message buffers.
func testBufs(sizes ...int) [][]byte {
	bufs := make([][]byte, len(sizes))
	for i, n := range sizes {
		bufs[i] = make([]byte, n, 1<<16-1)
		bufs[i][0] = 4
		for j := 4; j < n; j++ {
			bufs[i][j] = byte(i + j)
		}
	}
	return bufs
}

func repeat(n, size int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = size
	}
	return s
}

func TestSendGSORuns(t *testing.T) {
	cases := []struct {
		name  string
		sizes []int
		want  [][2]int
	}{
		{"short tail ends a run", []int{1000, 1000, 1000, 500, 1000, 1200, 1200, 100},
			[][2]int{{3500, 1000}, {1000, 0}, {2500, 1200}}},
		{"segment limit", repeat(100, 100), [][2]int{{6400, 100}, {3600, 100}}},
		{"payload limit", repeat(50, 1452), [][2]int{{45 * 1452, 1452}, {5 * 1452, 1452}}},
	}
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	for _, c := range cases {
		r := &gsoRecorder{}
		n, err := sendGSO(r, testBufs(c.sizes...), addr, nil)
		if err != nil || n != len(c.sizes) {
			t.Fatalf("%s: sent %d, %v", c.name, n, err)
		}
		if len(r.sizes) != len(c.want) {
			t.Fatalf("%s: messages %v, want %v", c.name, r.sizes, c.want)
		}
		for i := range c.want {
			if r.sizes[i] != c.want[i] {
				t.Fatalf("%s: messages %v, want %v", c.name, r.sizes, c.want)
			}
		}
	}
}

// testBindSend sends runs through a bind on a loopback socket, wrapped like
// client.go does when stats are enabled, and checks what the peer gets.
func testBindSend(t *testing.T, network, bindAddr, peerAddr string, failErr error) {
	wc := &testCounter{}
	b := &bind{
		reserved: []byte{1, 2, 3},
		listenFunc: func() (net.PacketConn, error) {
			c, err := net.ListenPacket(network, bindAddr)
			if err != nil {
				return nil, err
			}
			return &PacketCounterConnection{PacketConn: c, WriteCounter: wc}, nil
		},
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.gso == nil {
		t.Skip("no UDP GSO")
	}
	r := &gsoRecorder{next: b.gso, failErr: failErr}
	b.gso = r

	pa, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetReadBuffer(1 << 20)

	var sizes []int
	for i := 0; i < conn.IdealBatchSize; i++ {
		if i%40 == 39 {
			sizes = append(sizes, 300+i)
		} else {
			sizes = append(sizes, 1200)
		}
	}
	bufs := testBufs(sizes...)
	want := make([][]byte, len(bufs))
	var total int64
	for i := range bufs {
		want[i] = bytes.Clone(bufs[i])
		copy(want[i][1:4], []byte{1, 2, 3})
		total += int64(len(bufs[i]))
	}
	ep := &conn.StdNetEndpoint{AddrPort: peer.LocalAddr().(*net.UDPAddr).AddrPort()}
	if err := b.Send(bufs, ep); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for i := range want {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want[i]) {
			t.Fatalf("datagram %d differs: got %d bytes, want %d", i, n, len(want[i]))
		}
	}
	if wc.Value() != total {
		t.Fatalf("write counter = %d, want %d", wc.Value(), total)
	}
	segments := 0
	for _, s := range r.sizes {
		if s[1] > 0 {
			segments++
		}
	}
	if failErr == nil && segments == 0 {
		t.Fatal("no UDP_SEGMENT sends")
	}
	if failErr != nil && (segments != 0 || b.gso != nil) {
		t.Fatalf("UDP_SEGMENT sends = %d, gso = %v after %v", segments, b.gso, failErr)
	}
}

func TestBindSendGSO(t *testing.T) {
	testBindSend(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", nil)
}

// Xray's dialer listens on a dual-stack socket and sends to IPv4 peers.
func TestBindSendGSODualStackToIPv4(t *testing.T) {
	testBindSend(t, "udp", "[::]:0", "127.0.0.1:0", nil)
}

func TestBindSendGSOIPv6(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	testBindSend(t, "udp6", "[::1]:0", "[::1]:0", nil)
}

func TestBindSendGSOFallback(t *testing.T) {
	for _, err := range []error{syscall.EIO, syscall.EMSGSIZE, syscall.EINVAL} {
		t.Run(err.Error(), func(t *testing.T) {
			testBindSend(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", err)
		})
	}
}

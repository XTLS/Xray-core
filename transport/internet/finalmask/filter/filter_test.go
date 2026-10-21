package filter

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func TestTCPFilterBeforeOtherMasks(t *testing.T) {
	for _, policy := range testPolicies(t) {
		t.Run(policy.name, func(t *testing.T) {
			blocked4 := sourceConn("192.0.2.1")
			blocked6 := sourceConn("2001:db8::1")
			unknown := &testConn{addr: &net.UnixAddr{Name: "filter.sock", Net: "unix"}}
			missing := new(testConn)
			allowed := sourceConn("198.51.100.1")
			allowed6 := sourceConn("2001:db8:1::1")
			raw := &testListener{conns: []net.Conn{blocked4, blocked6, unknown, missing, allowed, allowed6}}
			spy := new(recordMask)
			fm := finalmask.NewFinalMask([]finalmask.TCPMask{spy, policy.config}, nil, nil,
				func(context.Context, net.Addr) (net.Listener, error) { return raw, nil }, nil, nil)
			l, err := fm.Listen(context.Background(), &net.TCPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			whitelist := len(policy.config.AllowedSourceIps) > 0
			want := []net.Conn{allowed, allowed6}
			if !whitelist {
				want = append([]net.Conn{unknown, missing}, want...)
			}
			for _, expected := range want {
				if got, err := l.Accept(); err != nil || got != expected {
					t.Fatalf("Accept() = (%v, %v), want %v", got, err, expected)
				}
			}
			// Fake sockets panic on Read or Write. Rejection must not require handshake data.
			if !blocked4.closed || !blocked6.closed || unknown.closed != whitelist || missing.closed != whitelist || allowed.closed || allowed6.closed || raw.closed {
				t.Fatal("filter did not close only the blocked connections")
			}
			if len(spy.seen) != len(want) {
				t.Fatal("blocked connections reached the next mask")
			}
			for i, conn := range spy.seen {
				if conn != want[i] {
					t.Fatal("unexpected connection reached the next mask")
				}
			}
			if conn, err := l.Accept(); conn != nil || !errors.Is(err, io.EOF) {
				t.Fatalf("listener error was not propagated: (%v, %v)", conn, err)
			}
		})
	}
}

func TestTCPFilterUsesProxyHeader(t *testing.T) {
	for _, test := range []struct {
		name, peer, reported string
		blocked              bool
	}{
		{"blocked_header", "198.51.100.1", "192.0.2.1", true},
		{"allowed_header", "192.0.2.1", "198.51.100.1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			peer := sourceConn(test.peer)
			peer.Conn = server
			conn := proxyproto.NewConn(peer)
			next := sourceConn("198.51.100.2")
			l, err := testConfig(t, "192.0.2.0/24").Listen(&testListener{conns: []net.Conn{conn, next}})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			written := make(chan error, 1)
			go func() {
				_, err := client.Write([]byte("PROXY TCP4 " + test.reported + " 203.0.113.1 1234 443\r\n"))
				written <- err
			}()
			got, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			var want net.Conn = conn
			if test.blocked {
				want = next
			}
			if got != want || peer.closed != test.blocked {
				t.Fatal("filter did not follow the address supplied by PROXY protocol")
			}
		})
	}
}

func TestUDPFilter(t *testing.T) {
	for _, policy := range testPolicies(t) {
		t.Run(policy.name, func(t *testing.T) {
			allowed := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1234}
			allowed6 := &net.UDPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: 1234}
			unknown := datagram{data: []byte("unknown"), addr: &net.UnixAddr{Name: "filter.sock", Net: "unixgram"}}
			missing := datagram{data: []byte("missing address")}
			raw := &testPacketConn{reads: []datagram{
				{data: []byte("blocked"), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}},
				{addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}},
				unknown,
				missing,
				{addr: allowed},
				{data: []byte("allowed"), addr: allowed},
				{data: []byte("allowed6"), addr: allowed6},
				{data: []byte("blocked again"), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1234}},
			}}
			fm := finalmask.NewFinalMask(nil, []finalmask.UDPMask{policy.config}, nil, nil, nil,
				func(context.Context, net.Addr) (net.PacketConn, error) { return raw, nil })
			conn, err := fm.ListenPacket(context.Background(), &net.UDPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			buf := make([]byte, 64)
			if len(policy.config.AllowedSourceIps) == 0 {
				for _, expected := range []datagram{unknown, missing} {
					n, addr, err := conn.ReadFrom(buf)
					if err != nil || addr != expected.addr || string(buf[:n]) != string(expected.data) {
						t.Fatalf("unknown source was not allowed by blacklist: (%q, %v, %v)", buf[:n], addr, err)
					}
				}
			}
			if n, addr, err := conn.ReadFrom(buf); n != 0 || addr != allowed || err != nil {
				t.Fatalf("zero-length allowed datagram was lost: (%d, %v, %v)", n, addr, err)
			}
			n, addr, err := conn.ReadFrom(buf)
			if err != nil || addr != allowed || string(buf[:n]) != "allowed" {
				t.Fatalf("ReadFrom() = (%q, %v, %v)", buf[:n], addr, err)
			}
			n, addr, err = conn.ReadFrom(buf)
			if err != nil || addr != allowed6 || string(buf[:n]) != "allowed6" {
				t.Fatalf("IPv6 ReadFrom() = (%q, %v, %v)", buf[:n], addr, err)
			}
			if _, _, err := conn.ReadFrom(buf); !errors.Is(err, io.EOF) {
				t.Fatalf("underlying read error was not propagated: %v", err)
			}
			if raw.closed {
				t.Fatal("dropping a packet closed the shared UDP socket")
			}
		})
	}
}

func TestEmptyFilter(t *testing.T) {
	for _, empty := range []*Config{{}, {AllowedSourceIps: []*geodata.IPRule{}}} {
		rawListener := new(testListener)
		rawPacket := new(testPacketConn)
		if l, err := empty.Listen(rawListener); err != nil || l != rawListener {
			t.Fatal("an empty TCP filter should preserve the listener")
		}
		if conn, err := empty.WrapPacketConnServer(rawPacket, nil, nil); err != nil || conn != rawPacket {
			t.Fatal("an empty UDP filter should preserve the socket")
		}
	}
}

func TestUDPFilterReadError(t *testing.T) {
	for _, policy := range testPolicies(t) {
		t.Run(policy.name, func(t *testing.T) {
			for _, test := range []struct {
				name    string
				source  net.Addr
				blocked bool
			}{
				{"blocked", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, true},
				{"allowed", &net.UDPAddr{IP: net.ParseIP("198.51.100.1")}, false},
				{"missing address", nil, len(policy.config.AllowedSourceIps) > 0},
				{"unknown address", &net.UnixAddr{Name: "filter.sock", Net: "unixgram"}, len(policy.config.AllowedSourceIps) > 0},
			} {
				t.Run(test.name, func(t *testing.T) {
					source := test.source
					raw := &testPacketConn{reads: []datagram{{data: []byte("partial"), addr: source, err: io.ErrShortBuffer}}}
					conn, err := policy.config.WrapPacketConnServer(raw, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 32)
					n, addr, err := conn.ReadFrom(buf)
					if !errors.Is(err, io.ErrShortBuffer) {
						t.Fatalf("read error was not preserved: %v", err)
					}
					if test.blocked {
						if n != 0 || addr != nil {
							t.Fatal("partial data from a blocked source was returned with an error")
						}
					} else if n != 7 || addr != source || string(buf[:n]) != "partial" {
						t.Fatal("partial data from an unblocked source was changed")
					}
				})
			}
		})
	}
}

func testPolicies(t *testing.T) []struct {
	name   string
	config *Config
} {
	t.Helper()
	blocked := testConfig(t, "192.0.2.0/24", "2001:db8::/48").BlockedSourceIps
	allowed := testConfig(t, "198.51.100.0/24", "2001:db8:1::/48").BlockedSourceIps
	broader := testConfig(t, "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32").BlockedSourceIps
	return []struct {
		name   string
		config *Config
	}{
		{"blacklist", &Config{BlockedSourceIps: blocked}},
		{"whitelist", &Config{AllowedSourceIps: allowed}},
		{"both", &Config{BlockedSourceIps: blocked, AllowedSourceIps: broader}},
	}
}

func testConfig(t *testing.T, entries ...string) *Config {
	t.Helper()
	rules, err := geodata.ParseIPRules(entries)
	if err != nil {
		t.Fatal(err)
	}
	return &Config{BlockedSourceIps: rules}
}

type testConn struct {
	net.Conn
	addr   net.Addr
	closed bool
}

func sourceConn(ip string) *testConn {
	return &testConn{addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}}
}

func (c *testConn) RemoteAddr() net.Addr { return c.addr }
func (c *testConn) Close() error {
	c.closed = true
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

type testListener struct {
	net.Listener
	conns  []net.Conn
	closed bool
}

func (l *testListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, io.EOF
	}
	conn := l.conns[0]
	l.conns = l.conns[1:]
	return conn, nil
}

func (l *testListener) Close() error { l.closed = true; return nil }

type datagram struct {
	data []byte
	addr net.Addr
	err  error
}

type testPacketConn struct {
	net.PacketConn
	reads  []datagram
	closed bool
}

func (c *testPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, io.EOF
	}
	packet := c.reads[0]
	c.reads = c.reads[1:]
	return copy(p, packet.data), packet.addr, packet.err
}

func (c *testPacketConn) Close() error { c.closed = true; return nil }

type recordMask struct{ seen []net.Conn }

func (m *recordMask) WrapConnClient(c net.Conn, _ *xnet.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	return c, nil
}

func (m *recordMask) WrapConnServer(c net.Conn) (net.Conn, error) {
	m.seen = append(m.seen, c)
	return c, nil
}

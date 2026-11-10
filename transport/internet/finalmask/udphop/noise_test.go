package udphop

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

type noiseWrite struct {
	packet, source, destination string
	at                          time.Time
}

type noiseSocket struct {
	net.PacketConn
	local                                 *net.UDPAddr
	closed                                chan struct{}
	once                                  sync.Once
	writes                                *[]noiseWrite
	firstWrite                            chan struct{}
	deadline, readDeadline, writeDeadline time.Time
}

func (c *noiseSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	*c.writes = append(*c.writes, noiseWrite{string(p), c.local.String(), addr.String(), time.Now()})
	if c.firstWrite != nil {
		close(c.firstWrite)
		c.firstWrite = nil
	}
	return len(p), nil
}
func (c *noiseSocket) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, stdnet.ErrClosed
}
func (c *noiseSocket) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *noiseSocket) LocalAddr() net.Addr                { return c.local }
func (c *noiseSocket) SetDeadline(v time.Time) error      { c.deadline = v; return nil }
func (c *noiseSocket) SetReadDeadline(v time.Time) error  { c.readDeadline = v; return nil }
func (c *noiseSocket) SetWriteDeadline(v time.Time) error { c.writeDeadline = v; return nil }

type captureHop struct {
	Config
	conn *udpHopConn
}

func (c *captureHop) WrapPacketConnClient(raw net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	conn, err := c.Config.WrapPacketConnClient(raw, dest, dialer)
	if err == nil {
		c.conn = conn.(*udpHopConn)
	}
	return conn, err
}

// A mask between noise and hopping must still process both noise and payload.
type prefixMask struct{}
type prefixConn struct{ net.PacketConn }

func (*prefixMask) WrapPacketConnClient(c net.PacketConn, _ *net.Destination, _ *finalmask.Dialer) (net.PacketConn, error) {
	return &prefixConn{c}, nil
}
func (*prefixMask) WrapPacketConnServer(c net.PacketConn, _ net.Addr, _ *finalmask.ListenConfig) (net.PacketConn, error) {
	return c, nil
}
func (c *prefixConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	_, err := c.PacketConn.WriteTo(append([]byte("mask:"), p...), addr)
	return len(p), err
}

type noiseFixture struct {
	conn    net.Conn
	hop     *udpHopConn
	writes  []noiseWrite
	sockets []*noiseSocket
	port    int
	fail    bool
}

func newNoiseFixture(t *testing.T, script bool, delay int64) *noiseFixture {
	t.Helper()
	f := &noiseFixture{port: 10000}
	nc := &noise.Config{ResetMin: 3, ResetMax: 3, Items: []*noise.Item{
		{Packet: []byte("first"), DelayMin: delay, DelayMax: delay},
		{Packet: []byte("second"), DelayMin: delay, DelayMax: delay},
	}}
	if script {
		path := filepath.Join(t.TempDir(), "noise.lua")
		var code string
		if delay == 0 {
			code = `function HandleNoise(plan, address) plan:Add(address); plan:Add("second") end`
		} else {
			code = `function HandleNoise(plan, address) plan:Add(address, 20); plan:Add("second", 20) end`
		}
		if err := os.WriteFile(path, []byte(code), 0600); err != nil {
			t.Fatal(err)
		}
		nc.Script = path
	}
	hm := &captureHop{Config: Config{IntervalMin: 3600, IntervalMax: 3600}}
	fm := finalmask.NewFinalMask(nil, []finalmask.UDPMask{nc, &prefixMask{}, hm}, nil, nil,
		func(_ context.Context, d net.Destination) (net.PacketConn, net.Addr, error) {
			if f.fail {
				return nil, nil, errors.New("dial failed")
			}
			s := &noiseSocket{local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: f.port}, closed: make(chan struct{}), writes: &f.writes}
			f.sockets = append(f.sockets, s)
			return s, &net.UDPAddr{IP: d.Address.IP(), Port: int(d.Port)}, nil
		}, nil)
	var err error
	f.conn, err = fm.DialUDP(context.Background(), net.UDPDestination(net.ParseAddress("192.0.2.1"), 443))
	if err != nil {
		t.Fatal(err)
	}
	f.hop = hm.conn
	t.Cleanup(func() {
		f.conn.Close()
		for _, s := range f.sockets {
			select {
			case <-s.closed:
			default:
				t.Error("socket leaked")
			}
		}
	})
	return f
}

func (f *noiseFixture) write(t *testing.T) {
	t.Helper()
	if n, err := f.conn.Write([]byte("payload")); err != nil || n != 7 {
		t.Fatalf("write = %d, %v", n, err)
	}
}

func (f *noiseFixture) expect(t *testing.T, start int, script, sequence bool) {
	t.Helper()
	want := []string{"mask:payload"}
	if sequence {
		first := "mask:first"
		if script {
			first = "mask:" + f.hop.addr.String()
		}
		want = []string{first, "mask:second", "mask:payload"}
	}
	got := f.writes[start:]
	var packets []string
	for _, w := range got {
		packets = append(packets, w.packet)
		if w.source != f.hop.cur.LocalAddr().String() || w.destination != f.hop.addr.String() {
			t.Fatalf("wrong path: %+v", w)
		}
	}
	if !reflect.DeepEqual(packets, want) {
		t.Fatalf("packets = %q, want %q", packets, want)
	}
}

func TestNoiseEndpointTransitions(t *testing.T) {
	for _, script := range []bool{false, true} {
		name := "items"
		if script {
			name = "lua"
		}
		for _, mode := range []string{"source", "port", "ip", "combined"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newNoiseFixture(t, script, 0)
					f.write(t)
					f.expect(t, 0, script, true)
					for cycle := 0; cycle < 3; cycle++ {
						// Continuous traffic keeps refreshing the reset deadline.
						for i := 0; i < 5; i++ {
							time.Sleep(time.Second)
							start := len(f.writes)
							f.write(t)
							f.expect(t, start, script, false)
						}
						port, ip := uint32(8443), "192.0.2.2/32"
						f.port = 10001
						if cycle == 1 {
							port, ip, f.port = 443, "192.0.2.1/32", 10000
						}
						f.hop.local = mode == "source" || mode == "combined"
						f.hop.remote = mode != "source"
						if mode == "port" || mode == "combined" {
							f.hop.remotePorts = []uint32{port}
						}
						if mode == "ip" || mode == "combined" {
							f.hop.remoteIPs = []netip.Prefix{netip.MustParsePrefix(ip)}
						}
						f.hop.hop()
						start := len(f.writes)
						f.write(t)
						f.expect(t, start, script, true)
						// Same actual source and destination, even if the socket is replaced.
						f.hop.hop()
						start = len(f.writes)
						f.write(t)
						f.expect(t, start, script, false)
					}
					// Inactivity still resets noise on the current path.
					time.Sleep(4 * time.Second)
					start := len(f.writes)
					f.write(t)
					f.expect(t, start, script, true)
				})
			})
		}
	}
}

func TestNoiseFailedHopAndDeadlines(t *testing.T) {
	f := newNoiseFixture(t, false, 0)
	f.write(t)
	deadline := time.Now().Add(time.Minute)
	f.conn.SetDeadline(deadline)
	f.conn.SetReadDeadline(deadline.Add(time.Second))
	f.conn.SetWriteDeadline(deadline.Add(2 * time.Second))
	f.hop.local, f.hop.remote = true, true
	f.hop.remotePorts = []uint32{8443}
	f.hop.remoteIPs = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}
	f.port, f.fail = 10001, true
	old := f.hop.addr.String()
	f.hop.hop()
	if f.hop.addr.String() != old {
		t.Fatal("failed hop changed destination")
	}
	start := len(f.writes)
	f.write(t)
	f.expect(t, start, false, false)
	f.fail = false
	f.hop.hop()
	start = len(f.writes)
	f.write(t)
	f.expect(t, start, false, true)
	s := f.sockets[len(f.sockets)-1]
	if s.deadline != deadline || s.readDeadline != deadline.Add(time.Second) || s.writeDeadline != deadline.Add(2*time.Second) {
		t.Fatal("deadlines lost")
	}
}

func TestNoiseConcurrentHop(t *testing.T) {
	for _, script := range []bool{false, true} {
		name := "items"
		if script {
			name = "lua"
		}
		t.Run(name, func(t *testing.T) {
			f := newNoiseFixture(t, script, 20)
			f.hop.local, f.hop.remote, f.port = true, true, 10001
			f.hop.remotePorts = []uint32{8443}
			f.hop.remoteIPs = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}
			written := make(chan struct{})
			firstWrite := make(chan struct{})
			f.sockets[0].firstWrite = firstWrite
			go func() { defer close(written); f.write(t) }()
			<-firstWrite
			hopped := make(chan struct{})
			go func() { f.hop.hop(); close(hopped) }()
			<-written
			<-hopped
			if len(f.writes) != 3 {
				t.Fatalf("writes = %v", f.writes)
			}
			for i, w := range f.writes {
				if w.source != "127.0.0.1:10000" || w.destination != "192.0.2.1:443" {
					t.Fatalf("sequence split: %+v", w)
				}
				if i > 0 && w.at.Sub(f.writes[i-1].at) < 20*time.Millisecond {
					t.Fatal("noise delay lost")
				}
			}
			start := len(f.writes)
			f.write(t)
			f.expect(t, start, script, true)
			start = len(f.writes)
			f.write(t)
			f.expect(t, start, script, false)
		})
	}
}

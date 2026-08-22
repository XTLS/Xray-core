package finalmask_test

import (
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
	"github.com/xtls/xray-core/transport/internet/finalmask/realm"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"github.com/xtls/xray-core/transport/internet/finalmask/xicmp"
)

// These masks dial (STUN/raw socket) on wrap, so they cannot join the cases below; the build still fails here
// if a rebase brings one back on net.PacketConn, which memory_settings.go asserts unchecked.
var _ = []finalmask.Udpmask{(*realm.Config)(nil), (*xicmp.Config)(nil), (*xdns.Config)(nil)}

type sockoptConn struct {
	readBuf  int
	writeBuf int
}

func (c *sockoptConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *sockoptConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (c *sockoptConn) Close() error                           { return nil }
func (c *sockoptConn) LocalAddr() net.Addr                    { return nil }
func (c *sockoptConn) SetDeadline(time.Time) error            { return nil }
func (c *sockoptConn) SetReadDeadline(time.Time) error        { return nil }
func (c *sockoptConn) SetWriteDeadline(time.Time) error       { return nil }
func (c *sockoptConn) SetReadBuffer(bytes int) error          { c.readBuf = bytes; return nil }
func (c *sockoptConn) SetWriteBuffer(bytes int) error         { c.writeBuf = bytes; return nil }

// quic-go raises the socket buffers through this interface only, so every mask layer must pass them down.
func TestMaskSockoptReachesSocket(t *testing.T) {
	cases := []layerMask{
		{name: "mkcp-header-dns", mask: &header.Config{ID: int32(header.DNS), Domain: "www.baidu.com"}},
		{name: "mkcp-aes128gcm", mask: &aes128gcm.Config{Password: "123"}},
		{name: "mkcp-original", mask: &original.Config{}},
		{name: "header-custom", mask: &custom.UDPConfig{}},
		{name: "noise", mask: &noise.Config{}},
		{name: "salamander", mask: &salamander.Config{Password: "salamander-mask"}},
		{name: "gecko", mask: &salamander.GeckoConfig{Password: "gecko-mask"}},
		{name: "sudoku", mask: &sudoku.Config{Password: "sudoku-mask"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := &sockoptConn{}
			manager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{c.mask})

			conn, err := manager.WrapPacketConnClient(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			if err := conn.SetReadBuffer(1 << 23); err != nil {
				t.Fatalf("SetReadBuffer: %v", err)
			}
			if raw.readBuf != 1<<23 {
				t.Errorf("read buffer = %d, want %d", raw.readBuf, 1<<23)
			}

			if err := conn.SetWriteBuffer(1 << 22); err != nil {
				t.Fatalf("SetWriteBuffer: %v", err)
			}
			if raw.writeBuf != 1<<22 {
				t.Errorf("write buffer = %d, want %d", raw.writeBuf, 1<<22)
			}
		})
	}
}

// internet.FakePacketConn and friends lack the setters; the boundary adapter must swallow them, never fail a dial.
func TestWrapConnWithoutSockopt(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := finalmask.WrapConn(&internet.FakePacketConn{Conn: client})
	if err := conn.SetReadBuffer(1 << 23); err != nil {
		t.Errorf("SetReadBuffer: %v", err)
	}
	if err := conn.SetWriteBuffer(1 << 22); err != nil {
		t.Errorf("SetWriteBuffer: %v", err)
	}
	if _, ok := finalmask.UnwrapUdpMask(conn).(*internet.FakePacketConn); !ok {
		t.Error("UnwrapUdpMask did not return the underlying conn")
	}
}

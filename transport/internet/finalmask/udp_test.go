package finalmask_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	singM "github.com/sagernet/sing/common/metadata"
	singN "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/dns"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/srtp"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/utp"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/wechat"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/wireguard"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
)

func mustSendRecv(
	t *testing.T,
	from net.PacketConn,
	to net.PacketConn,
	msg []byte,
) {
	t.Helper()

	go func() {
		_, err := from.WriteTo(msg, to.LocalAddr())
		if err != nil {
			t.Error(err)
		}
	}()

	buf := make([]byte, 1024)
	n, _, err := to.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(msg) {
		t.Fatalf("unexpected size: %d", n)
	}

	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("unexpected data")
	}
}

type layerMask struct {
	name   string
	mask   finalmask.Udpmask
	layers int
}

type countingConn struct {
	net.Conn
	written atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *countingConn) Written() int64 {
	return c.written.Load()
}

type recordedPacketWrite struct {
	payload []byte
	addr    net.Addr
}

type scriptedPacketConn struct {
	local    *net.UDPAddr
	writes   chan recordedPacketWrite
	reads    chan recordedPacketWrite
	closed   atomic.Bool
	deadline atomic.Int64
}

func newScriptedPacketConn() *scriptedPacketConn {
	return &scriptedPacketConn{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000},
		writes: make(chan recordedPacketWrite, 8),
		reads:  make(chan recordedPacketWrite, 8),
	}
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	item, ok := <-c.reads
	if !ok {
		return 0, nil, io.EOF
	}
	copy(p, item.payload)
	return len(item.payload), item.addr, nil
}

func (c *scriptedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writes <- recordedPacketWrite{
		payload: append([]byte(nil), p...),
		addr:    addr,
	}
	return len(p), nil
}

func (c *scriptedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.reads)
	}
	return nil
}

func (c *scriptedPacketConn) LocalAddr() net.Addr { return c.local }
func (c *scriptedPacketConn) SetDeadline(t time.Time) error {
	c.deadline.Store(t.UnixNano())
	return nil
}
func (c *scriptedPacketConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(t.UnixNano())
	return nil
}
func (c *scriptedPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadline.Store(t.UnixNano())
	return nil
}

type captureUDPHandler struct {
	gotMetadata chan singM.Metadata
}

func (h *captureUDPHandler) NewConnection(_ context.Context, _ net.Conn, _ singM.Metadata) error {
	return nil
}

func (h *captureUDPHandler) NewPacketConnection(_ context.Context, _ singN.PacketConn, metadata singM.Metadata) error {
	select {
	case h.gotMetadata <- metadata:
	default:
	}
	return nil
}

func (h *captureUDPHandler) NewError(_ context.Context, _ error) {}

func newStandaloneEchoUDPConfig() *custom.UDPConfig {
	return &custom.UDPConfig{
		Mode: "standalone",
		Client: []*custom.UDPItem{
			{Packet: []byte{0xAA}},
			{Rand: 2, Save: "txid"},
		},
		Server: []*custom.UDPItem{
			{Packet: []byte{0xBB}},
			{Var: "txid"},
		},
	}
}

func newStandaloneStunLikeUDPConfig() *custom.UDPConfig {
	return &custom.UDPConfig{
		Mode: "standalone",
		Client: []*custom.UDPItem{
			{Packet: []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}},
			{Rand: 12, RandMin: 0x2A, RandMax: 0x2A, Save: "txid"},
		},
		Server: []*custom.UDPItem{
			{Packet: []byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}},
			{Var: "txid"},
			{Packet: []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}},
			{Rand: 2, Save: "mapped_port"},
			{Rand: 4, Save: "mapped_ip"},
		},
	}
}

func newStandaloneStunLikeUDPServerConfig() *custom.UDPConfig {
	return &custom.UDPConfig{
		Mode: "standalone",
		Client: []*custom.UDPItem{
			{Packet: []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}},
			{Rand: 12, RandMin: 0x2A, RandMax: 0x2A, Save: "txid"},
		},
		Server: []*custom.UDPItem{
			{Packet: []byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}},
			{Var: "txid"},
			{Packet: []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}},
			{
				Expr: &custom.Expr{
					Op: "be16",
					Args: []*custom.ExprArg{
						{
							Value: &custom.ExprArg_Expr{
								Expr: &custom.Expr{
									Op: "xor16",
									Args: []*custom.ExprArg{
										{Value: &custom.ExprArg_Metadata{Metadata: "src_port_u16"}},
										{Value: &custom.ExprArg_U64{U64: 0x2112}},
									},
								},
							},
						},
					},
				},
			},
			{
				Expr: &custom.Expr{
					Op: "be32",
					Args: []*custom.ExprArg{
						{
							Value: &custom.ExprArg_Expr{
								Expr: &custom.Expr{
									Op: "xor32",
									Args: []*custom.ExprArg{
										{Value: &custom.ExprArg_Metadata{Metadata: "src_ip4_u32"}},
										{Value: &custom.ExprArg_U64{U64: 0x2112A442}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func newUDPClientServerPair(t *testing.T, cfg *custom.UDPConfig) (net.PacketConn, net.PacketConn, net.PacketConn, net.PacketConn) {
	t.Helper()

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientRaw.Close() })

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverRaw.Close() })

	maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg})

	client, err := maskManager.WrapPacketConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := maskManager.WrapPacketConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	return clientRaw, serverRaw, client, server
}

func TestPacketConnReadWrite(t *testing.T) {
	cases := []layerMask{
		{
			name:   "aes128gcm",
			mask:   &aes128gcm.Config{Password: "123"},
			layers: 2,
		},
		{
			name:   "original",
			mask:   &original.Config{},
			layers: 2,
		},
		{
			name:   "dns",
			mask:   &dns.Config{Domain: "www.baidu.com"},
			layers: 2,
		},
		{
			name:   "srtp",
			mask:   &srtp.Config{},
			layers: 2,
		},
		{
			name:   "utp",
			mask:   &utp.Config{},
			layers: 2,
		},
		{
			name:   "wechat",
			mask:   &wechat.Config{},
			layers: 2,
		},
		{
			name:   "wireguard",
			mask:   &wireguard.Config{},
			layers: 2,
		},
		{
			name:   "salamander",
			mask:   &salamander.Config{Password: "1234"},
			layers: 2,
		},
		{
			name: "sudoku-prefer-ascii",
			mask: &sudoku.Config{
				Password: "sudoku-mask",
				Ascii:    "prefer_ascii",
			},
			layers: 1,
		},
		{
			name: "sudoku-custom-table",
			mask: &sudoku.Config{
				Password:    "sudoku-mask",
				Ascii:       "prefer_entropy",
				CustomTable: "xpxvvpvv",
			},
			layers: 1,
		},
		{
			name: "sudoku-custom-tables",
			mask: &sudoku.Config{
				Password:     "sudoku-mask",
				Ascii:        "prefer_entropy",
				CustomTables: []string{"xpxvvpvv", "vxpvxvvp"},
			},
			layers: 1,
		},
		{
			name: "custom",
			mask: &custom.UDPConfig{
				Client: []*custom.UDPItem{
					{
						Packet: []byte{1},
					},
					{
						Rand: 1,
					},
				},
				Server: []*custom.UDPItem{
					{
						Packet: []byte{1},
					},
					{
						Rand: 1,
					},
				},
			},
			layers: 1,
		},
		{
			name:   "salamander-single",
			mask:   &salamander.Config{Password: "1234"},
			layers: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mask := c.mask
			layers := c.layers
			if layers <= 0 {
				layers = 1
			}
			masks := make([]finalmask.Udpmask, 0, layers)
			for i := 0; i < layers; i++ {
				masks = append(masks, mask)
			}
			maskManager := finalmask.NewUdpmaskManager(masks)

			client, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			client, err = maskManager.WrapPacketConnClient(client)
			if err != nil {
				t.Fatal(err)
			}

			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			server, err = maskManager.WrapPacketConnServer(server)
			if err != nil {
				t.Fatal(err)
			}

			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = server.SetDeadline(time.Now().Add(time.Second))

			mustSendRecv(t, client, server, []byte("client -> server"))
			mustSendRecv(t, server, client, []byte("server -> client"))

			mustSendRecv(t, client, server, []byte{})
			mustSendRecv(t, server, client, []byte{})
		})
	}
}

func TestUDPcustomStaticHeaderWireShape(t *testing.T) {
	cfg := &custom.UDPConfig{
		Client: []*custom.UDPItem{
			{Packet: []byte{0xAA, 0xBB}},
			{Rand: 2, RandMin: 0x10, RandMax: 0x20},
		},
		Server: []*custom.UDPItem{
			{Packet: []byte{0xCC}},
			{Rand: 1, RandMin: 0x30, RandMax: 0x40},
		},
	}
	maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg})

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	client, err := maskManager.WrapPacketConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("udp-custom-wire")
	if _, err := client.WriteTo(payload, serverRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	_ = serverRaw.SetDeadline(time.Now().Add(time.Second))
	n, _, err := serverRaw.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(payload)+4 {
		t.Fatalf("unexpected wire size: got=%d want=%d", n, len(payload)+4)
	}
	if !bytes.Equal(buf[:2], []byte{0xAA, 0xBB}) {
		t.Fatalf("unexpected static header prefix: %x", buf[:2])
	}
	for i, b := range buf[2:4] {
		if b < 0x10 || b > 0x20 {
			t.Fatalf("rand byte %d out of range: %x", i, b)
		}
	}
	if !bytes.Equal(buf[4:n], payload) {
		t.Fatalf("unexpected payload: %q", buf[4:n])
	}
}

func TestUDPcustomServerRejectsMismatchedStaticHeader(t *testing.T) {
	cfg := &custom.UDPConfig{
		Client: []*custom.UDPItem{
			{Packet: []byte{0x01, 0x02}},
		},
		Server: []*custom.UDPItem{
			{Packet: []byte{0x03}},
		},
	}
	maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg})

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	server, err := maskManager.WrapPacketConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	_ = server.SetDeadline(time.Now().Add(200 * time.Millisecond))

	if _, err := clientRaw.WriteTo([]byte{0x09, 0x09, 'b', 'a', 'd'}, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 128)
	n, _, err := server.ReadFrom(buf)
	if n != 0 {
		t.Fatalf("expected no payload on mismatched header, got %d bytes", n)
	}
	if err != nil {
		t.Fatalf("expected mismatch to be dropped without surfaced error, got %v", err)
	}
}

func TestUDPcustomStandaloneClientSendsDetachedHandshakeBeforePayload(t *testing.T) {
	_, serverRaw, client, _ := newUDPClientServerPair(t, newStandaloneEchoUDPConfig())

	payload := []byte("standalone-payload")
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.WriteTo(payload, serverRaw.LocalAddr())
		writeErr <- err
	}()

	wire := make([]byte, 128)
	_ = serverRaw.SetDeadline(time.Now().Add(time.Second))
	n, addr, err := serverRaw.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("unexpected handshake size: got=%d want=3", n)
	}
	if !bytes.Equal(wire[:1], []byte{0xAA}) {
		t.Fatalf("unexpected handshake prefix: %x", wire[:1])
	}
	txid := append([]byte(nil), wire[1:n]...)

	if _, err := serverRaw.WriteTo(append([]byte{0xBB}, txid...), addr); err != nil {
		t.Fatal(err)
	}

	n, _, err = serverRaw.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:n], payload) {
		t.Fatalf("unexpected payload after handshake: %q", wire[:n])
	}

	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestUDPcustomStandaloneServerConsumesHandshakeAndAutoResponds(t *testing.T) {
	clientRaw, _, _, server := newUDPClientServerPair(t, newStandaloneEchoUDPConfig())

	_ = clientRaw.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	readPayload := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			readErr <- err
			return
		}
		readPayload <- append([]byte(nil), buf[:n]...)
	}()

	txid := []byte{0x10, 0x20}
	if _, err := clientRaw.WriteTo(append([]byte{0xAA}, txid...), server.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 128)
	n, _, err := clientRaw.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], append([]byte{0xBB}, txid...)) {
		t.Fatalf("unexpected auto-response: %x", buf[:n])
	}

	payload := []byte("server-side-standalone")
	if _, err := clientRaw.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-readPayload:
		if !bytes.Equal(got, payload) {
			t.Fatalf("unexpected payload: %q", got)
		}
	case err := <-readErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("payload read timeout")
	}
}

func TestUDPcustomStandaloneStunLikeExchangeUsesSavedTxidAndSrcMetadata(t *testing.T) {
	clientRaw, _, _, server := newUDPClientServerPair(t, newStandaloneStunLikeUDPServerConfig())

	_ = clientRaw.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	readPayload := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			readErr <- err
			return
		}
		readPayload <- append([]byte(nil), buf[:n]...)
	}()

	txid := bytes.Repeat([]byte{0x2A}, 12)
	request := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}, txid...)
	if _, err := clientRaw.WriteTo(request, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, _, err := clientRaw.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 0, 32)
	want = append(want, []byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}...)
	want = append(want, txid...)
	want = append(want, []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}...)

	clientAddr := clientRaw.LocalAddr().(*net.UDPAddr)
	xPort := uint16(clientAddr.Port) ^ 0x2112
	xIP := binary.BigEndian.Uint32(clientAddr.IP.To4()) ^ 0x2112A442
	want = append(want, byte(xPort>>8), byte(xPort))
	want = append(want, byte(xIP>>24), byte(xIP>>16), byte(xIP>>8), byte(xIP))

	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("unexpected stun-like response: got=%x want=%x", buf[:n], want)
	}

	payload := []byte("after-standalone-stun")
	if _, err := clientRaw.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-readPayload:
		if !bytes.Equal(got, payload) {
			t.Fatalf("unexpected payload after stun exchange: %q", got)
		}
	case err := <-readErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("payload read timeout")
	}
}

func TestUDPcustomStandaloneClientHandshakeSurvivesConcurrentReader(t *testing.T) {
	_, serverRaw, clientMask, serverMask := newUDPClientServerPair(t, newStandaloneStunLikeUDPConfig())

	go func() {
		buf := make([]byte, 2048)
		_ = clientMask.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _, _ = clientMask.ReadFrom(buf)
	}()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := serverMask.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == len([]byte("dns-payload")) && string(buf[:n]) == "dns-payload" {
				return
			}
			_ = addr
		}
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := clientMask.WriteTo([]byte("dns-payload"), serverRaw.LocalAddr())
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected handshake to complete even with concurrent reader")
	}
}

func TestSudokuBDD(t *testing.T) {
	t.Run("GivenSudokuTCPMask_WhenRoundTripWithAsciiPreference_ThenPayloadMatches", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password: "sudoku-tcp",
			Ascii:    "prefer_ascii",
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		serverConn, err := cfg.WrapConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		send := bytes.Repeat([]byte("client->server"), 1024)
		recv := make([]byte, len(send))

		writeErr := make(chan error, 1)
		go func() {
			_, wErr := clientConn.Write(send)
			writeErr <- wErr
		}()

		if _, err := io.ReadFull(serverConn, recv); err != nil {
			t.Fatal(err)
		}
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(send, recv) {
			t.Fatal("tcp sudoku payload mismatch")
		}
	})

	t.Run("GivenSudokuTCPMask_WhenRoundTrip_ThenBothDirectionsMatch", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password:   "sudoku-packed",
			Ascii:      "prefer_ascii",
			PaddingMin: 0,
			PaddingMax: 0,
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		serverConn, err := cfg.WrapConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		clientToServer := bytes.Repeat([]byte("client-packed->server"), 257)
		serverToClient := bytes.Repeat([]byte("server-packed->client"), 263)

		c2sRecv := make([]byte, len(clientToServer))
		c2sErr := make(chan error, 1)
		go func() {
			_, err := clientConn.Write(clientToServer)
			c2sErr <- err
		}()
		if _, err := io.ReadFull(serverConn, c2sRecv); err != nil {
			t.Fatal(err)
		}
		if err := <-c2sErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(clientToServer, c2sRecv) {
			t.Fatal("tcp client->server payload mismatch")
		}

		s2cRecv := make([]byte, len(serverToClient))
		s2cErr := make(chan error, 1)
		go func() {
			_, err := serverConn.Write(serverToClient)
			s2cErr <- err
		}()
		if _, err := io.ReadFull(clientConn, s2cRecv); err != nil {
			t.Fatal(err)
		}
		if err := <-s2cErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(serverToClient, s2cRecv) {
			t.Fatal("tcp server->client payload mismatch")
		}
	})

	t.Run("GivenSudokuTCPMask_WhenServerWritesDownlink_ThenWireBytesAreReduced", func(t *testing.T) {
		payload := bytes.Repeat([]byte("0123456789abcdef"), 192) // 3072 bytes, divisible by 3.

		countWireBytes := func(wrapServer func(net.Conn, *sudoku.Config) (net.Conn, error), cfg *sudoku.Config) int64 {
			t.Helper()

			clientRaw, serverRaw := net.Pipe()
			watchedServerRaw := &countingConn{Conn: serverRaw}

			clientConn, err := cfg.WrapConnClient(clientRaw)
			if err != nil {
				t.Fatal(err)
			}
			serverConn, err := wrapServer(watchedServerRaw, cfg)
			if err != nil {
				t.Fatal(err)
			}

			readErr := make(chan error, 1)
			go func() {
				_, err := io.CopyN(io.Discard, clientConn, int64(len(payload)))
				readErr <- err
			}()

			if _, err := serverConn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := <-readErr; err != nil {
				t.Fatal(err)
			}

			_ = clientConn.Close()
			_ = serverConn.Close()
			return watchedServerRaw.Written()
		}

		pureUplinkPackedDownlink := &sudoku.Config{
			Password:   "sudoku-bandwidth",
			Ascii:      "prefer_entropy",
			PaddingMin: 0,
			PaddingMax: 0,
		}
		packedDownlinkBytes := countWireBytes(func(raw net.Conn, cfg *sudoku.Config) (net.Conn, error) {
			return cfg.WrapConnServer(raw)
		}, pureUplinkPackedDownlink)
		legacyPureBytes := countWireBytes(func(raw net.Conn, cfg *sudoku.Config) (net.Conn, error) {
			return sudoku.NewTCPConn(raw, cfg)
		}, pureUplinkPackedDownlink)

		if packedDownlinkBytes >= legacyPureBytes {
			t.Fatalf("expected default packed downlink bytes < legacy pure bytes, got packed=%d pure=%d", packedDownlinkBytes, legacyPureBytes)
		}
	})

	t.Run("GivenSudokuMultiTableTCPMask_WhenRoundTrip_ThenPayloadMatches", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password:     "sudoku-multi-tcp",
			Ascii:        "prefer_entropy",
			CustomTables: []string{"xpxvvpvv", "vxpvxvvp"},
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		serverConn, err := cfg.WrapConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		send := bytes.Repeat([]byte("rotate-table"), 513)
		recv := make([]byte, len(send))

		writeErr := make(chan error, 1)
		go func() {
			_, wErr := clientConn.Write(send)
			writeErr <- wErr
		}()

		if _, err := io.ReadFull(serverConn, recv); err != nil {
			t.Fatal(err)
		}
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(send, recv) {
			t.Fatal("multi-table tcp sudoku payload mismatch")
		}
	})

	t.Run("GivenSudokuMultiTableTCPMask_WhenPackedDownlink_ThenPayloadMatches", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password:     "sudoku-multi-packed",
			Ascii:        "prefer_entropy",
			CustomTables: []string{"xpxvvpvv", "vxpvxvvp"},
			PaddingMin:   0,
			PaddingMax:   0,
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		serverConn, err := cfg.WrapConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		send := bytes.Repeat([]byte("packed-rotate"), 257)
		recv := make([]byte, len(send))

		writeErr := make(chan error, 1)
		go func() {
			_, wErr := clientConn.Write(send)
			writeErr <- wErr
		}()

		if _, err := io.ReadFull(serverConn, recv); err != nil {
			t.Fatal(err)
		}
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(send, recv) {
			t.Fatal("multi-table tcp sudoku payload mismatch")
		}
	})

	t.Run("GivenSudokuUDPMask_WhenNotInnermost_ThenWrapFails", func(t *testing.T) {
		cfg := &sudoku.Config{Password: "sudoku-udp"}
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()

		if _, err := cfg.WrapPacketConnClient(raw, 0, 1); err == nil {
			t.Fatal("expected innermost check failure")
		}
	})

	t.Run("GivenSudokuMultiTableUDPMask_WhenClientSendsMultipleDatagrams_ThenPayloadMatches", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password:     "sudoku-udp-multi",
			Ascii:        "prefer_entropy",
			CustomTables: []string{"xpxvvpvv", "vxpvxvvp"},
			PaddingMin:   0,
			PaddingMax:   0,
		}
		maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg})

		clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer clientRaw.Close()

		serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer serverRaw.Close()

		client, err := maskManager.WrapPacketConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		server, err := maskManager.WrapPacketConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))

		mustSendRecv(t, client, server, []byte("first-datagram"))
		mustSendRecv(t, client, server, []byte("second-datagram"))
		mustSendRecv(t, client, server, []byte("third-datagram"))
	})

	t.Run("GivenSudokuTCPMask_WhenCloseWriteIsCalled_ThenEOFPropagates", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password:   "sudoku-closewrite",
			Ascii:      "prefer_ascii",
			PaddingMin: 0,
			PaddingMax: 0,
		}

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		acceptCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			acceptCh <- conn
		}()

		clientRaw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer clientRaw.Close()

		var serverRaw net.Conn
		select {
		case serverRaw = <-acceptCh:
		case err := <-errCh:
			t.Fatal(err)
		case <-time.After(2 * time.Second):
			t.Fatal("accept timeout")
		}
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}
		serverConn, err := cfg.WrapConnServer(serverRaw)
		if err != nil {
			t.Fatal(err)
		}

		closeWriter, ok := clientConn.(interface{ CloseWrite() error })
		if !ok {
			t.Fatalf("wrapped conn does not expose CloseWrite: %T", clientConn)
		}

		writeErr := make(chan error, 1)
		go func() {
			if _, err := clientConn.Write([]byte("closewrite")); err != nil {
				writeErr <- err
				return
			}
			writeErr <- closeWriter.CloseWrite()
		}()

		buf := make([]byte, len("closewrite"))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, []byte("closewrite")) {
			t.Fatal("unexpected payload before closewrite")
		}
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}

		one := make([]byte, 1)
		n, err := serverConn.Read(one)
		if n != 0 || err != io.EOF {
			t.Fatalf("expected EOF after CloseWrite, got n=%d err=%v", n, err)
		}
	})

	t.Run("GivenSudokuTCPMask_WhenProxyUnwrapRawConn_ThenMaskConnIsRetained", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password: "sudoku-unwrap",
			Ascii:    "prefer_entropy",
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}

		unwrapped, readCounter, writeCounter := proxy.UnwrapRawConn(clientConn)
		if readCounter != nil || writeCounter != nil {
			t.Fatal("unexpected stat counters while unwrapping sudoku conn")
		}
		if unwrapped != clientConn {
			t.Fatalf("expected sudoku conn to stay wrapped, got %T", unwrapped)
		}
	})

	t.Run("GivenSudokuTCPMask_WhenProxyUnwrapRawConn_AfterDownlinkOptimization_ThenMaskConnIsRetained", func(t *testing.T) {
		cfg := &sudoku.Config{
			Password: "sudoku-packed-unwrap",
			Ascii:    "prefer_entropy",
		}

		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		defer serverRaw.Close()

		clientConn, err := cfg.WrapConnClient(clientRaw)
		if err != nil {
			t.Fatal(err)
		}

		unwrapped, readCounter, writeCounter := proxy.UnwrapRawConn(clientConn)
		if readCounter != nil || writeCounter != nil {
			t.Fatal("unexpected stat counters while unwrapping sudoku conn")
		}
		if unwrapped != clientConn {
			t.Fatalf("expected sudoku conn to stay wrapped, got %T", unwrapped)
		}
	})
}

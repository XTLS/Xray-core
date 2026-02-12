package finalmask_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/finalmask"
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
			defer client.Close()

			client, err = maskManager.WrapPacketConnClient(client)
			if err != nil {
				t.Fatal(err)
			}

			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

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

	t.Run("GivenSudokuUDPMask_WhenNotInnermost_ThenWrapFails", func(t *testing.T) {
		cfg := &sudoku.Config{Password: "sudoku-udp"}
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()

		if _, err := cfg.WrapPacketConnClient(raw, true, 0, false); err == nil {
			t.Fatal("expected innermost check failure")
		}
	})

	t.Run("GivenSudokuTCPMask_WhenProxyUnwrapRawConn_ThenUnderlyingConnIsExposed", func(t *testing.T) {
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
		if unwrapped != clientRaw {
			t.Fatalf("unexpected unwrapped conn type: %T", unwrapped)
		}
	})
}

package finalmask_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/dns"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/srtp"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/utp"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/wechat"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/wireguard"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
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
	name string
	mask finalmask.Udpmask
}

func TestPacketConnReadWrite(t *testing.T) {
	cases := []layerMask{
		{
			name: "aes128gcm",
			mask: &aes128gcm.Config{Password: "123"},
		},
		{
			name: "original",
			mask: &original.Config{},
		},
		{
			name: "dns",
			mask: &dns.Config{Domain: "www.baidu.com"},
		},
		{
			name: "srtp",
			mask: &srtp.Config{},
		},
		{
			name: "utp",
			mask: &utp.Config{},
		},
		{
			name: "wechat",
			mask: &wechat.Config{},
		},
		{
			name: "wireguard",
			mask: &wireguard.Config{},
		},
		{
			name: "salamander",
			mask: &salamander.Config{Password: "1234"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mask := c.mask

			maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{mask, mask})

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

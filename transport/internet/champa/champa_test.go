package champa_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/champa"
	"github.com/xtls/xray-core/transport/internet/champa/internal/noise"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Test_listenChampaAndDial verifies a full round trip: a Listen() spins up the
// AMP/Noise/KCP/smux server stack on a local port, Dial() builds the matching
// client stack pointed at it, and a single payload echoes back unchanged.
func Test_listenChampaAndDial(t *testing.T) {
	privkey, err := noise.GeneratePrivkey()
	common.Must(err)
	pubkey := noise.PubkeyFromPrivkey(privkey)

	listenPort := tcp.PickPort()

	gotConn := make(chan struct{}, 1)
	listener, err := champa.Listen(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "champa",
		ProtocolSettings: &champa.Config{
			Privkey: hex.EncodeToString(privkey),
		},
	}, func(conn stat.Connection) {
		gotConn <- struct{}{}
		go func(c stat.Connection) {
			defer c.Close()
			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := c.Read(b[:])
			if err != nil {
				return
			}
			if _, err := c.Write(b[:n]); err != nil {
				return
			}
		}(conn)
	})
	common.Must(err)
	defer listener.Close()

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "champa",
		ProtocolSettings: &champa.Config{
			ServerUrl: "http://" + net.LocalHostIP.IP().String() + ":" + listenPort.String() + "/",
			Pubkey:    hex.EncodeToString(pubkey),
		},
	}

	dest := net.TCPDestination(net.LocalHostIP, listenPort)
	conn, err := champa.Dial(context.Background(), dest, streamSettings)
	common.Must(err)
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var b [1024]byte
	n, err := conn.Read(b[:])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(b[:n]); got != "ping" {
		t.Fatalf("echo: got %q, want %q", got, "ping")
	}

	select {
	case <-gotConn:
	default:
		t.Fatal("server never observed a connection")
	}
}

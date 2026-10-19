package internet

import (
	"context"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestUDPControllerReceivesRemoteAddress(t *testing.T) {
	previous := Controllers
	t.Cleanup(func() { Controllers = previous })

	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
			if err != nil {
				if host == "::1" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer peer.Close()
			destination := net.DestinationFromAddr(peer.LocalAddr())

			for _, bindSource := range []bool{false, true} {
				name := "wildcard-source"
				var source net.Address
				if bindSource {
					name = "explicit-source"
					source = destination.Address
				}
				t.Run(name, func(t *testing.T) {
					var address string
					Controllers = []func(string, string, syscall.RawConn) error{
						func(_ string, remote string, _ syscall.RawConn) error {
							address = remote
							return nil
						},
					}
					conn, err := (&DefaultSystemDialer{}).Dial(context.Background(), source, destination, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if address != peer.LocalAddr().String() {
						t.Fatalf("controller address = %q, want remote endpoint %q", address, peer.LocalAddr())
					}
					if bindSource && !conn.LocalAddr().(*net.UDPAddr).IP.Equal(source.IP()) {
						t.Fatalf("local address = %v, want source IP %v", conn.LocalAddr(), source)
					}
				})
			}
		})
	}
}

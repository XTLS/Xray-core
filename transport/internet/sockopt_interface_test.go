//go:build linux || darwin || windows

package internet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// missingInterface is short enough for Linux's IFNAMSIZ and is not expected to exist.
const missingInterface = "xnoif0"

// TestMissingInterfaceFailsClosed checks that a dial with sockopt.interface
// naming an interface that does not exist fails with a BindError instead of
// falling back to the routing table (which can send the socket back into a TUN).
//
// The destination is a live local listener, so an unbound fallback would succeed.
func TestMissingInterfaceFailsClosed(t *testing.T) {
	sockopt := &internet.SocketConfig{Interface: missingInterface}

	for _, c := range []struct {
		name    string
		network net.Network
		host    string
	}{
		{"tcp4", net.Network_TCP, "127.0.0.1"},
		{"tcp6", net.Network_TCP, "::1"},
		{"udp4", net.Network_UDP, "127.0.0.1"},
		{"udp6", net.Network_UDP, "::1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var port net.Port
			switch c.network {
			case net.Network_TCP:
				l, err := net.Listen("tcp", net.JoinHostPort(c.host, "0"))
				if err != nil {
					t.Skipf("cannot listen on %s: %v", c.host, err)
				}
				defer l.Close()
				port = net.Port(l.Addr().(*net.TCPAddr).Port)
			case net.Network_UDP:
				p, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseAddress(c.host).IP()})
				if err != nil {
					t.Skipf("cannot listen on %s: %v", c.host, err)
				}
				defer p.Close()
				port = net.Port(p.LocalAddr().(*net.UDPAddr).Port)
			}

			dest := net.Destination{Address: net.ParseAddress(c.host), Port: port, Network: c.network}
			conn, err := (&internet.DefaultSystemDialer{}).Dial(context.Background(), nil, dest, sockopt)
			if conn != nil {
				conn.Close()
				t.Fatalf("dial to %s with missing interface %q succeeded: unbound fallback", dest, missingInterface)
			}
			if err == nil {
				t.Fatal("dial returned neither a connection nor an error")
			}
			var bindErr *internet.BindError
			if !errors.As(err, &bindErr) {
				t.Errorf("want *internet.BindError in the chain, got %T: %v", err, err)
			}
		})
	}
}

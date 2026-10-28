package internet_test

import (
	"context"
	"errors"
	"slices"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/windows"
)

// TestDialUDPBindFallback checks that a UDP dial whose dual-stack socket
// cannot be bound to both IP versions, as on an interface without one of
// them, moves to a socket of the destination's version only, and still
// fails when that one cannot be bound either.
func TestDialUDPBindFallback(t *testing.T) {
	for _, c := range []struct {
		dest   string
		reject []string // the kinds of socket that cannot be bound
		tried  []string // the kinds of socket tried, in order
		ok     bool
	}{
		{"127.0.0.1", nil, []string{"dual"}, true},
		{"127.0.0.1", []string{"dual"}, []string{"dual", "udp4"}, true},
		{"::1", []string{"dual"}, []string{"dual", "udp6"}, true},
		{"127.0.0.1", []string{"dual", "udp4"}, []string{"dual", "udp4"}, false},
	} {
		var tried []string
		internet.ControllersLock.Lock()
		saved := internet.Controllers
		internet.Controllers = []func(string, string, syscall.RawConn) error{func(network, _ string, rc syscall.RawConn) error {
			kind := network
			if network == "udp6" {
				rc.Control(func(fd uintptr) {
					if v6only, _ := windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY); v6only == 0 {
						kind = "dual"
					}
				})
			}
			tried = append(tried, kind)
			if slices.Contains(c.reject, kind) {
				return internet.NewBindError(errors.New("cannot bind " + kind))
			}
			return nil
		}}
		internet.ControllersLock.Unlock()

		conn, err := internet.DialSystem(context.Background(), net.UDPDestination(net.ParseAddress(c.dest), 53), nil)
		if conn != nil {
			conn.Close()
		}
		internet.ControllersLock.Lock()
		internet.Controllers = saved
		internet.ControllersLock.Unlock()

		if (err == nil) != c.ok || !slices.Equal(tried, c.tried) {
			t.Errorf("%s rejecting %v: tried %v, err %v", c.dest, c.reject, tried, err)
		}
	}
}

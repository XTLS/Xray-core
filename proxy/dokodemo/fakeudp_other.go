//go:build !linux && !openbsd
// +build !linux,!openbsd

package dokodemo

import (
	"fmt"
	"net"
)

func FakeUDP(addr *net.UDPAddr, mark int) (net.PacketConn, error) {
	return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("!linux")}
}

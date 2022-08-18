//go:build !linux
// +build !linux

package pf

import (
	"fmt"
	"net"
)

func FakeUDP(addr *net.UDPAddr, mark int) (net.PacketConn, error) {
	return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("!linux")}
}

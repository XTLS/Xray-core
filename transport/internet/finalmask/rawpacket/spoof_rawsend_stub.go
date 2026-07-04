//go:build !darwin && !freebsd && !linux && !(windows && (amd64 || 386))

package rawpacket

import (
	"fmt"
	"net/netip"
)

type rawSendFD struct{}

func openRawSender(dstIP netip.Addr) (*rawSendFD, error) {
	return nil, fmt.Errorf("rawpacket: raw sockets not supported on this platform")
}

func (r *rawSendFD) send(packet []byte) error {
	return fmt.Errorf("rawpacket: raw sockets not supported on this platform")
}

func (r *rawSendFD) close() error {
	return nil
}

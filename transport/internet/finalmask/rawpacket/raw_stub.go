//go:build !linux && !darwin && !freebsd && !(windows && (amd64 || 386))

package rawpacket

import (
	"errors"
	"net"
)

const PlatformSupported = false

func newRawSpoofer(conn net.Conn, method Method, ttl uint8) (rawSpoofer, error) {
	return nil, errors.New("rawpacket: unsupported platform")
}

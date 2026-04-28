//go:build !linux && !darwin && !freebsd && !(windows && (amd64 || 386))

package tlsspoof

import (
	"net"

	"errors"
)

const PlatformSupported = false

func newRawSpoofer(conn net.Conn, method Method) (rawSpoofer, error) {
	return nil, errors.New("tls_spoof: unsupported platform")
}

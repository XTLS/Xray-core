package socks

import (
	"io"

	"github.com/xtls/xray-core/common/net"
)

// WriteSocks5AuthFailureForTest exposes writeSocks5AuthFailure to external
// test packages. It is only compiled into test binaries.
func WriteSocks5AuthFailureForTest(w io.Writer, behavior AuthFailureBehavior, version, auth byte) error {
	return writeSocks5AuthFailure(w, behavior, version, auth)
}

// NewServerSessionForTest exposes a minimal server session to external tests.
func NewServerSessionForTest(config *ServerConfig) *ServerSession {
	return &ServerSession{
		config:       config,
		address:      net.AnyIP,
		port:         net.Port(0),
		localAddress: net.AnyIP,
	}
}

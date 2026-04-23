package champa

import (
	"net"

	"github.com/xtaci/smux"
)

// streamConn adapts an smux.Stream into a net.Conn that reports concrete
// *net.TCPAddr local/remote addresses. xray's DestinationFromAddr only
// accepts *net.TCPAddr / *net.UDPAddr / *net.UnixAddr and panics on anything
// else, so we must not return a custom net.Addr type from here.
type streamConn struct {
	*smux.Stream
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Stream.LocalAddr()
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Stream.RemoteAddr()
}

var _ net.Conn = (*streamConn)(nil)

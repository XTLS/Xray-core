package champa

import (
	"net"

	"github.com/xtaci/smux"
	xnet "github.com/xtls/xray-core/common/net"
)

// streamConn adapts an smux.Stream into a net.Conn that reports synthetic
// local/remote addresses chosen by Dial / Listen. smux.Stream's
// LocalAddr/RemoteAddr return the underlying KCP DummyAddr, which isn't
// useful to the rest of Xray.
type streamConn struct {
	*smux.Stream
	local  net.Addr
	remote xnet.Destination
}

func (c *streamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Stream.LocalAddr()
}

func (c *streamConn) RemoteAddr() net.Addr {
	if addr := c.remote.RawNetAddr(); addr != nil {
		return addr
	}
	return labelAddr(c.remote.NetAddr())
}

type labelAddr string

func (a labelAddr) Network() string { return "tcp" }
func (a labelAddr) String() string  { return string(a) }

var _ net.Conn = (*streamConn)(nil)

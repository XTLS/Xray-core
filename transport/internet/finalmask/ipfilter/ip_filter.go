package ipfilter

import (
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
)

type listener struct {
	net.Listener
	matcher geodata.IPMatcher
}

// Accept filters connections after the TCP handshake and before higher-level processing.
func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if matchAddress(l.matcher, conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

type packetConn struct {
	net.PacketConn
	matcher geodata.IPMatcher
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		// Reads may return both data and an error; filter the data first.
		if matchAddress(c.matcher, addr) {
			if err != nil {
				return 0, nil, err
			}
			continue
		}
		return n, addr, err
	}
}

func matchAddress(matcher geodata.IPMatcher, addr net.Addr) bool {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return matcher.Match(addr.IP)
	case *net.UDPAddr:
		return matcher.Match(addr.IP)
	case *net.IPAddr:
		return matcher.Match(addr.IP)
	default:
		return true
	}
}

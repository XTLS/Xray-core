package filter

import (
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
)

type listener struct {
	net.Listener
	filter *filter
}

// Accept filters connections after the TCP handshake and before higher-level processing.
func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.filter.rejects(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

type packetConn struct {
	net.PacketConn
	filter *filter
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		// Reads may return both data and an error; filter the data first.
		if c.filter.rejects(addr) {
			if err != nil {
				return 0, nil, err
			}
			continue
		}
		return n, addr, err
	}
}

type filter struct {
	blocked geodata.IPMatcher
	allowed geodata.IPMatcher
}

func (f *filter) rejects(addr net.Addr) bool {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	default:
		// Unknown sources cannot satisfy an allowlist.
		return f.allowed != nil
	}
	if f.blocked != nil && f.blocked.Match(ip) {
		return true
	}
	return f.allowed != nil && !f.allowed.Match(ip)
}

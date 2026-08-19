package tlsspoof

import (
	"net"
	"net/netip"

	"errors"
)

// The returned addresses are v4-unmapped and share the same family.
func tcpEndpoints(conn net.Conn) (*net.TCPConn, netip.AddrPort, netip.AddrPort, error) {
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return nil, netip.AddrPort{}, netip.AddrPort{}, errors.New("tls_spoof: underlying conn is not *net.TCPConn")
	}
	local := tcpConn.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := tcpConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	if !local.IsValid() || !remote.IsValid() {
		return nil, netip.AddrPort{}, netip.AddrPort{}, errors.New("tls_spoof: invalid conn address")
	}
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if local.Addr().Is4() != remote.Addr().Is4() {
		return nil, netip.AddrPort{}, netip.AddrPort{}, errors.New("tls_spoof: local/remote address family mismatch")
	}
	return tcpConn, local, remote, nil
}

//go:build !linux

package wireguard

import (
	"context"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

var _ Tunnel = (*gvisorNet)(nil)

type gvisorNet struct {
	tunnel
	net *netstack.Net
}

func (g *gvisorNet) Close() error {
	return g.tunnel.Close()
}

func (g *gvisorNet) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (
	net.Conn, error,
) {
	return g.net.DialContextTCPAddrPort(ctx, addr)
}

func (g *gvisorNet) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	return g.net.DialUDPAddrPort(laddr, raddr)
}

func CreateTun(localAddresses []netip.Addr, mtu int) (Tunnel, error) {
	out := &gvisorNet{}
	tun, n, err := netstack.CreateNetTUN(localAddresses, nil, mtu)
	if err != nil {
		return nil, err
	}
	out.tun, out.net = tun, n
	return out, nil
}

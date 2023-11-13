//go:build !linux

package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/wireguard/gvisortun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ Tunnel = (*gvisorNet)(nil)

type gvisorNet struct {
	tunnel
	net *gvisortun.Net
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

func CreateTun(localAddresses []netip.Addr, mtu int, handler promiscuousModeHandler) (Tunnel, error) {
	out := &gvisorNet{}
	tun, n, stack, err := gvisortun.CreateNetTUN(localAddresses, mtu, handler != nil)
	if err != nil {
		return nil, err
	}

	if handler != nil {
		// handler is only used for promiscuous mode
		// capture all packets and send to handler

		tcpForwarder := tcp.NewForwarder(stack, 0, 65535, func(r *tcp.ForwarderRequest) {
			go func(r *tcp.ForwarderRequest) {
				var (
					wq waiter.Queue
					id = r.ID()
				)

				// Perform a TCP three-way handshake.
				ep, err := r.CreateEndpoint(&wq)
				if err != nil {
					newError(err.String()).AtError().WriteToLog()
					r.Complete(true)
					return
				}
				r.Complete(false)
				defer ep.Close()

				// enable tcp keep-alive to prevent hanging connections
				ep.SocketOptions().SetKeepAlive(true)

				// local address is actually destination
				handler(xnet.TCPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort)), gonet.NewTCPConn(&wq, ep))
			}(r)
		})
		stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

		udpForwarder := udp.NewForwarder(stack, func(r *udp.ForwarderRequest) {
			go func(r *udp.ForwarderRequest) {
				var (
					wq waiter.Queue
					id = r.ID()
				)

				ep, err := r.CreateEndpoint(&wq)
				if err != nil {
					newError(err.String()).AtError().WriteToLog()
					return
				}
				defer ep.Close()

				// prevents hanging connections and ensure timely release
				ep.SocketOptions().SetLinger(tcpip.LingerOption{
					Enabled: true,
					Timeout: 15 * time.Second,
				})

				handler(xnet.UDPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort)), gonet.NewUDPConn(stack, &wq, ep))
			}(r)
		})
		stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	}

	out.tun, out.net = tun, n
	return out, nil
}

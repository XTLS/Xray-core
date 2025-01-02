package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/wireguard/gvisortun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type tunCreator func(localAddresses []netip.Addr, mtu int, handler promiscuousModeHandler) (Tunnel, error)

type promiscuousModeHandler func(dest xnet.Destination, conn net.Conn)

type Tunnel interface {
	BuildDevice(ipc string, bind conn.Bind) error
	DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error)
	Close() error
}

type tunnel struct {
	tun    tun.Device
	device *device.Device
	rw     sync.Mutex
}

func (t *tunnel) BuildDevice(ipc string, bind conn.Bind) (err error) {
	t.rw.Lock()
	defer t.rw.Unlock()

	if t.device != nil {
		return errors.New("device is already initialized")
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  fmt.Sprintf(format, args...),
			})
		},
		Errorf: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf(format, args...),
			})
		},
	}

	t.device = device.NewDevice(t.tun, bind, logger)
	if err = t.device.IpcSet(ipc); err != nil {
		return err
	}
	if err = t.device.Up(); err != nil {
		return err
	}
	return nil
}

func (t *tunnel) Close() (err error) {
	t.rw.Lock()
	defer t.rw.Unlock()

	if t.device == nil {
		return nil
	}

	t.device.Close()
	t.device = nil
	err = t.tun.Close()
	t.tun = nil
	return nil
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = fmt.Sprintf("%s%d", tunName, tunIndex)
	return
}

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

func createGVisorTun(localAddresses []netip.Addr, mtu int, handler promiscuousModeHandler) (Tunnel, error) {
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
					errors.LogError(context.Background(), err.String())
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
					errors.LogError(context.Background(), err.String())
					return
				}
				defer ep.Close()

				// prevents hanging connections and ensure timely release
				ep.SocketOptions().SetLinger(tcpip.LingerOption{
					Enabled: true,
					Timeout: 15 * time.Second,
				})

				handler(xnet.UDPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort)), gonet.NewUDPConn(&wq, ep))
			}(r)
		})
		stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	}

	out.tun, out.net = tun, n
	return out, nil
}

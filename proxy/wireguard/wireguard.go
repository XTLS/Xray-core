/*

Some of codes are copied from https://github.com/octeep/wireproxy, license below.

Copyright (c) 2022 Wind T.F. Wong <octeep@pm.me>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/

package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/wireguard-go/device"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	conf          *DeviceConfig
	net           *Net
	bind          *netBindClient
	policyManager policy.Manager
	dns           dns.Client
	// cached configuration
	ipc       string
	endpoints []netip.Addr
}

// New creates a new wireguard handler.
func New(ctx context.Context, conf *DeviceConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	endpoints, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	return &Handler{
		conf:          conf,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		dns:           v.GetFeature(dns.ClientType()).(dns.Client),
		ipc:           createIPCRequest(conf),
		endpoints:     endpoints,
	}, nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if h.bind == nil || h.bind.dialer != dialer || h.net == nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "switching dialer",
		})
		// bind := conn.NewStdNetBind() // TODO: conn.Bind wrapper for dialer
		bind := &netBindClient{
			dialer:  dialer,
			workers: int(h.conf.NumWorkers),
			dns:     h.dns,
		}

		net, err := h.makeVirtualTun(bind)
		if err != nil {
			bind.Close()
			return newError("failed to create virtual tun interface").Base(err)
		}

		h.net = net
		if h.bind != nil {
			h.bind.Close()
		}
		h.bind = bind
	}

	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	// Destination of the inner request.
	destination := outbound.Target
	command := protocol.RequestCommandTCP
	if destination.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}

	// resolve dns
	addr := destination.Address
	if addr.Family().IsDomain() {
		ips, err := h.dns.LookupIP(addr.Domain(), dns.IPOption{
			IPv4Enable: h.net.HasV4(),
			IPv6Enable: h.net.HasV6(),
		})
		if err != nil {
			return newError("failed to lookup DNS").Base(err)
		} else if len(ips) == 0 {
			return dns.ErrEmptyResponse
		}
		addr = net.IPAddress(ips[0])
	}

	p := h.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	addrPort := netip.AddrPortFrom(toNetIpAddr(addr), destination.Port.Value())

	var requestFunc func() error
	var responseFunc func() error

	if command == protocol.RequestCommandTCP {
		conn, err := h.net.DialContextTCPAddrPort(ctx, addrPort)
		if err != nil {
			return newError("failed to create TCP connection").Base(err)
		}

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if command == protocol.RequestCommandUDP {
		conn, err := h.net.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

// serialize the config into an IPC request
func createIPCRequest(conf *DeviceConfig) string {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\npreshared_key=%s\n",
			peer.PublicKey, peer.Endpoint, peer.KeepAlive, peer.PreSharedKey))

		for _, ip := range peer.AllowedIps {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}

	return request.String()[:request.Len()]
}

// convert endpoint string to netip.Addr
func parseEndpoints(conf *DeviceConfig) ([]netip.Addr, error) {
	endpoints := make([]netip.Addr, len(conf.Endpoint))
	for i, str := range conf.Endpoint {
		var addr netip.Addr
		if strings.Contains(str, "/") {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}
			addr = prefix.Addr()
			if prefix.Bits() != addr.BitLen() {
				return nil, newError("interface address subnet should be /32 for IPv4 and /128 for IPv6")
			}
		} else {
			var err error
			addr, err = netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}
		}
		endpoints[i] = addr
	}

	return endpoints, nil
}

// creates a tun interface on netstack given a configuration
func (h *Handler) makeVirtualTun(bind *netBindClient) (*Net, error) {
	tun, tnet, err := CreateNetTUN(h.endpoints, h.dns, int(h.conf.Mtu))
	if err != nil {
		return nil, err
	}

	bind.dnsOption.IPv4Enable = tnet.HasV4()
	bind.dnsOption.IPv6Enable = tnet.HasV6()

	// dev := device.NewDevice(tun, conn.NewDefaultBind(), nil /* device.NewLogger(device.LogLevelVerbose, "") */)
	dev := device.NewDevice(tun, bind, &device.Logger{
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
	}, int(h.conf.NumWorkers))
	err = dev.IpcSet(h.ipc)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}

func init() {
	common.Must(common.RegisterConfig((*DeviceConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*DeviceConfig))
	}))
}

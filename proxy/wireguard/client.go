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
	"context"
	"net/netip"

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
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	outbound.Name = "wireguard"
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.SetCanSpliceCopy(3)
	}

	if h.bind == nil || h.bind.dialer != dialer || h.net == nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "switching dialer",
		})
		// bind := conn.NewStdNetBind() // TODO: conn.Bind wrapper for dialer
		bind := &netBindClient{
			netBind: netBind{
				dns:     h.dns,
				workers: int(h.conf.NumWorkers),
			},
			dialer:   dialer,
			reserved: h.conf.Reserved,
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

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	p := h.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	var requestFunc func() error
	var responseFunc func() error

	if command == protocol.RequestCommandTCP {
		conn, err := h.net.DialContextTCP(ctx, addr, destination.Port)
		if err != nil {
			return newError("failed to create TCP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if command == protocol.RequestCommandUDP {
		conn, err := h.net.DialUDP(addr, destination.Port)
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

// creates a tun interface on netstack given a configuration
func (h *Handler) makeVirtualTun(bind *netBindClient) (*Net, error) {
	tun, tnet, err := CreateNetTUN(h.endpoints, int(h.conf.Mtu), true)
	if err != nil {
		return nil, err
	}

	bind.dnsOption.IPv4Enable = tnet.HasV4()
	bind.dnsOption.IPv6Enable = tnet.HasV6()

	// dev := device.NewDevice(tun, conn.NewDefaultBind(), nil /* device.NewLogger(device.LogLevelVerbose, "") */)
	dev := device.NewDevice(tun, bind, wgLogger, int(h.conf.NumWorkers))
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

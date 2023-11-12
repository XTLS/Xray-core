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
	stdnet "net"
	"net/netip"
	"strings"
	"sync"

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
	net           Tunnel
	bind          *netBindClient
	policyManager policy.Manager
	dns           dns.Client
	// cached configuration
	ipc              string
	endpoints        []netip.Addr
	hasIPv4, hasIPv6 bool
	wgLock           sync.Mutex
}

// New creates a new wireguard handler.
func New(ctx context.Context, conf *DeviceConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	endpoints, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	hasIPv4, hasIPv6 := false, false
	for _, e := range endpoints {
		if e.Is4() {
			hasIPv4 = true
		}
		if e.Is6() {
			hasIPv6 = true
		}
	}

	d := v.GetFeature(dns.ClientType()).(dns.Client)
	return &Handler{
		conf:          conf,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		dns:           d,
		ipc:           createIPCRequest(conf, d, hasIPv6),
		endpoints:     endpoints,
		hasIPv4:       hasIPv4,
		hasIPv6:       hasIPv6,
	}, nil
}

func (h *Handler) processWireGuard(dialer internet.Dialer) (err error) {
	h.wgLock.Lock()
	defer h.wgLock.Unlock()

	if h.bind != nil && h.bind.dialer == dialer && h.net != nil {
		return nil
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "switching dialer",
	})

	if h.net != nil {
		_ = h.net.Close()
		h.net = nil
	}
	if h.bind != nil {
		_ = h.bind.Close()
		h.bind = nil
	}

	// bind := conn.NewStdNetBind() // TODO: conn.Bind wrapper for dialer
	bind := &netBindClient{
		dialer:   dialer,
		workers:  int(h.conf.NumWorkers),
		dns:      h.dns,
		reserved: h.conf.Reserved,
	}
	defer func() {
		if err != nil {
			_ = bind.Close()
		}
	}()

	h.net, err = h.makeVirtualTun(bind)
	if err != nil {
		return newError("failed to create virtual tun interface").Base(err)
	}
	h.bind = bind
	return nil
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

	if err := h.processWireGuard(dialer); err != nil {
		return err
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
			IPv4Enable: h.hasIPv4,
			IPv6Enable: h.hasIPv6,
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
	addrPort := netip.AddrPortFrom(toNetIpAddr(addr), destination.Port.Value())

	var requestFunc func() error
	var responseFunc func() error

	if command == protocol.RequestCommandTCP {
		conn, err := h.net.DialContextTCPAddrPort(ctx, addrPort)
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
		conn, err := h.net.DialUDPAddrPort(netip.AddrPort{}, addrPort)
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

// serialize the config into an IPC request
func createIPCRequest(conf *DeviceConfig, d dns.Client, resolveEndPointToV4 bool) string {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	for _, peer := range conf.Peers {
		endpoint := peer.Endpoint
		host, port, err := net.SplitHostPort(endpoint)
		if resolveEndPointToV4 && err == nil {
			_, err = netip.ParseAddr(host)
			if err != nil {
				ipList, err := d.LookupIP(host, dns.IPOption{IPv4Enable: true, IPv6Enable: false})
				if err == nil && len(ipList) > 0 {
					endpoint = stdnet.JoinHostPort(ipList[0].String(), port)
				}
			}
		}

		request.WriteString(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\npreshared_key=%s\n",
			peer.PublicKey, endpoint, peer.KeepAlive, peer.PreSharedKey))

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
func (h *Handler) makeVirtualTun(bind *netBindClient) (Tunnel, error) {
	t, err := CreateTun(h.endpoints, int(h.conf.Mtu))
	if err != nil {
		return nil, err
	}

	bind.dnsOption.IPv4Enable = h.hasIPv4
	bind.dnsOption.IPv6Enable = h.hasIPv6

	if err = t.BuildDevice(h.ipc, bind); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

func init() {
	common.Must(common.RegisterConfig((*DeviceConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*DeviceConfig))
	}))
}

//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/sagernet/sing/common/control"
	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/proxy/wireguard/iptables"
	iptexec "github.com/xtls/xray-core/proxy/wireguard/iptables/exec"
	enetlink "github.com/xtls/xray-core/proxy/wireguard/netlink"
)

var _ Tunnel = (*deviceNet)(nil)

type deviceNet struct {
	dialer net.Dialer

	deviceName string

	handle    *enetlink.Handle
	linkAddrs []netlink.Addr
	routes    []*netlink.Route
	rules     []*netlink.Rule

	ipt iptables.Interface

	iptManglePreRoutingRules [][]string
}

func newDeviceNet(interfaceName string) *deviceNet {
	var dialer net.Dialer
	bindControl := control.BindToInterface(control.DefaultInterfaceFinder(), interfaceName, -1)
	dialer.Control = control.Append(dialer.Control, bindControl)
	return &deviceNet{dialer: dialer, deviceName: interfaceName}
}

func (d *deviceNet) BuildDevice(conf *DeviceConfig, ipc string, bind conn.Bind) error {
	privateKey, err := base64.StdEncoding.DecodeString(conf.SecretKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	var peers []enetlink.WireGuardPeer
	var dev enetlink.WireGuardDevice

	dev.Device = d.deviceName
	dev.Flags = enetlink.WGDEVICE_HAS_PRIVATE_KEY
	copy(dev.PrivateKey[:], privateKey)

	for _, peer := range conf.Peers {
		host, port := peer.Endpoint, 51820
		if h, p, err := net.SplitHostPort(peer.Endpoint); err == nil {
			host = h
			if newPort, err := strconv.Atoi(p); err == nil {
				port = newPort
			}
		}
		var peerIP net.IP
		if peerIP = net.ParseIP(host); peerIP == nil {
			if ips, err := net.LookupIP(host); err == nil {
				var v4, v6 net.IP
				for _, i := range ips {
					if v4 == nil && i.To4() != nil {
						v4 = i
					}
					if v6 == nil && i.To16() != nil {
						v6 = i
					}
				}
				if v4 != nil {
					peerIP = v4
				} else if v6 != nil {
					peerIP = v6
				}
			} else if len(ips) == 0 {
				return fmt.Errorf("failed to lookup IP empty records for %s", host)
			} else {
				return fmt.Errorf("failed to lookup IP for %s: %w", host, err)
			}
		}
		var allowedIPs []netip.Prefix
		for _, ip := range peer.AllowedIps {
			if p, err := netip.ParsePrefix(ip); err != nil {
				return fmt.Errorf("failed to parse allowed ip %s: %w", ip, err)
			} else {
				allowedIPs = append(allowedIPs, p)
			}
		}

		peerAddr, _ := netip.AddrFromSlice(peerIP)

		var peerConf enetlink.WireGuardPeer
		if peer.PublicKey != "" {
			publicKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to decode public key: %w", err)
			}
			copy(peerConf.PublicKey[:], publicKey)
			peerConf.Flags |= enetlink.WGPEER_HAS_PUBLIC_KEY
		}
		if peer.PreSharedKey != "" {
			preSharedKey, err := base64.StdEncoding.DecodeString(peer.PreSharedKey)
			if err != nil {
				return fmt.Errorf("failed to decode preshared key: %w", err)
			}
			copy(peerConf.PresharedKey[:], preSharedKey)
			peerConf.Flags |= enetlink.WGPEER_HAS_PRESHARED_KEY
		}

		peerConf.PersistentKeepaliveInterval = uint16(peer.KeepAlive)
		if peerConf.PersistentKeepaliveInterval <= 0 {
			peerConf.PersistentKeepaliveInterval = 25
		}
		peerConf.Flags |= enetlink.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL

		peerConf.AllowedIPs = allowedIPs
		peerConf.Endpoint = netip.AddrPortFrom(peerAddr, uint16(port))

		peers = append(peers, peerConf)
	}
	dev.Peers = peers
	return d.handle.WireGuardSetDevice(&dev)
}

func (d *deviceNet) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (
	net.Conn, error,
) {
	return d.dialer.DialContext(ctx, "tcp", addr.String())
}

func (d *deviceNet) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	dialer := d.dialer
	dialer.LocalAddr = &net.UDPAddr{IP: laddr.Addr().AsSlice(), Port: int(laddr.Port())}
	return dialer.DialContext(context.Background(), "udp", raddr.String())
}

func (d *deviceNet) Close() (err error) {
	var errs []error
	for _, rule := range d.rules {
		if err = d.handle.RuleDel(rule); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule: %w", err))
		}
	}
	for _, route := range d.routes {
		if err = d.handle.RouteDel(route); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete route: %w", err))
		}
	}
	for _, rule := range d.iptManglePreRoutingRules {
		if err = d.ipt.DeleteRule(iptables.TableMangle, iptables.ChainPrerouting, rule...); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete iptables rule: %w", err))
		}
	}
	wg := netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: d.deviceName}}
	if err = d.handle.LinkDel(&wg); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete wireguard interface: %w", err))
	}
	if d.handle != nil {
		d.handle.Close()
		d.handle = nil
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func createKernelTun(localAddresses []netip.Addr, mtu int, handler promiscuousModeHandler) (t Tunnel, err error) {
	if handler != nil {
		return nil, newError("TODO: support promiscuous mode")
	}

	var v4, v6 *net.IPNet
	for _, prefixes := range localAddresses {
		if v4 == nil && prefixes.Is4() {
			x := prefixes
			v4 = &net.IPNet{IP: x.AsSlice(), Mask: net.CIDRMask(x.BitLen(), 32)}
		}
		if v6 == nil && prefixes.Is6() && CheckUnixKernelIPv6IsEnabled() {
			x := prefixes
			v6 = &net.IPNet{IP: x.AsSlice(), Mask: net.CIDRMask(x.BitLen(), 128)}
		}
	}
	v4Enable, v6Enable := v4 != nil, v6 != nil

	n := CalculateInterfaceName("xray-out-")
	wg := netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: n, MTU: mtu}}

	out := newDeviceNet(n)
	out.handle, err = enetlink.NewHandle()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = out.Close()
		}
	}()

	// create wireguard interface
	if err = out.handle.LinkAdd(&wg); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = out.handle.LinkDel(&wg)
		}
	}()

	ipv4TableIndex := 3000
	if v4Enable {
		ipv4TableIndex, err = out.handle.EmptyRouteTableIndex(netlink.FAMILY_V4, ipv4TableIndex)
		if err != nil {
			return nil, err
		}
	}

	ipv6TableIndex := 3000
	if v6Enable {
		ipv6TableIndex, err = out.handle.EmptyRouteTableIndex(netlink.FAMILY_V6, ipv6TableIndex)
		if err != nil {
			return nil, err
		}
	}

	out.ipt = iptables.New(iptexec.New(), iptables.ProtocolIPv4)
	if exist := out.ipt.Present(); !exist {
		return nil, fmt.Errorf("iptables is not available")
	}

	l, err := netlink.LinkByName(n)
	if err != nil {
		return nil, err
	}

	if v4Enable {
		addr := netlink.Addr{IPNet: v4}
		out.linkAddrs = append(out.linkAddrs, addr)

		rt := &netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Table:     ipv4TableIndex,
		}
		out.routes = append(out.routes, rt)

		r := netlink.NewRule()
		r.Table, r.Family, r.Mark = ipv4TableIndex, unix.AF_INET, ipv4TableIndex
		out.rules = append(out.rules, r)

		// -i wg0 -j MARK --set-xmark 0x334/0xffffffff
		out.iptManglePreRoutingRules = append(out.iptManglePreRoutingRules, []string{
			"-i", n, "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0xffffffff", ipv4TableIndex),
		})
	}
	if v6Enable {
		addr := netlink.Addr{IPNet: v6}
		out.linkAddrs = append(out.linkAddrs, addr)

		rt := &netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:     ipv6TableIndex,
		}
		out.routes = append(out.routes, rt)

		r := netlink.NewRule()
		r.Table, r.Family, r.Src = ipv6TableIndex, unix.AF_INET6, addr.IPNet
		out.rules = append(out.rules, r)
	}

	for _, addr := range out.linkAddrs {
		if err = out.handle.AddrAdd(l, &addr); err != nil {
			return nil, fmt.Errorf("failed to add address %s to %s: %w", addr, n, err)
		}
	}
	if err = out.handle.LinkSetMTU(l, mtu); err != nil {
		return nil, err
	}
	if err = out.handle.LinkSetUp(l); err != nil {
		return nil, err
	}

	for _, route := range out.routes {
		if err = out.handle.RouteAdd(route); err != nil {
			return nil, fmt.Errorf("failed to add route %s: %w", route, err)
		}
	}
	for _, rule := range out.rules {
		if err = out.handle.RuleAdd(rule); err != nil {
			return nil, fmt.Errorf("failed to add rule %s: %w", rule, err)
		}
	}
	for _, rule := range out.iptManglePreRoutingRules {
		_, err = out.ipt.EnsureRule(iptables.Append, iptables.TableMangle,
			iptables.ChainPrerouting, rule...)
		if err != nil {
			return nil, fmt.Errorf("failed to add iptable rule %s: %w", rule, err)
		}
	}
	return out, nil
}

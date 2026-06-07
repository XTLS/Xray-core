//go:build linux

package wireguard

import (
	"context"
	goerrors "errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	tableIndex int = 10230
	mu         sync.Mutex
)

func allocateIPv6TableIndex() int {
	mu.Lock()
	defer mu.Unlock()

	if tableIndex > 10230 {
		errors.LogInfo(context.Background(), "allocate new ipv6 table index: ", tableIndex)
	}
	currentIndex := tableIndex
	tableIndex++
	return currentIndex
}

type kernelTun struct {
	tun.Device

	dialer    *net.Dialer
	lc        *net.ListenConfig
	handle    *netlink.Handle
	linkAddrs []netlink.Addr
	routes    []*netlink.Route
	rules     []*netlink.Rule
}

func createKernelTun(localAddresses, dnsServers []netip.Addr, mtu int) (tdev tun.Device, tnet *Net, err error) {
	var v4, v6 *netip.Addr
	for _, prefixes := range localAddresses {
		if v4 == nil && prefixes.Is4() {
			x := prefixes
			v4 = &x
		}
		if v6 == nil && prefixes.Is6() {
			x := prefixes
			v6 = &x
		}
	}

	writeSysctlZero := func(path string) error {
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.WriteFile(path, []byte("0"), 0o644)
	}

	// system configs.
	if v4 != nil {
		if err = writeSysctlZero("/proc/sys/net/ipv4/conf/all/rp_filter"); err != nil {
			return nil, nil, fmt.Errorf("failed to disable ipv4 rp_filter for all: %w", err)
		}
	}
	if v6 != nil {
		if err = writeSysctlZero("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err != nil {
			return nil, nil, fmt.Errorf("failed to enable ipv6: %w", err)
		}
		if err = writeSysctlZero("/proc/sys/net/ipv6/conf/all/rp_filter"); err != nil {
			return nil, nil, fmt.Errorf("failed to disable ipv6 rp_filter for all: %w", err)
		}
	}

	n := CalculateInterfaceName("wg")
	wgt, err := tun.CreateTUN(n, mtu)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = wgt.Close()
		}
	}()

	// disable linux rp_filter for tunnel device to avoid packet drop.
	// the operation require root privilege on container require '--privileged' flag.
	if v4 != nil {
		if err = writeSysctlZero("/proc/sys/net/ipv4/conf/" + n + "/rp_filter"); err != nil {
			return nil, nil, fmt.Errorf("failed to disable ipv4 rp_filter for tunnel: %w", err)
		}
	}
	if v6 != nil {
		if err = writeSysctlZero("/proc/sys/net/ipv6/conf/" + n + "/rp_filter"); err != nil {
			return nil, nil, fmt.Errorf("failed to disable ipv6 rp_filter for tunnel: %w", err)
		}
	}

	ipv6TableIndex := allocateIPv6TableIndex()
	if v6 != nil {
		r := &netlink.Route{Table: ipv6TableIndex}
		for {
			routeList, fErr := netlink.RouteListFiltered(netlink.FAMILY_V6, r, netlink.RT_FILTER_TABLE)
			if len(routeList) == 0 || fErr != nil {
				break
			}
			ipv6TableIndex--
			if ipv6TableIndex < 0 {
				return nil, nil, fmt.Errorf("failed to find available ipv6 table index")
			}
		}
	}

	t := &kernelTun{
		Device: wgt,
	}

	t.handle, err = netlink.NewHandle()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()

	l, err := netlink.LinkByName(n)
	if err != nil {
		return nil, nil, err
	}

	if v4 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   v4.AsSlice(),
				Mask: net.CIDRMask(v4.BitLen(), v4.BitLen()),
			},
		}
		t.linkAddrs = append(t.linkAddrs, addr)
	}
	if v6 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   v6.AsSlice(),
				Mask: net.CIDRMask(v6.BitLen(), v6.BitLen()),
			},
		}
		t.linkAddrs = append(t.linkAddrs, addr)

		rt := &netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			},
			Table: ipv6TableIndex,
		}
		t.routes = append(t.routes, rt)

		r := netlink.NewRule()
		r.Table, r.Family, r.Src = ipv6TableIndex, unix.AF_INET6, addr.IPNet
		t.rules = append(t.rules, r)
		r = netlink.NewRule()
		r.Table, r.Family, r.OifName = ipv6TableIndex, unix.AF_INET6, n
		t.rules = append(t.rules, r)
	}

	for _, addr := range t.linkAddrs {
		if err = t.handle.AddrAdd(l, &addr); err != nil {
			return nil, nil, fmt.Errorf("failed to add address %s to %s: %w", addr, n, err)
		}
	}
	if err = t.handle.LinkSetMTU(l, mtu); err != nil {
		return nil, nil, err
	}
	if err = t.handle.LinkSetUp(l); err != nil {
		return nil, nil, err
	}

	for _, route := range t.routes {
		if err = t.handle.RouteAdd(route); err != nil {
			return nil, nil, fmt.Errorf("failed to add route %s: %w", route, err)
		}
	}
	for _, rule := range t.rules {
		if err = t.handle.RuleAdd(rule); err != nil {
			return nil, nil, fmt.Errorf("failed to add rule %s: %w", rule, err)
		}
	}

	dialer := &net.Dialer{}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := syscall.BindToDevice(int(fd), n); err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to bind to device")
			}
		})
	}
	lc := &net.ListenConfig{}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := syscall.BindToDevice(int(fd), n); err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to bind to device")
			}
		})
	}
	t.dialer = dialer
	t.lc = lc

	tnet = &Net{
		DialContextTCPAddrPort: t.DialContextTCPAddrPort,
		DialUDPAddrPort:        t.DialUDPAddrPort,
		dnsServers:             dnsServers,
		hasV4:                  v4 != nil,
		hasV6:                  v6 != nil,
	}

	return t, tnet, nil
}

func (tun *kernelTun) Close() (err error) {
	var errs []error
	for _, rule := range tun.rules {
		if err = tun.handle.RuleDel(rule); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule: %w", err))
		}
	}
	for _, route := range tun.routes {
		if err = tun.handle.RouteDel(route); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete route: %w", err))
		}
	}
	if err = tun.Device.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close device: %w", err))
	}
	tun.handle.Close()
	errs = append(errs, tun.Device.Close())
	return goerrors.Join(errs...)
}

func (tun *kernelTun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return tun.dialer.DialContext(ctx, "tcp", addr.String())
}

func (tun *kernelTun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	conn, err := tun.lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{
		PacketConn: conn,
		Dest:       net.UDPAddrFromAddrPort(raddr),
	}, nil
}

func KernelTunSupported() (bool, error) {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0 // 0 means current process

	var data unix.CapUserData
	if err := unix.Capget(&hdr, &data); err != nil {
		return false, fmt.Errorf("failed to get capabilities: %v", err)
	}

	return (data.Effective & (1 << unix.CAP_NET_ADMIN)) != 0, nil
}

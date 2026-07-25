//go:build android

package tun

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	ipRoute2TableIndex = 2022
	ipRoute2RuleIndex  = 9000
)

// AndroidTun manages the TUN interface on Android.
// Two modes:
//   - FD mode: xray.tun.fd env set > 0, interface provided externally (V2RayNG etc.)
//   - Self-create mode: no FD, creates TUN via /dev/tun and configures addresses/routes/rules
type AndroidTun struct {
	tunFd   int
	tunName string
	options *Config
	ownsTun bool               // self-created vs FD-provided
	tunLink netlink.Link

	ifAddrs []netlink.Addr
	routes  []netlink.Route

	routeMonitorStop chan struct{}
	routeMonitorOnce sync.Once
}

var _ Tun = (*AndroidTun)(nil)

// NewTun builds a new AndroidTun.
// If xray.tun.fd > 0 is provided, it wraps that FD directly (legacy/App mode).
// Otherwise it creates a TUN device via the kernel interface.
func NewTun(options *Config) (Tun, error) {
	fdStr := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })

	if fdStr != "" {
		fd, err := strconv.Atoi(fdStr)
		if err == nil && fd > 0 {
			if err = unix.SetNonblock(fd, true); err != nil {
				_ = unix.Close(fd)
				return nil, err
			}
			return &AndroidTun{tunFd: fd, options: options}, nil
		}
	}

	// No external FD — create TUN ourselves
	tunFd, tunLink, name, err := openTun(options.Name)
	if err != nil {
		return nil, err
	}

	return &AndroidTun{
		tunFd:   tunFd,
		tunName: name,
		options: options,
		ownsTun: true,
		tunLink: tunLink,
	}, nil
}

// openTun opens or creates the TUN device.
// Android may have /dev/tun or /dev/net/tun depending on kernel config.
func openTun(name string) (int, netlink.Link, string, error) {
	ctrlPath := "/dev/tun"
	if _, err := os.Stat(ctrlPath); os.IsNotExist(err) {
		ctrlPath = "/dev/net/tun"
	}

	fd, err := unix.Open(ctrlPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, nil, "", errors.New("failed to open TUN device: ", ctrlPath).Base(err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, nil, "", err
	}

	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, nil, "", err
	}

	actualName := ifr.Name()
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, nil, "", err
	}

	tunLink, err := netlink.LinkByName(actualName)
	if err != nil {
		_ = unix.Close(fd)
		return -1, nil, "", err
	}

	return fd, tunLink, actualName, nil
}

// Start sets up TUN: MTU, IP addresses, link up, routes, ip rules.
// In FD mode the external App is expected to handle setup.
func (t *AndroidTun) Start() error {
	if !t.ownsTun {
		return nil
	}

	if err := netlink.LinkSetMTU(t.tunLink, int(t.options.MTU)); err != nil {
		return errors.New("failed to set MTU").Base(err)
	}
	if err := t.setInterfaceAddresses(); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(t.tunLink); err != nil {
		_ = t.unsetInterfaceAddresses()
		return err
	}
	if err := t.setRoutes(); err != nil {
		_ = t.unsetInterfaceAddresses()
		_ = netlink.LinkSetDown(t.tunLink)
		return err
	}
	if err := t.setRules(); err != nil {
		_ = t.unsetRoutes()
		_ = t.unsetInterfaceAddresses()
		_ = netlink.LinkSetDown(t.tunLink)
		return err
	}

	if updater != nil {
		t.routeMonitorStop = make(chan struct{})
		go t.monitorRouteChanges()
	}

	return nil
}

// Close tears down TUN: rules, routes, addresses, link down, fd.
func (t *AndroidTun) Close() error {
	if !t.ownsTun {
		return nil
	}
	t.routeMonitorOnce.Do(func() {
		if t.routeMonitorStop != nil {
			close(t.routeMonitorStop)
		}
	})
	_ = t.unsetRules()
	_ = t.unsetRoutes()
	_ = t.unsetInterfaceAddresses()
	_ = netlink.LinkSetDown(t.tunLink)
	return unix.Close(t.tunFd)
}

// Name returns the TUN interface name.
func (t *AndroidTun) Name() (string, error) {
	if t.tunLink != nil {
		return t.tunLink.Attrs().Name, nil
	}
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return "", err
	}
	if err = unix.IoctlIfreq(t.tunFd, unix.TUNGETIFF, ifr); err != nil {
		return "", err
	}
	return ifr.Name(), nil
}

// Index returns the TUN interface system index.
func (t *AndroidTun) Index() (int, error) {
	if t.tunLink != nil {
		return t.tunLink.Attrs().Index, nil
	}
	name, err := t.Name()
	if err != nil {
		return 0, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// newEndpoint returns a gVisor fdbased link endpoint wrapping the TUN fd.
func (t *AndroidTun) newEndpoint() (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
}

// ---------------------------------------------------------------------------
// Address management
// ---------------------------------------------------------------------------

func (t *AndroidTun) setInterfaceAddresses() error {
	for _, addrStr := range t.options.Gateway {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			_ = t.unsetInterfaceAddresses()
			return errors.New("invalid interface address ", addrStr).Base(err)
		}
		if err := netlink.AddrReplace(t.tunLink, addr); err != nil {
			_ = t.unsetInterfaceAddresses()
			return errors.New("failed to add address ", addrStr).Base(err)
		}
		t.ifAddrs = append(t.ifAddrs, *addr)
	}
	return nil
}

func (t *AndroidTun) unsetInterfaceAddresses() error {
	var errs []error
	for i := len(t.ifAddrs) - 1; i >= 0; i-- {
		if err := netlink.AddrDel(t.tunLink, &t.ifAddrs[i]); err != nil {
			errs = append(errs, err)
		}
	}
	t.ifAddrs = nil
	return errors.Combine(errs...)
}

// ---------------------------------------------------------------------------
// Route management — uses a custom routing table, not RT_TABLE_MAIN
// ---------------------------------------------------------------------------

func (t *AndroidTun) setRoutes() error {
	routes, err := androidRoutes(t.options.AutoSystemRoutingTable, ipRoute2TableIndex, t.tunLink.Attrs().Index)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if err := netlink.RouteAdd(&route); err != nil {
			_ = t.unsetRoutes()
			return errors.New("failed to add route").Base(err)
		}
		t.routes = append(t.routes, route)
	}
	return nil
}

func (t *AndroidTun) unsetRoutes() error {
	var errs []error
	for i := len(t.routes) - 1; i >= 0; i-- {
		if err := netlink.RouteDel(&t.routes[i]); err != nil {
			errs = append(errs, err)
		}
	}
	t.routes = nil
	return errors.Combine(errs...)
}

// androidRoutes returns routes on a custom routing table.
// Gateway addresses are not used on Android (point-to-point TUN).
func androidRoutes(cidrs []string, table, linkIndex int) ([]netlink.Route, error) {
	var routes []netlink.Route
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, errors.New("invalid route ", cidr).Base(err)
		}
		prefix = prefix.Masked()
		_, ipNet, err := net.ParseCIDR(prefix.String())
		if err != nil {
			return nil, errors.New("invalid CIDR ", prefix.String()).Base(err)
		}
		routes = append(routes, netlink.Route{
			Dst:       ipNet,
			LinkIndex: linkIndex,
			Table:     table,
		})
	}
	return routes, nil
}

// ---------------------------------------------------------------------------
// IP rule management — redirect traffic to the custom routing table
// ---------------------------------------------------------------------------

func (t *AndroidTun) setRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.NewRule()
		r.Priority = ipRoute2RuleIndex
		r.Family = family
		r.Table = ipRoute2TableIndex
		if err := netlink.RuleAdd(r); err != nil {
			_ = t.unsetRules()
			return errors.New("failed to add rule").Base(err)
		}
	}
	return nil
}

func (t *AndroidTun) unsetRules() error {
	list, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	var errs []error
	for _, rule := range list {
		if rule.Priority != ipRoute2RuleIndex {
			continue
		}
		del := netlink.NewRule()
		del.Family = rule.Family
		del.Priority = rule.Priority
		if err := netlink.RuleDel(del); err != nil {
			errs = append(errs, errors.New("failed to delete rule priority ", rule.Priority).Base(err))
		}
	}
	return errors.Combine(errs...)
}

// ---------------------------------------------------------------------------
// Route monitoring — re-find outbound interface on network changes
// ---------------------------------------------------------------------------

func (t *AndroidTun) monitorRouteChanges() {
	if netlinkBanned() {
		errors.LogInfo(context.Background(), "[tun] android: netlink banned by Google, fallback to polling /proc/net/route")
		t.pollRouteChanges()
		return
	}

	routeCh := make(chan netlink.RouteUpdate, 1)
	if err := netlink.RouteSubscribe(routeCh, t.routeMonitorStop); err != nil {
		errors.LogInfo(context.Background(), "[tun] android: failed to subscribe route changes: ", err)
		t.pollRouteChanges()
		return
	}

	linkCh := make(chan netlink.LinkUpdate, 1)
	if err := netlink.LinkSubscribe(linkCh, t.routeMonitorStop); err != nil {
		errors.LogInfo(context.Background(), "[tun] android: failed to subscribe link changes: ", err)
		t.pollRouteChanges()
		return
	}

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}

	for {
		select {
		case _, ok := <-routeCh:
			if !ok {
				return
			}
			timer.Reset(time.Second)
		case _, ok := <-linkCh:
			if !ok {
				return
			}
			timer.Reset(time.Second)
		case <-timer.C:
			t.updateOutboundInterface()
		case <-t.routeMonitorStop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

// pollRouteChanges polls /proc/net/route every 5s as fallback when netlink is banned.
func (t *AndroidTun) pollRouteChanges() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.updateOutboundInterface()
		case <-t.routeMonitorStop:
			return
		}
	}
}

// updateOutboundInterface updates the shared InterfaceUpdater directly,
// avoiding double-query that happens via updater.Update().
func (t *AndroidTun) updateOutboundInterface() {
	if updater == nil {
		return
	}
	var iface *net.Interface
	var err error
	if updater.fixedName != "" {
		iface, err = findOutboundByName(updater.fixedName, updater.tunIndex)
	} else {
		iface, err = findOutboundAuto(updater.tunIndex)
	}
	if err != nil || iface == nil {
		return
	}
	updater.Lock()
	if updater.iface == nil || updater.iface.Index != iface.Index || updater.iface.Name != iface.Name {
		updater.iface = iface
	}
	updater.Unlock()
}

// netlinkBanned checks whether Android 14+ has banned netlink for this process.
func netlinkBanned() bool {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_ROUTE)
	if err != nil {
		return true
	}
	defer unix.Close(fd)
	return unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil
}

// ---------------------------------------------------------------------------
// Outbound interface binding
// ---------------------------------------------------------------------------

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return unix.BindToDevice(int(fd), iface.Name)
}

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName != "" {
		return findOutboundByName(fixedName, tunIndex)
	}
	return findOutboundAuto(tunIndex)
}

func findOutboundByName(name string, tunIndex int) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, errors.New("outbound interface ", name, " not found").Base(err)
	}
	if iface.Index == tunIndex {
		return nil, errors.New("outbound interface cannot be the TUN interface")
	}
	return iface, nil
}

// findOutboundAuto finds the physical interface that has the default route.
// On Android the default route lives in a per-network table, not RT_TABLE_MAIN.
// We scan ip rules to find which table that is, then read routes from it.
func findOutboundAuto(tunIndex int) (*net.Interface, error) {
	table, err := androidDefaultRouteTable(unix.AF_INET)
	if err != nil {
		table, err = androidDefaultRouteTable(unix.AF_INET6)
	}
	if err != nil {
		return nil, errors.New("no default route table found via ip rule")
	}

	iface, err := findInterfaceInTable(table, tunIndex)
	if err == nil {
		return iface, nil
	}

	return findDefaultRouteFromProc(tunIndex)
}

// androidDefaultRouteTable scans ip rules to find the routing table
// Android uses for the physical default route.
//
// On Android the default route lives in a per-network table (e.g. wlan0),
// not RT_TABLE_MAIN. The ip rules entry for it has Mask=0xFFFF.
// This matches sing-tun's detection logic.
func androidDefaultRouteTable(family int) (int, error) {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return 0, errors.New("netlink rule list failed").Base(err)
	}
	for _, r := range rules {
		if r.Table != unix.RT_TABLE_MAIN && r.Table != unix.RT_TABLE_LOCAL && r.Mask != nil && *r.Mask == 0xFFFF {
			return r.Table, nil
		}
	}
	return 0, errors.New("no Android default route table found")
}

// findInterfaceInTable reads routes from a given table and returns the first
// non-loopback, non-TUN physical interface with a default route.
func findInterfaceInTable(table, tunIndex int) (*net.Interface, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.LinkIndex == 0 {
			continue
		}
		iface, err := net.InterfaceByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		if iface.Index == tunIndex || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			return iface, nil
		}
	}
	return nil, errors.New("no usable interface in table ", table)
}

func findDefaultRouteFromProc(tunIndex int) (*net.Interface, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Iface") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		iface, err := net.InterfaceByName(fields[0])
		if err != nil {
			continue
		}
		if iface.Index == tunIndex || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		return iface, nil
	}
	return nil, errors.New("no default route in /proc/net/route")
}

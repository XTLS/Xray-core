//go:build linux && !android

package tun

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/proxy/dns"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// LinuxTun is an object that handles tun network interface on linux
// current version is heavily stripped to do nothing more,
// then create a network interface, to be provided as file descriptor to gVisor ip stack
type LinuxTun struct {
	tunFd   int
	tunLink netlink.Link
	options *Config
	ownsTun bool

	interfaceAddresses []netlink.Addr
	systemRoutes       []netlink.Route
	routeMonitorStop   chan struct{}
	routeMonitorOnce   sync.Once

	systemDNSSet   bool
	systemDNSDirty bool
}

// resolvectlRunner runs a resolvectl command. Overridable for tests.
var resolvectlRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// systemDNSAddrs derives the addresses used for the system DNS takeover from the
// first IPv4 gateway: the gateway address itself is what a query from this
// interface appears to come from, and the next address is what the resolver is
// pointed at. The latter belongs to the TUN and is answered inside Xray;
// handing the configured public resolvers to resolvectl instead would leave the
// system querying them directly over the physical link, defeating the point of
// the TUN.
func systemDNSAddrs(gateway []string) (source, dns netip.Addr, ok bool) {
	for _, address := range gateway {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if !addr.Is4() {
			continue
		}
		return addr, addr.Next(), true
	}
	return netip.Addr{}, netip.Addr{}, false
}

func buildResolvectlArgs(action, iface string, extra ...string) []string {
	args := make([]string, 0, 2+len(extra))
	args = append(args, action, iface)
	args = append(args, extra...)
	return args
}

func runResolvectl(action, iface string, extra ...string) error {
	args := buildResolvectlArgs(action, iface, extra...)
	if _, err := resolvectlRunner("resolvectl", args...); err != nil {
		return errors.New("resolvectl ", action, " failed").Base(err)
	}
	return nil
}

// ifaceName returns the TUN interface name, or empty when the link is not
// available. Callers must treat empty as "nothing to configure".
func (t *LinuxTun) ifaceName() string {
	if t.tunLink == nil {
		return ""
	}
	attrs := t.tunLink.Attrs()
	if attrs == nil {
		return ""
	}
	return attrs.Name
}

// probeSourcePort is a representative client port for the routing probe. A real
// query arrives from an ephemeral port that cannot be known in advance, so this
// only matters for a rule that matches on a source port.
const probeSourcePort = 49152

// verifyDNSRouting reports whether a DNS query to address would actually be
// handled. Redirecting the system resolver at an address nothing answers would
// break name resolution outright, so the takeover only proceeds when routing
// hands such a query to a DNS-capable outbound.
//
// Overridable for tests.
var verifyDNSRouting = func(ctx context.Context, inboundTag, source, address string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return errors.New("invalid DNS address ", address).Base(err)
	}
	src, err := netip.ParseAddr(source)
	if err != nil || !src.Is4() {
		return errors.New("invalid source address ", source).Base(err)
	}

	instance := core.MustFromContext(ctx)

	// Without a DNS section Core installs a resolver that forwards to the system
	// resolver. Pointing the system resolver at the TUN would then close a loop
	// through the DNS outbound, so refuse instead of breaking resolution.
	if _, isSystemResolver := instance.GetFeature(feature_dns.ClientType()).(*localdns.Client); isSystemResolver {
		return errors.New("DNS feature is the system resolver, takeover would loop")
	}

	router, ok := instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return errors.New("router feature unavailable")
	}

	// A real query from this interface carries a source address, and rules may
	// match on it, so the probe has to carry one too.
	queryCtx := session.ContextWithInbound(ctx, &session.Inbound{
		Name:   "tun",
		Tag:    inboundTag,
		Source: xnet.UDPDestination(xnet.IPAddress(src.AsSlice()), probeSourcePort),
	})
	queryCtx = session.ContextWithOutbounds(queryCtx, []*session.Outbound{{
		Target: xnet.UDPDestination(xnet.IPAddress(ip.AsSlice()), 53),
	}})

	route, err := router.PickRoute(routingsession.AsRoutingContext(queryCtx))
	if err != nil {
		return errors.New("no route for ", address, ":53").Base(err)
	}

	manager, ok := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return errors.New("outbound manager unavailable")
	}

	handler := manager.GetHandler(route.GetOutboundTag())
	if handler == nil {
		return errors.New("outbound ", route.GetOutboundTag(), " does not exist")
	}
	if settings := handler.ProxySettings(); settings == nil || settings.Type != serial.GetMessageType(&dns.Config{}) {
		return errors.New("outbound ", route.GetOutboundTag(), " does not handle DNS")
	}
	return nil
}

// ConfigureSystemDNS points systemd-resolved at this interface so name lookups
// resolve through Xray instead of leaking to the physical link.
//
// It acts only when the config opts in, and it verifies the data path first:
// unless a query to the advertised address would actually be handled, host-wide
// resolution is left to the OS, which is the documented default. Errors are
// returned to the caller, which treats them as non-fatal.
func (t *LinuxTun) ConfigureSystemDNS(ctx context.Context, inboundTag string) error {
	if !t.options.AutoSystemDns {
		return nil
	}
	if t.systemDNSSet {
		return nil
	}

	// A previous revert may have failed. Retry before applying anything, so a
	// dirty resolver does not silently outlive the attempt to clean it up.
	if t.systemDNSDirty {
		if err := t.revertSystemDNS(); err != nil {
			return errors.New("previous system DNS revert still failing").Base(err)
		}
	}

	source, address, ok := systemDNSAddrs(t.options.Gateway)
	if !ok {
		return errors.New("no IPv4 gateway, cannot derive a system DNS address")
	}

	iface := t.ifaceName()
	if iface == "" {
		return errors.New("interface not available")
	}

	if err := verifyDNSRouting(ctx, inboundTag, source.String(), address.String()); err != nil {
		return errors.New("no DNS path at ", address.String(), ":53").Base(err)
	}

	// Applied as a sequence with rollback: a half-configured resolver would be
	// worse than none at all.
	if err := runResolvectl("dns", iface, address.String()); err != nil {
		return errors.New("resolvectl dns failed").Base(err)
	}
	if err := runResolvectl("domain", iface, "~."); err != nil {
		return t.rollbackSystemDNS(iface, errors.New("resolvectl domain failed").Base(err))
	}
	if err := runResolvectl("default-route", iface, "true"); err != nil {
		return t.rollbackSystemDNS(iface, errors.New("resolvectl default-route failed").Base(err))
	}

	t.systemDNSSet = true
	errors.LogInfo(ctx, "[tun] system DNS set to ", address.String(), " on ", iface)
	return nil
}

// rollbackSystemDNS undoes a partially applied takeover. A failed revert is
// recorded so the next attempt retries it, and is reported rather than
// swallowed.
func (t *LinuxTun) rollbackSystemDNS(iface string, cause error) error {
	if err := runResolvectl("revert", iface); err != nil {
		t.systemDNSDirty = true
		return errors.New("revert failed, per-link DNS settings may remain").Base(err).Base(cause)
	}
	return cause
}

// revertSystemDNS issues the revert and keeps the dirty flag in step with the
// outcome.
func (t *LinuxTun) revertSystemDNS() error {
	err := runResolvectl("revert", t.ifaceName())
	t.systemDNSDirty = err != nil
	if err != nil {
		return err
	}
	t.systemDNSSet = false
	return nil
}

// unsetSystemDNS hands DNS back to the OS. Only meaningful when
// ConfigureSystemDNS applied something, or a previous revert failed.
func (t *LinuxTun) unsetSystemDNS() {
	if !t.systemDNSSet && !t.systemDNSDirty {
		return
	}

	if t.ifaceName() == "" {
		// The link is gone, and its per-link settings went with it.
		t.systemDNSSet = false
		t.systemDNSDirty = false
		return
	}

	if err := t.revertSystemDNS(); err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to revert system DNS; per-link settings may remain until revert succeeds")
	}
}

// LinuxTun implements Tun
var _ Tun = (*LinuxTun)(nil)

// NewTun builds new tun interface handler (linux specific)
func NewTun(options *Config) (Tun, error) {
	tunFd, tunLink, fdProvided, err := openFromEnv(options.Name)
	if err != nil {
		return nil, err
	}
	if fdProvided {
		return &LinuxTun{
			tunFd:   tunFd,
			tunLink: tunLink,
			options: options,
		}, nil
	}

	tunFd, err = open(options.Name)
	if err != nil {
		return nil, err
	}

	tunLink, err = setup(options.Name, int(options.MTU))
	if err != nil {
		_ = unix.Close(tunFd)
		return nil, err
	}

	linuxTun := &LinuxTun{
		tunFd:   tunFd,
		tunLink: tunLink,
		options: options,
		ownsTun: true,
	}

	return linuxTun, nil
}

func openFromEnv(expectedName string) (int, netlink.Link, bool, error) {
	fdStr := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })
	if fdStr == "" {
		return -1, nil, false, nil
	}

	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return -1, nil, true, errors.New("invalid ", platform.TunFdKey).Base(err)
	}
	if fd < 3 {
		return -1, nil, true, errors.New("invalid ", platform.TunFdKey, ": file descriptor must be >= 3")
	}

	ifr, err := unix.NewIfreq("")
	if err != nil {
		return -1, nil, true, err
	}
	if err = unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return -1, nil, true, err
	}

	flags := ifr.Uint16()
	if flags&unix.IFF_TUN == 0 {
		return -1, nil, true, errors.New("invalid ", platform.TunFdKey, ": file descriptor is not a TUN device")
	}
	if flags&unix.IFF_NO_PI == 0 {
		return -1, nil, true, errors.New("invalid ", platform.TunFdKey, ": TUN device must use IFF_NO_PI")
	}

	actualName := ifr.Name()
	if expectedName != "" && actualName != expectedName {
		return -1, nil, true, errors.New("invalid ", platform.TunFdKey, ": TUN device name ", actualName, " does not match configured name ", expectedName)
	}

	tunLink, err := netlink.LinkByName(actualName)
	if err != nil {
		return -1, nil, true, err
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return -1, nil, true, err
	}

	return fd, tunLink, true, nil
}

// open the file that implements tun interface in the OS
func open(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	flags := unix.IFF_TUN | unix.IFF_NO_PI
	ifr.SetUint16(uint16(flags))
	err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}

	return fd, nil
}

// setup the interface through netlink socket
func setup(name string, MTU int) (netlink.Link, error) {
	tunLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	err = netlink.LinkSetMTU(tunLink, MTU)
	if err != nil {
		_ = netlink.LinkSetDown(tunLink)
		return nil, err
	}

	return tunLink, nil
}

// Start is called by handler to bring tun interface to life
func (t *LinuxTun) Start() error {
	if !t.ownsTun {
		return nil
	}

	if err := netlink.LinkSetUp(t.tunLink); err != nil {
		return err
	}

	if err := t.setInterfaceAddresses(); err != nil {
		_ = netlink.LinkSetDown(t.tunLink)
		return err
	}

	if err := t.setSystemRoutes(); err != nil {
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

// Close is called to shut down the tun interface
func (t *LinuxTun) Close() error {
	t.routeMonitorOnce.Do(func() {
		if t.routeMonitorStop != nil {
			close(t.routeMonitorStop)
		}
	})

	t.unsetSystemDNS()
	_ = t.unsetSystemRoutes()
	_ = t.unsetInterfaceAddresses()

	if t.ownsTun {
		_ = netlink.LinkSetDown(t.tunLink)
	}
	_ = unix.Close(t.tunFd)

	return nil
}

func (t *LinuxTun) Name() (string, error) {
	return t.tunLink.Attrs().Name, nil
}

func (t *LinuxTun) Index() (int, error) {
	return t.tunLink.Attrs().Index, nil
}

// newEndpoint builds new gVisor stack.LinkEndpoint from the tun interface file descriptor
func (t *LinuxTun) newEndpoint() (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
}

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return unix.BindToDevice(int(fd), iface.Name)
}

func (t *LinuxTun) setInterfaceAddresses() error {
	if len(t.options.Gateway) == 0 {
		return nil
	}
	for _, address := range t.options.Gateway {
		addr, err := netlink.ParseAddr(address)
		if err != nil {
			_ = t.unsetInterfaceAddresses()
			return errors.New("invalid interface address ", address).Base(err)
		}
		if err := netlink.AddrAdd(t.tunLink, addr); err != nil {
			_ = t.unsetInterfaceAddresses()
			return errors.New("failed to add interface address ", address).Base(err)
		}
		t.interfaceAddresses = append(t.interfaceAddresses, *addr)
	}
	return nil
}

func (t *LinuxTun) unsetInterfaceAddresses() error {
	var errs []error
	for i := len(t.interfaceAddresses) - 1; i >= 0; i-- {
		address := t.interfaceAddresses[i]
		if err := netlink.AddrDel(t.tunLink, &address); err != nil {
			errs = append(errs, errors.New("failed to delete interface address ", address.String()).Base(err))
		}
	}
	t.interfaceAddresses = nil
	return errors.Combine(errs...)
}

func (t *LinuxTun) setSystemRoutes() error {
	if len(t.options.AutoSystemRoutingTable) == 0 {
		return nil
	}
	tunIndex := t.tunLink.Attrs().Index
	for _, cidr := range t.options.AutoSystemRoutingTable {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return errors.New("invalid system route ", cidr).Base(err)
		}
		prefix = prefix.Masked()
		_, ipNet, _ := net.ParseCIDR(prefix.String())
		route := netlink.Route{
			LinkIndex: tunIndex,
			Dst:       ipNet,
			Priority:  1,
		}
		if err := netlink.RouteAdd(&route); err != nil {
			_ = t.unsetSystemRoutes()
			return errors.New("failed to add system route ", cidr).Base(err)
		}
		t.systemRoutes = append(t.systemRoutes, route)
	}
	return nil
}

func (t *LinuxTun) unsetSystemRoutes() error {
	var errs []error
	for i := len(t.systemRoutes) - 1; i >= 0; i-- {
		route := t.systemRoutes[i]
		if err := netlink.RouteDel(&route); err != nil {
			errs = append(errs, errors.New("failed to delete system route").Base(err))
		}
	}
	t.systemRoutes = nil
	return errors.Combine(errs...)
}

func (t *LinuxTun) monitorRouteChanges() {
	routeCh := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(routeCh, t.routeMonitorStop); err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to subscribe route changes")
		return
	}

	linkCh := make(chan netlink.LinkUpdate)
	if err := netlink.LinkSubscribe(linkCh, t.routeMonitorStop); err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to subscribe link changes")
		return
	}

	for {
		select {
		case _, ok := <-routeCh:
			if !ok {
				return
			}
			if updater != nil {
				updater.Update()
			}
		case _, ok := <-linkCh:
			if !ok {
				return
			}
			if updater != nil {
				updater.Update()
			}
		case <-t.routeMonitorStop:
			return
		}
	}
}

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName != "" {
		iface, err := net.InterfaceByName(fixedName)
		if err != nil {
			return nil, err
		}
		if iface.Index == tunIndex {
			return nil, errors.New("outbound interface cannot be the TUN interface")
		}
		return iface, nil
	}

	for _, family := range []int{
		netlink.FAMILY_V4,
		netlink.FAMILY_V6,
	} {
		iface, err := findDefaultInterface(family, tunIndex)
		if err == nil {
			return iface, nil
		}
	}

	return nil, errors.New("no usable outbound interface found")
}

func findDefaultInterface(family int, tunIndex int) (*net.Interface, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, err
	}

	var selected *net.Interface
	selectedMetric := -1

	for _, route := range routes {
		if route.Dst != nil {
			ones, _ := route.Dst.Mask.Size()
			if ones != 0 {
				continue
			}
		}

		if route.LinkIndex == 0 || route.LinkIndex == tunIndex {
			continue
		}

		iface, err := net.InterfaceByIndex(route.LinkIndex)
		if err != nil {
			continue
		}

		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if selected == nil || route.Priority < selectedMetric {
			selected = iface
			selectedMetric = route.Priority
		}
	}

	if selected == nil {
		return nil, errors.New("physical default route not found")
	}

	return selected, nil
}

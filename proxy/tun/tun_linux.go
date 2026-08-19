//go:build linux && !android

package tun

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
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

//go:build linux && !android

package tun

import (
	"net"
	"strconv"

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

	err := netlink.LinkSetUp(t.tunLink)
	if err != nil {
		return err
	}

	return nil
}

// Close is called to shut down the tun interface
func (t *LinuxTun) Close() error {
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

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName == "" {
		return nil, errors.New("automatic outbound interface selection is not supported on this platform")
	}
	iface, err := net.InterfaceByName(fixedName)
	if err != nil {
		return nil, err
	}
	if iface.Index == tunIndex {
		return nil, errors.New("outbound interface cannot be the TUN interface")
	}
	return iface, nil
}

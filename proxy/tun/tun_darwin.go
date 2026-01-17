//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	utunControlName = "com.apple.net.utun_control"
	utunOptIfName   = 2
	sysprotoControl = 2
)

type DarwinTun struct {
	tunFd   int
	name    string
	options TunOptions
}

var _ Tun = (*DarwinTun)(nil)
var _ GVisorTun = (*DarwinTun)(nil)

func NewTun(options TunOptions) (Tun, error) {
	tunFd, name, err := openUTun(options.Name)
	if err != nil {
		return nil, err
	}

	return &DarwinTun{
		tunFd:   tunFd,
		name:    name,
		options: options,
	}, nil
}

func (t *DarwinTun) Start() error {
	if t.options.MTU > 0 {
		if err := setMTU(t.name, int(t.options.MTU)); err != nil {
			return err
		}
	}
	return setState(t.name, true)
}

func (t *DarwinTun) Close() error {
	_ = setState(t.name, false)
	return unix.Close(t.tunFd)
}

func (t *DarwinTun) newEndpoint() (stack.LinkEndpoint, error) {
	return newDarwinEndpoint(t.tunFd, t.options.MTU), nil
}

func openUTun(name string) (int, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return -1, "", err
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}

	sockaddr := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: parseUTunUnit(name),
	}

	if err := unix.Connect(fd, sockaddr); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}

	tunName, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfName)
	if err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}

	tunName = strings.TrimRight(tunName, "\x00")
	if tunName == "" {
		_ = unix.Close(fd)
		return -1, "", errors.New("empty utun name")
	}

	return fd, tunName, nil
}

func parseUTunUnit(name string) uint32 {
	var unit uint32
	if _, err := fmt.Sscanf(name, "utun%d", &unit); err != nil {
		return 0
	}
	return unit + 1
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	_    [12]byte
}

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

func setMTU(name string, mtu int) error {
	if mtu <= 0 {
		return nil
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	ifr := ifreqMTU{MTU: int32(mtu)}
	copy(ifr.Name[:], name)
	return ioctlPtr(fd, unix.SIOCSIFMTU, unsafe.Pointer(&ifr))
}

func setState(name string, up bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	ifr := ifreqFlags{}
	copy(ifr.Name[:], name)

	if err := ioctlPtr(fd, unix.SIOCGIFFLAGS, unsafe.Pointer(&ifr)); err != nil {
		return err
	}

	if up {
		ifr.Flags |= unix.IFF_UP
	} else {
		ifr.Flags &^= unix.IFF_UP
	}

	return ioctlPtr(fd, unix.SIOCSIFFLAGS, unsafe.Pointer(&ifr))
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

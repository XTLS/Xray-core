//go:build android

package tun

import (
	"context"
	"net"
	"strconv"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type AndroidTun struct {
	tunFd   int
	options *Config
}

// DefaultTun implements Tun
var _ Tun = (*AndroidTun)(nil)

// NewTun builds new tun interface handler
func NewTun(options *Config) (Tun, error) {
	fd, err := strconv.Atoi(platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "0" }))
	errors.LogInfo(context.Background(), "read Android Tun Fd ", fd, err)

	err = unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return &AndroidTun{
		tunFd:   fd,
		options: options,
	}, nil
}

func (t *AndroidTun) Start() error {
	return nil
}

func (t *AndroidTun) Close() error {
	return nil
}

func (t *AndroidTun) Name() (string, error) {
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return "", err
	}
	if err = unix.IoctlIfreq(t.tunFd, unix.TUNGETIFF, ifr); err != nil {
		return "", err
	}
	return ifr.Name(), nil
}

func (t *AndroidTun) Index() (int, error) {
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

func (t *AndroidTun) newEndpoint() (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
}

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return unix.BindToDevice(int(fd), iface.Name)
}

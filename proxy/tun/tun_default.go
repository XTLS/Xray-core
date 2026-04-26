//go:build !linux && !windows && !android && !darwin && !freebsd

package tun

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type DefaultTun struct {
}

// DefaultTun implements Tun
var _ Tun = (*DefaultTun)(nil)

// NewTun builds new tun interface handler
func NewTun(options *Config) (Tun, error) {
	return nil, errors.New("Tun is not supported on your platform")
}

func (t *DefaultTun) Start() error {
	return errors.New("Tun is not supported on your platform")
}

func (t *DefaultTun) Close() error {
	return errors.New("Tun is not supported on your platform")
}

func (t *DefaultTun) Name() (string, error) {
	return "", errors.New("Tun is not supported on your platform")
}

func (t *DefaultTun) Index() (int, error) {
	return 0, errors.New("Tun is not supported on your platform")
}

func (t *DefaultTun) newEndpoint() (stack.LinkEndpoint, error) {
	return nil, errors.New("Tun is not supported on your platform")
}

func setinterface(string, string, uintptr, *net.Interface) error {
	return errors.New("Tun is not supported on your platform")
}

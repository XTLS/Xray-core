package tun

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// Tun interface implements tun interface interaction
type Tun interface {
	Start() error
	Close() error
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
	Name() (string, error)
	Index() (int, error)
	newEndpoint() (stack.LinkEndpoint, error)
}

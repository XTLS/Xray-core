//go:build windows

package tun

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// WindowsTun is an object that handles tun network interface on Windows
// current version is heavily stripped to do nothing more,
// then create a network interface, to be provided as endpoint to gVisor ip stack
type WindowsTun struct {
	options TunOptions
	adapter *wintun.Adapter
	session wintun.Session
	MTU     uint32
}

// WindowsTun implements Tun
var _ Tun = (*WindowsTun)(nil)

// WindowsTun implements GVisorTun
var _ GVisorTun = (*WindowsTun)(nil)

// NewTun creates a Wintun interface with the given name. Should a Wintun
// interface with the same name exist, it tried to be reused.
func NewTun(options TunOptions) (Tun, error) {
	// instantiate wintun adapter
	adapter, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	// start the interface with ring buffer capacity of 8 MiB
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}

	tun := &WindowsTun{
		options: options,
		adapter: adapter,
		session: session,
		// there is currently no iphndl.dll support, which is the netlink library for windows
		// so there is nowhere to change MTU for the Wintun interface, and we take its default value
		MTU: wintun.PacketSizeMax,
	}

	return tun, nil
}

func open(name string) (*wintun.Adapter, error) {
	var guid *windows.GUID
	// try to open existing adapter by name
	adapter, err := wintun.OpenAdapter(name)
	if err == nil {
		return adapter, nil
	}
	// try to create adapter anew
	adapter, err = wintun.CreateAdapter(name, "Xray", guid)
	if err == nil {
		return adapter, nil
	}
	return nil, err
}

func (t *WindowsTun) Start() error {
	return nil
}

func (t *WindowsTun) Close() error {
	t.session.End()
	_ = t.adapter.Close()

	return nil
}

// newEndpoint builds new gVisor stack.LinkEndpoint (WintunEndpoint) on top of WindowsTun
func (t *WindowsTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &WintunEndpoint{tun: t}, nil
}

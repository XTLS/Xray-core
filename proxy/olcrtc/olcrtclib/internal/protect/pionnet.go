// SPDX-License-Identifier: WTFPL

// ProtectedNet wraps Pion's network adapter. It applies Protector to each
// socket fd and hides tunnel-style interfaces from candidate gathering. Callers
// install it only when Protector is set, so default builds keep Pion's standard
// network stack.

package protect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
)

// tunInterfacePrefixes lists interface name prefixes excluded from candidate
// gathering. Keep pptp explicit; it does not match the ppp prefix.
//
//nolint:gochecknoglobals // fixed lookup table; a slice cannot be const
var tunInterfacePrefixes = []string{"tun", "ppp", "pptp"}

// ErrUnexpectedConnType is returned when a protected listen/dial yields an
// unexpected concrete type. The caller closes that connection instead of using
// an unprotected fallback.
var ErrUnexpectedConnType = errors.New("protect: unexpected connection type")

// ProtectedNet wraps Pion's standard net.
type ProtectedNet struct {
	*stdnet.Net
}

// NewProtectedNet builds a ProtectedNet over Pion's standard net.
func NewProtectedNet() (*ProtectedNet, error) {
	base, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("stdnet: %w", err)
	}
	return &ProtectedNet{Net: base}, nil
}

// Interfaces returns system interfaces after filtering tunnel-style devices.
func (n *ProtectedNet) Interfaces() ([]*transport.Interface, error) {
	all, err := n.Net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]*transport.Interface, 0, len(all))
	for _, ifc := range all {
		if !isTunInterface(ifc.Name) {
			out = append(out, ifc)
		}
	}
	return out, nil
}

// InterfaceByName applies the same filtering as Interfaces.
func (n *ProtectedNet) InterfaceByName(name string) (*transport.Interface, error) {
	if isTunInterface(name) {
		return nil, transport.ErrInterfaceNotFound
	}
	ifc, err := n.Net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", name, err)
	}
	return ifc, nil
}

func isTunInterface(name string) bool {
	for _, p := range tunInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ListenPacket listens for packets on a protected socket.
func (n *ProtectedNet) ListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: controlFunc}
	conn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, fmt.Errorf("listen packet %s %q: %w", network, address, err)
	}
	return conn, nil
}

// ListenUDP listens for UDP packets on a protected socket.
func (n *ProtectedNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	lc := net.ListenConfig{Control: controlFunc}
	address := udpAddrString(locAddr)
	pc, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s %q: %w", network, address, err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, ErrUnexpectedConnType
	}
	return uc, nil
}

// Dial connects to the address on a protected socket.
func (n *ProtectedNet) Dial(network, address string) (net.Conn, error) {
	d := net.Dialer{Control: controlFunc}
	conn, err := d.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %q: %w", network, address, err)
	}
	return conn, nil
}

// DialUDP connects to a UDP address on a protected socket.
func (n *ProtectedNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	d := net.Dialer{Control: controlFunc}
	if laddr != nil {
		d.LocalAddr = laddr
	}
	address := udpAddrString(raddr)
	conn, err := d.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s %q: %w", network, address, err)
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, ErrUnexpectedConnType
	}
	return uc, nil
}

// DialTCP connects to a TCP address on a protected socket.
func (n *ProtectedNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	d := net.Dialer{Control: controlFunc}
	if laddr != nil {
		d.LocalAddr = laddr
	}
	address := tcpAddrString(raddr)
	conn, err := d.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("dial tcp %s %q: %w", network, address, err)
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, ErrUnexpectedConnType
	}
	return tc, nil
}

// ListenTCP listens for TCP connections on a protected socket.
func (n *ProtectedNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	lc := net.ListenConfig{Control: controlFunc}
	address := tcpAddrString(laddr)
	l, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s %q: %w", network, address, err)
	}
	tl, ok := l.(*net.TCPListener)
	if !ok {
		_ = l.Close()
		return nil, ErrUnexpectedConnType
	}
	return protectedTCPListener{tl}, nil
}

// CreateDialer returns a dialer that protects each fd. It copies d and chains
// any existing Control hook.
func (n *ProtectedNet) CreateDialer(d *net.Dialer) transport.Dialer {
	var dialer net.Dialer
	if d != nil {
		dialer = *d
	}
	if dialer.ControlContext != nil {
		dialer.ControlContext = chainControlContext(dialer.ControlContext)
	} else {
		dialer.Control = chainControl(dialer.Control)
	}
	return n.Net.CreateDialer(&dialer)
}

// CreateListenConfig returns a listen config that protects each fd. It copies
// lc and chains any existing Control hook.
func (n *ProtectedNet) CreateListenConfig(lc *net.ListenConfig) transport.ListenConfig {
	var cfg net.ListenConfig
	if lc != nil {
		cfg = *lc
	}
	// net.ListenConfig exposes Control only; net.Dialer is the type with ControlContext.
	cfg.Control = chainControl(cfg.Control)
	return n.Net.CreateListenConfig(&cfg)
}

// chainControl runs the protector first, then any existing Control hook.
func chainControl(
	next func(network, address string, c syscall.RawConn) error,
) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if err := controlFunc(network, address, c); err != nil {
			return err
		}
		if next != nil {
			return next(network, address, c)
		}
		return nil
	}
}

// chainControlContext runs the protector first, then any existing ControlContext hook.
func chainControlContext(
	next func(context.Context, string, string, syscall.RawConn) error,
) func(context.Context, string, string, syscall.RawConn) error {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if err := controlFunc(network, address, c); err != nil {
			return err
		}
		if next != nil {
			return next(ctx, network, address, c)
		}
		return nil
	}
}

type protectedTCPListener struct {
	*net.TCPListener
}

// AcceptTCP accepts the next TCP connection on the protected listener.
func (l protectedTCPListener) AcceptTCP() (transport.TCPConn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, fmt.Errorf("accept tcp: %w", err)
	}
	return conn, nil
}

func udpAddrString(a *net.UDPAddr) string {
	if a == nil {
		return ":0"
	}
	return a.String()
}

func tcpAddrString(a *net.TCPAddr) string {
	if a == nil {
		return ":0"
	}
	return a.String()
}

// Compile-time assertion that ProtectedNet satisfies Pion's Net.
var _ transport.Net = (*ProtectedNet)(nil)

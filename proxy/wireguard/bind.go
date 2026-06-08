package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"golang.zx2c4.com/wireguard/conn"
)

type bind struct {
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func() (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	net.PacketConn
	closeCh chan struct{}
	mu      sync.Mutex
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.PacketConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	b.PacketConn = c
	ch := make(chan struct{})
	b.closeCh = ch

	return []conn.ReceiveFunc{
		func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			for {
				n, addr, err := c.ReadFrom(bufs[0])
				if err != nil {
					if goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
						select {
						case <-ch:
						default:
							errors.LogErrorInner(context.Background(), err, "unexpected closed")
							if b.downFunc != nil {
								go func() {
									err = b.downFunc()
									if err != nil {
										errors.LogErrorInner(context.Background(), err, "down err")
									}
								}()
							}
						}
						return 0, net.ErrClosed
					}
					errors.LogErrorInner(context.Background(), err, "bind recv err")
					continue
				}
				if n > 3 {
					bufs[0][1] = 0
					bufs[0][2] = 0
					bufs[0][3] = 0
				}
				sizes[0] = n
				eps[0] = &conn.StdNetEndpoint{AddrPort: addr.(*net.UDPAddr).AddrPort()}
				return 1, nil
			}
		},
	}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		_ = b.PacketConn.Close()
		close(b.closeCh)
		b.PacketConn = nil
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.PacketConn
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	if len(bufs[0]) > 3 && len(b.reserved) == 3 {
		bufs[0][1] = b.reserved[0]
		bufs[0][2] = b.reserved[1]
		bufs[0][3] = b.reserved[2]
	}

	_, err := c.WriteTo(bufs[0], net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort))
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "bind send err")
	}
	return err
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.resolveFunc == nil {
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		return &conn.StdNetEndpoint{
			AddrPort: e,
		}, nil
	}
	host, sport, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port " + sport)
	}
	ip, err := b.resolveFunc(host)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.AddrFromSlice(ip)
	return &conn.StdNetEndpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
	}, nil
}

func (b *bind) BatchSize() int {
	return 1
}

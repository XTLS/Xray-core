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

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"golang.zx2c4.com/wireguard/conn"
)

type bind struct {
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func() (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	net.PacketConn
	// gso is the socket under PacketConn when it takes UDP_SEGMENT. Sends
	// through it bypass PacketCounterConnection, so they count to writeCounter.
	gso          msgWriter
	writeCounter stats.Counter
	closeCh      chan struct{}
	mu           sync.Mutex
}

type msgWriter interface {
	WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error)
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
	b.gso, b.writeCounter = gsoConn(c)
	ch := make(chan struct{})
	b.closeCh = ch

	return []conn.ReceiveFunc{
		func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			for {
				n, addr, err := c.ReadFrom(bufs[0])
				if err != nil {
					if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
						select {
						case <-ch:
						default:
							errors.LogErrorInner(context.Background(), err, "unexpected closed")
							b.mu.Lock()
							downFunc := b.downFunc
							b.mu.Unlock()
							if downFunc != nil {
								go func() {
									common.Must(downFunc())
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

// setDownFunc sets downFunc after the device is created, since the device may already be using the bind.
func (b *bind) setDownFunc(f func() error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.downFunc = f
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		close(b.closeCh)
		_ = b.PacketConn.Close()
		b.PacketConn = nil
		b.gso = nil
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	b.mu.Lock()
	c, gso, wc := b.PacketConn, b.gso, b.writeCounter
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	for i := range bufs {
		if len(bufs[i]) > 3 && len(b.reserved) == 3 {
			bufs[i][1] = b.reserved[0]
			bufs[i][2] = b.reserved[1]
			bufs[i][3] = b.reserved[2]
		}
	}
	if gso != nil && len(bufs) > 1 {
		var sent int
		sent, err = sendGSO(gso, bufs, ep.(*conn.StdNetEndpoint).AddrPort, wc)
		if err == nil || !gsoFailed(err) {
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "bind send err")
			}
			return err
		}
		// The route does not take UDP_SEGMENT, e.g. no checksum offload or a
		// path MTU below the datagram size. Send one by one from now on.
		errors.LogInfoInner(context.Background(), err, "bind: UDP GSO disabled")
		b.mu.Lock()
		if b.gso == gso {
			b.gso = nil
		}
		b.mu.Unlock()
		bufs = bufs[sent:]
	}
	for i := range bufs {
		_, err = c.WriteTo(bufs[i], net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort))
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
			break
		}
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

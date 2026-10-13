package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

type bind struct {
	resolveFunc  func(host string) (net.IP, error)
	listenFunc   func() (net.PacketConn, error)
	downFunc     func() error
	reserved     []byte
	readCounter  stats.Counter
	writeCounter stats.Counter

	socket  atomic.Pointer[bindSocket]
	closeCh chan struct{}
	mu      sync.Mutex
}

type bindSocket struct {
	c     net.PacketConn
	udp   *net.UDPConn
	batch interface {
		ReadBatch([]ipv4.Message, int) (int, error)
		WriteBatch([]ipv4.Message, int) (int, error)
	}
}

type bindMessages struct {
	messages [conn.IdealBatchSize]ipv4.Message
	buffers  [conn.IdealBatchSize][1][]byte
	addr     net.UDPAddr
	ip       [16]byte
}

var bindMessagePool = sync.Pool{New: func() any {
	m := new(bindMessages)
	for i := range m.messages {
		m.messages[i].Buffers = m.buffers[i][:]
	}
	return m
}}

func (m *bindMessages) release() {
	for i := range m.messages {
		m.buffers[i][0] = nil
		m.messages[i].Addr = nil
	}
	bindMessagePool.Put(m)
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket.Load() != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	s := &bindSocket{c: c}
	if udp, ok := c.(*net.UDPConn); ok {
		s.udp = udp
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			if udp.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
				s.batch = ipv4.NewPacketConn(udp)
			} else {
				s.batch = ipv6.NewPacketConn(udp)
			}
		}
	}
	b.socket.Store(s)
	ch := make(chan struct{})
	b.closeCh = ch
	return []conn.ReceiveFunc{
		func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			for {
				n, err := s.receive(bufs, sizes, eps)
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
								go func() { common.Must(downFunc()) }()
							}
						}
						return 0, net.ErrClosed
					}
					errors.LogErrorInner(context.Background(), err, "bind recv err")
					continue
				}
				total := 0
				for i := range n {
					if sizes[i] > 3 {
						bufs[i][1], bufs[i][2], bufs[i][3] = 0, 0, 0
					}
					total += sizes[i]
				}
				if b.readCounter != nil {
					b.readCounter.Add(int64(total))
				}
				return n, nil
			}
		},
	}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (s *bindSocket) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if s.batch != nil {
		m := bindMessagePool.Get().(*bindMessages)
		defer m.release()
		count := min(len(bufs), conn.IdealBatchSize)
		for i := range count {
			m.buffers[i][0] = bufs[i]
		}
		n, err := s.batch.ReadBatch(m.messages[:count], 0)
		for i := range n {
			sizes[i] = m.messages[i].N
			eps[i] = &conn.StdNetEndpoint{AddrPort: m.messages[i].Addr.(*net.UDPAddr).AddrPort()}
		}
		return n, err
	}
	var n int
	var addr netip.AddrPort
	var err error
	if s.udp != nil {
		n, addr, err = s.udp.ReadFromUDPAddrPort(bufs[0])
	} else {
		var rawAddr net.Addr
		n, rawAddr, err = s.c.ReadFrom(bufs[0])
		if err == nil {
			addr = rawAddr.(*net.UDPAddr).AddrPort()
		}
	}
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
	return 1, nil
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
	if s := b.socket.Swap(nil); s != nil {
		close(b.closeCh)
		_ = s.c.Close()
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	s := b.socket.Load()
	if s == nil {
		return syscall.EAFNOSUPPORT
	}
	for _, buf := range bufs {
		if len(buf) > 3 && len(b.reserved) == 3 {
			buf[1], buf[2], buf[3] = b.reserved[0], b.reserved[1], b.reserved[2]
		}
	}
	addr := ep.(*conn.StdNetEndpoint).AddrPort
	total := 0
	defer func() {
		if b.writeCounter != nil {
			b.writeCounter.Add(int64(total))
		}
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
		}
	}()
	if s.batch != nil {
		m := bindMessagePool.Get().(*bindMessages)
		defer m.release()
		m.ip = addr.Addr().As16()
		m.addr = net.UDPAddr{IP: m.ip[:], Port: int(addr.Port()), Zone: addr.Addr().Zone()}
		if addr.Addr().Is4() {
			m.addr.IP = m.ip[12:]
		}
		for len(bufs) > 0 {
			count := min(len(bufs), conn.IdealBatchSize)
			for i := range count {
				m.buffers[i][0] = bufs[i]
				m.messages[i].Addr = &m.addr
			}
			n, writeErr := s.batch.WriteBatch(m.messages[:count], 0)
			for _, buf := range bufs[:n] {
				total += len(buf)
			}
			bufs = bufs[n:]
			if writeErr != nil {
				return writeErr
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		return nil
	}
	var rawAddr *net.UDPAddr
	if s.udp == nil {
		rawAddr = net.UDPAddrFromAddrPort(addr)
	}
	for _, buf := range bufs {
		var n int
		if s.udp != nil {
			n, err = s.udp.WriteToUDPAddrPort(buf, addr)
		} else {
			n, err = s.c.WriteTo(buf, rawAddr)
		}
		if err != nil {
			return err
		}
		total += n
	}
	return nil
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
	return conn.IdealBatchSize
}

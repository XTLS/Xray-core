package udphop

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	mrand "math/rand"
	gonet "net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

type udpHopConn struct {
	conn    net.PacketConn
	sockopt *internet.SocketConfig

	ips         []netip.Prefix
	ports       []uint32
	intervalMin int64
	intervalMax int64

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	pre     net.PacketConn
	cur     net.PacketConn
	addr    *net.UDPAddr
	readCh  chan packet
	closeCh chan struct{}
	mu      sync.Mutex
}

func NewUDPHopConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	ips := make([]netip.Prefix, 0, len(c.IPs))
	for _, ip := range c.IPs {
		prefix, err := netip.ParsePrefix(ip)
		if err == nil {
			ips = append(ips, prefix)
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			ips = append(ips, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, errors.New("invalid ips")
	}
	if len(c.Ports) == 0 {
		return nil, errors.New("empty ports")
	}
	if c.IntervalMin < 5 || c.IntervalMax < 5 {
		return nil, errors.New("invalid interval")
	}
	conn := &udpHopConn{
		conn:    raw,
		sockopt: c.Sockopt,

		ips:         ips,
		ports:       c.Ports,
		intervalMin: c.IntervalMin,
		intervalMax: c.IntervalMax,

		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}
	return conn, nil
}

func (c *udpHopConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *udpHopConn) hop() {
	if c.closed() {
		return
	}
	var addr *net.UDPAddr
	switch {
	case len(c.ips) > 0:
		addr = &net.UDPAddr{
			IP:   randPrefix(c.ips[mrand.Intn(len(c.ips))]),
			Port: int(c.ports[mrand.Intn(len(c.ports))]),
		}
	case c.addr != nil:
		addr = &net.UDPAddr{
			IP:   c.addr.IP,
			Port: int(c.ports[mrand.Intn(len(c.ports))]),
		}
	default:
		return
	}
	var pkt net.PacketConn
	raw, err := internet.DialSystem(context.Background(), net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), c.sockopt)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "hop err")
		return
	}
	switch c := raw.(type) {
	case *internet.PacketConnWrapper:
		pkt = c.PacketConn
	case *cnc.Connection:
		pkt = &internet.FakePacketConn{Conn: c}
	default:
		panic(reflect.TypeOf(c))
	}
	pkt.SetDeadline(c.deadline)
	pkt.SetReadDeadline(c.readDeadline)
	pkt.SetWriteDeadline(c.writeDeadline)
	if c.pre != nil {
		_ = c.pre.Close()
	}
	c.pre = c.cur
	c.cur = pkt
	c.addr = addr
	go c.recv(pkt)
}

func (c *udpHopConn) recv(conn net.PacketConn) {
	for {
		if c.closed() {
			break
		}
		p := pool.Get().([]byte)
		n, addr, err := conn.ReadFrom(p)
		if err != nil {
			pool.Put(p[:cap(p)])
			if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, gonet.ErrClosed) {
				break
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					goto exit
				}
			}
			errors.LogErrorInner(context.Background(), err, "recv err")
			continue
		}
		select {
		case c.readCh <- packet{p: p[:n], addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			goto exit
		}
	}
exit:
	if c.closed() {
		select {
		case packet := <-c.readCh:
			if packet.p != nil {
				pool.Put(packet.p[:cap(packet.p)])
			}
		default:
		}
	}
}

func (c *udpHopConn) hopLoop() {
	ticker := time.NewTicker(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ticker.Reset(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
			c.mu.Lock()
			c.hop()
			c.mu.Unlock()
		case <-c.closeCh:
			return
		}
	}
}

func (c *udpHopConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.readCh:
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	case <-c.closeCh:
		return 0, nil, io.EOF
	}
}

func (c *udpHopConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.addr == nil {
		c.addr = &net.UDPAddr{
			IP:   addr.(*net.UDPAddr).IP,
			Port: addr.(*net.UDPAddr).Port,
		}
	}

	if c.cur == nil {
		c.hop()
		if c.cur == nil {
			return 0, nil
		}
		go c.hopLoop()
	}

	_, err = c.cur.WriteTo(p, c.addr)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
		return 0, nil
	}
	return len(p), nil
}

func (c *udpHopConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	if c.pre != nil {
		_ = c.pre.Close()
	}
	if c.cur != nil {
		_ = c.cur.Close()
	}
	_ = c.conn.Close()
	return nil
}

func (c *udpHopConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *udpHopConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	if c.pre != nil {
		_ = c.pre.SetDeadline(t)
	}
	if c.cur != nil {
		_ = c.cur.SetDeadline(t)
	}
	return nil
}

func (c *udpHopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.pre != nil {
		_ = c.pre.SetReadDeadline(t)
	}
	if c.cur != nil {
		_ = c.cur.SetReadDeadline(t)
	}
	return nil
}

func (c *udpHopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.pre != nil {
		_ = c.pre.SetWriteDeadline(t)
	}
	if c.cur != nil {
		_ = c.cur.SetWriteDeadline(t)
	}
	return nil
}

func randPrefix(p netip.Prefix) []byte {
	if p.IsSingleIP() {
		return p.Addr().AsSlice()
	}
	b := p.Addr().AsSlice()
	prefix := p.Bits()
	var new [16]byte
	common.Must2(rand.Read(new[:len(b)]))
	i := prefix / 8
	j := prefix % 8
	if i+1 < len(b) {
		copy(b[i+1:], new[i+1:])
	}
	mask := byte(0xff << (8 - j))
	b[i] = (b[i] & mask) | (new[i] &^ mask)
	return b
}

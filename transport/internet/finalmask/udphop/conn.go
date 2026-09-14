package udphop

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	mrand "math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
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
	dialer *finalmask.Dialer
	local  bool
	remote bool

	intervalMin int64
	intervalMax int64
	remoteIPs   []netip.Prefix
	remotePorts []uint32

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	pre     net.PacketConn
	cur     net.PacketConn
	addr    *net.UDPAddr
	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewUDPHopConn(c *Config, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if c.IntervalMin < 5 || c.IntervalMax < 5 {
		return nil, errors.New("invalid interval")
	}
	remoteIPs := make([]netip.Prefix, 0, len(c.RemoteIPs))
	for _, ip := range c.RemoteIPs {
		remoteIPs = append(remoteIPs, netip.MustParsePrefix(ip))
	}
	remotePorts := c.RemotePorts
	if c.Remote || c.RemoteOnce {
		if len(remoteIPs) > 0 {
			dest.Address = net.IPAddress(randPrefix(remoteIPs[mrand.Intn(len(remoteIPs))]))
		}
		if len(remotePorts) > 0 {
			dest.Port = net.Port(remotePorts[mrand.Intn(len(remotePorts))])
		}
	}
	conn, err := dialer.DialUDP(*dest)
	if err != nil {
		return nil, err
	}
	cur := conn.(*finalmask.PacketConnWrapper).PacketConn
	addr := conn.RemoteAddr().(*net.UDPAddr)
	client := &udpHopConn{
		dialer: dialer,
		local:  c.Local,
		remote: c.Remote,

		intervalMin: c.IntervalMin,
		intervalMax: c.IntervalMax,
		remoteIPs:   remoteIPs,
		remotePorts: remotePorts,

		cur:     cur,
		addr:    addr,
		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}
	go client.run()
	client.wg.Add(1)
	go client.recv(client.cur)
	return client, nil
}

func (c *udpHopConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *udpHopConn) run() {
	ticker := time.NewTicker(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			ticker.Reset(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
			c.hop()
		}
	}
}

func (c *udpHopConn) hop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return
	}
	oldIP := c.addr.IP
	oldPort := c.addr.Port
	if c.remote {
		if len(c.remoteIPs) > 0 {
			c.addr.IP = randPrefix(c.remoteIPs[mrand.Intn(len(c.remoteIPs))])
		}
		if len(c.remotePorts) > 0 {
			c.addr.Port = int(c.remotePorts[mrand.Intn(len(c.remotePorts))])
		}
	}
	if c.local {
		conn, err := c.dialer.DialUDP(net.UDPDestination(net.IPAddress(c.addr.IP), net.Port(c.addr.Port)))
		if err != nil {
			c.addr.IP = oldIP
			c.addr.Port = oldPort
			errors.LogErrorInner(context.Background(), err, "hop err")
			return
		}
		conn.SetDeadline(c.deadline)
		conn.SetReadDeadline(c.readDeadline)
		conn.SetWriteDeadline(c.writeDeadline)
		if c.pre != nil {
			_ = c.pre.Close()
		}
		c.pre = c.cur
		c.cur = conn.(*finalmask.PacketConnWrapper).PacketConn
		c.wg.Add(1)
		go c.recv(c.cur)
	}
}

func (c *udpHopConn) recv(conn net.PacketConn) {
	defer c.wg.Done()

	for {
		p := pool.Get().([]byte)
		n, addr, err := conn.ReadFrom(p)
		if err != nil {
			pool.Put(p[:cap(p)])
			if c.closed() {
				return
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					return
				}
				continue
			}
			errors.LogErrorInner(context.Background(), err, "recv err")
			return
		}
		select {
		case c.readCh <- packet{p: p[:n], addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			return
		}
	}
}

func (c *udpHopConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *udpHopConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err = c.cur.WriteTo(p, c.addr)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
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
	c.wg.Wait()
	select {
	case packet := <-c.readCh:
		if packet.p != nil {
			pool.Put(packet.p[:cap(packet.p)])
		}
	default:
	}
	close(c.readCh)
	return nil
}

func (c *udpHopConn) LocalAddr() net.Addr {
	return c.cur.LocalAddr()
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

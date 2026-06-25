//go:build !linux

package xicmp

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func clientIDToAddr(clientID [8]byte) *net.UDPAddr {
	ip := make(net.IP, 16)

	ip[0] = 0xfd
	ip[1] = 0x00

	copy(ip[8:], clientID[:])

	return &net.UDPAddr{IP: ip}
}

type record struct {
	id   int
	seq  int
	addr net.Addr
	last time.Time
}

type xicmpConnServer struct {
	conn    net.PacketConn
	icmp4   *icmp.PacketConn
	icmp6   *icmp.PacketConn
	ips     map[netip.Addr]struct{}
	rec     map[string]record
	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	icmp4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	icmp6, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}

	ips := make(map[netip.Addr]struct{})
	for _, ip := range c.IPs {
		ips[netip.MustParseAddr(ip)] = struct{}{}
	}

	conn := &xicmpConnServer{
		conn:    raw,
		icmp4:   icmp4,
		icmp6:   icmp6,
		ips:     ips,
		rec:     make(map[string]record),
		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}

	go conn.clean()
	conn.wg.Add(2)
	go conn.recv4()
	go conn.recv6()

	return conn, nil
}

func (c *xicmpConnServer) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *xicmpConnServer) clean() {
	ticker := time.NewTicker(time.Minute / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for key, r := range c.rec {
				if now.Sub(r.last) > time.Minute {
					delete(c.rec, key)
				}
			}
			c.mu.Unlock()
		case <-c.closeCh:
			return
		}
	}
}

func (c *xicmpConnServer) recv4() {
	defer c.wg.Done()

	var b [finalmask.UDPSize]byte
	for {
		if c.closed() {
			return
		}

		n, addr, err := c.icmp4.ReadFrom(b[:])
		if err != nil {
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{
					err: err,
				}:
				case <-c.closeCh:
					return
				}
			} else {
				errors.LogErrorInner(context.Background(), err, "recv4 err")
			}
			continue
		}

		msg, err := icmp.ParseMessage(1, b[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if len(echo.Data) <= 8 {
			continue
		}

		if len(c.ips) > 0 {
			netipAddr, ok := netip.AddrFromSlice(addr.(*net.IPAddr).IP)
			if !ok {
				continue
			}

			if _, ok := c.ips[netipAddr]; !ok {
				continue
			}
		}

		cAddr := clientIDToAddr([8]byte(echo.Data[:8]))

		c.mu.Lock()
		c.rec[cAddr.String()] = record{
			id:   echo.ID,
			seq:  echo.Seq,
			addr: addr,
			last: time.Now(),
		}
		c.mu.Unlock()

		p := pool.Get().([]byte)[:len(echo.Data[8:])]
		copy(p, echo.Data[8:])

		select {
		case c.readCh <- packet{
			p:    p,
			addr: cAddr,
		}:
		case <-c.closeCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnServer) recv6() {
	defer c.wg.Done()

	var b [finalmask.UDPSize]byte
	for {
		if c.closed() {
			return
		}

		n, addr, err := c.icmp6.ReadFrom(b[:])
		if err != nil {
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{
					err: err,
				}:
				case <-c.closeCh:
					return
				}
			} else {
				errors.LogErrorInner(context.Background(), err, "recv6 err")
			}
			continue
		}

		msg, err := icmp.ParseMessage(58, b[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv6.ICMPTypeEchoRequest {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if len(echo.Data) <= 8 {
			continue
		}

		if len(c.ips) > 0 {
			netipAddr, ok := netip.AddrFromSlice(addr.(*net.IPAddr).IP)
			if !ok {
				continue
			}

			if _, ok := c.ips[netipAddr]; !ok {
				continue
			}
		}

		cAddr := clientIDToAddr([8]byte(echo.Data[:8]))

		c.mu.Lock()
		c.rec[cAddr.String()] = record{
			id:   echo.ID,
			seq:  echo.Seq,
			addr: addr,
			last: time.Now(),
		}
		c.mu.Unlock()

		p := pool.Get().([]byte)[:len(echo.Data[8:])]
		copy(p, echo.Data[8:])

		select {
		case c.readCh <- packet{
			p:    p,
			addr: cAddr,
		}:
		case <-c.closeCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p)
		}
		return n, packet.addr, packet.err
	}
	return 0, nil, io.EOF
}

func (c *xicmpConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p)+8 > finalmask.UDPSize {
		errors.LogError(context.Background(), "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	c.mu.Lock()
	r, ok := c.rec[addr.String()]
	if !ok {
		errors.LogError(context.Background(), "drop packet to ", addr, " with size ", len(p))
		c.mu.Unlock()
		return 0, nil
	}
	r.last = time.Now()
	c.rec[addr.String()] = r
	c.mu.Unlock()

	// errors.LogDebug(context.Background(), "id ", r.id, " seq ", r.seq, " addr ", r.addr)

	b := pool.Get().([]byte)[:finalmask.UDPSize]
	defer pool.Put(b)

	copy(b[8:], p)

	if r.addr.(*net.IPAddr).IP.To4() != nil {
		b = marshal(b, ipv4.ICMPTypeEchoReply, r.id, r.seq, len(p))
		_, err = c.icmp4.WriteTo(b, r.addr)
	} else {
		b = marshal(b, ipv6.ICMPTypeEchoReply, r.id, r.seq, len(p))
		_, err = c.icmp6.WriteTo(b, r.addr)
	}

	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
		return 0, err
	}
	return len(p), nil
}

func (c *xicmpConnServer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	_ = c.icmp4.Close()
	_ = c.icmp6.Close()
	_ = c.conn.Close()
	c.wg.Wait()
	select {
	case p := <-c.readCh:
		if p.p != nil {
			pool.Put(p.p)
		}
	default:
	}
	close(c.readCh)
	return nil
}

func (c *xicmpConnServer) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *xicmpConnServer) SetDeadline(t time.Time) error {
	_ = c.icmp4.SetDeadline(t)
	_ = c.icmp6.SetDeadline(t)
	return nil
}

func (c *xicmpConnServer) SetReadDeadline(t time.Time) error {
	_ = c.icmp4.SetReadDeadline(t)
	_ = c.icmp6.SetReadDeadline(t)
	return nil
}

func (c *xicmpConnServer) SetWriteDeadline(t time.Time) error {
	_ = c.icmp4.SetWriteDeadline(t)
	_ = c.icmp6.SetWriteDeadline(t)
	return nil
}

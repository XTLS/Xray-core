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
	conn     net.PacketConn
	icmp4    *icmp.PacketConn
	icmp6    *icmp.PacketConn
	ips      map[netip.Addr]struct{}
	rec      map[string]record
	readCh   chan packet
	closedCh chan struct{}
	mu       sync.Mutex
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
		conn:     raw,
		icmp4:    icmp4,
		icmp6:    icmp6,
		ips:      ips,
		rec:      make(map[string]record),
		readCh:   make(chan packet),
		closedCh: make(chan struct{}),
	}

	go conn.clean()
	go conn.recv4()
	go conn.recv6()

	return conn, nil
}

func (c *xicmpConnServer) closed() bool {
	select {
	case <-c.closedCh:
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
		case <-c.closedCh:
			return
		}
	}
}

func (c *xicmpConnServer) recv4() {
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
				case <-c.closedCh:
					return
				}
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

		p := make([]byte, len(echo.Data[8:]))
		copy(p, echo.Data[8:])

		select {
		case c.readCh <- packet{
			p:    p,
			addr: cAddr,
		}:
		case <-c.closedCh:
			return
		}
	}
}

func (c *xicmpConnServer) recv6() {
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
				case <-c.closedCh:
					return
				}
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

		p := make([]byte, len(echo.Data[8:]))
		copy(p, echo.Data[8:])

		select {
		case c.readCh <- packet{
			p:    p,
			addr: cAddr,
		}:
		case <-c.closedCh:
			return
		}
	}
}

func (c *xicmpConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.readCh:
		return copy(p, packet.p), packet.addr, packet.err
	case <-c.closedCh:
		return 0, nil, io.EOF
	}
}

func (c *xicmpConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p)+16 > finalmask.UDPSize {
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

	typ := icmp.Type(ipv6.ICMPTypeEchoReply)
	if r.addr.(*net.IPAddr).IP.To4() != nil {
		typ = ipv4.ICMPTypeEchoReply
	}

	msg := icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   r.id,
			Seq:  r.seq,
			Data: p,
		},
	}

	buf, err := msg.Marshal(nil)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	if r.addr.(*net.IPAddr).IP.To4() != nil {
		_, err = c.icmp4.WriteTo(buf, r.addr)

	} else {
		_, err = c.icmp6.WriteTo(buf, r.addr)
	}

	if err != nil {
		errors.LogErrorInner(context.Background(), err, "xicmp write")
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
	close(c.closedCh)
	_ = c.icmp4.Close()
	_ = c.icmp6.Close()
	_ = c.conn.Close()
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

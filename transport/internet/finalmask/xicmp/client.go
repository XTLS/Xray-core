package xicmp

import (
	"bytes"
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

type xicmpConnClient struct {
	conn     net.PacketConn
	icmp4    *icmp.PacketConn
	icmp6    *icmp.PacketConn
	udp      bool
	ips      []netip.Addr
	clientID [8]byte
	id       int
	seq      int
	readCh   chan packet
	closedCh chan struct{}
	mu       sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	var icmp4, icmp6 *icmp.PacketConn
	var err4, err6 error
	if c.DGRAM {
		icmp4, err4 = icmp.ListenPacket("udp4", "0.0.0.0")
		icmp6, err6 = icmp.ListenPacket("udp6", "::")
	} else {
		icmp4, err4 = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		icmp6, err6 = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	if err4 != nil || err6 != nil {
		return nil, errors.Combine(err4, err6)
	}

	ips := make([]netip.Addr, 0, len(c.IPs))
	for _, ip := range c.IPs {
		ips = append(ips, netip.MustParseAddr(ip))
	}

	var clientID [8]byte
	common.Must2(rand.Read(clientID[:]))

	conn := &xicmpConnClient{
		conn:     raw,
		icmp4:    icmp4,
		icmp6:    icmp6,
		udp:      c.DGRAM,
		ips:      ips,
		clientID: clientID,
		id:       mathrand.Intn(65536),
		seq:      1,
		readCh:   make(chan packet),
		closedCh: make(chan struct{}),
	}

	go conn.recv4()
	go conn.recv6()

	return conn, nil
}

func (c *xicmpConnClient) ring(a, b uint16) uint16 {
	return min(a-b, b-a)
}

func (c *xicmpConnClient) closed() bool {
	select {
	case <-c.closedCh:
		return true
	default:
		return false
	}
}

func (c *xicmpConnClient) recv4() {
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

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// errors.LogDebug(context.Background(), "id ", echo.ID, " seq ", echo.Seq, " addr ", addr)

		if !c.udp && echo.ID != c.id {
			continue
		}

		if c.ring(uint16(echo.Seq), uint16(c.seq)) > 1000 {
			continue
		}

		if len(echo.Data) > 8 && bytes.Equal(echo.Data[:8], c.clientID[:]) {
			continue
		}

		p := pool.Get().([]byte)[:len(echo.Data)]
		copy(p, echo.Data)

		if !c.udp {
			addr = &net.UDPAddr{IP: addr.(*net.IPAddr).IP}
		}

		select {
		case c.readCh <- packet{
			p:    p,
			addr: addr,
		}:
		case <-c.closedCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) recv6() {
	var b [finalmask.UDPSize]byte

	for {
		if c.closed() {
			break
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

		if msg.Type != ipv6.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// errors.LogDebug(context.Background(), "id ", echo.ID, " seq ", echo.Seq, " addr ", addr)

		if !c.udp && echo.ID != c.id {
			continue
		}

		if c.ring(uint16(echo.Seq), uint16(c.seq)) > 1000 {
			continue
		}

		if len(echo.Data) > 8 && bytes.Equal(echo.Data[:8], c.clientID[:]) {
			continue
		}

		p := pool.Get().([]byte)[:len(echo.Data)]
		copy(p, echo.Data)

		if !c.udp {
			addr = &net.UDPAddr{IP: addr.(*net.IPAddr).IP}
		}

		select {
		case c.readCh <- packet{
			p:    p,
			addr: addr,
		}:
		case <-c.closedCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.readCh:
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p)
		}
		return n, packet.addr, packet.err
	case <-c.closedCh:
		return 0, nil, io.EOF
	}
}

func (c *xicmpConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p)+16 > finalmask.UDPSize {
		errors.LogError(context.Background(), "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	b := pool.Get().([]byte)[:finalmask.UDPSize]
	defer pool.Put(b)

	copy(b, c.clientID[:])
	copy(b[8:], p)

	ip := addr.(*net.UDPAddr).IP
	if len(c.ips) > 0 {
		ip = c.ips[mathrand.Intn(len(c.ips))].AsSlice()
	}

	typ := icmp.Type(ipv6.ICMPTypeEchoRequest)
	if ip.To4() != nil {
		typ = ipv4.ICMPTypeEcho
	}

	c.mu.Lock()
	seq := c.seq
	c.seq += 1
	c.seq %= 65536
	c.mu.Unlock()

	msg := icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   c.id,
			Seq:  seq,
			Data: b[:8+len(p)],
		},
	}

	buf, err := msg.Marshal(nil)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	if c.udp {
		addr = &net.UDPAddr{IP: ip}
	} else {
		addr = &net.IPAddr{IP: ip}
	}

	if ip.To4() != nil {
		_, err = c.icmp4.WriteTo(buf, addr)

	} else {
		_, err = c.icmp6.WriteTo(buf, addr)
	}

	if err != nil {
		errors.LogErrorInner(context.Background(), err, "xicmp write")
		return 0, err
	}

	return len(p), nil
}

func (c *xicmpConnClient) Close() error {
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

func (c *xicmpConnClient) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *xicmpConnClient) SetDeadline(t time.Time) error {
	_ = c.icmp4.SetDeadline(t)
	_ = c.icmp6.SetDeadline(t)
	return nil
}

func (c *xicmpConnClient) SetReadDeadline(t time.Time) error {
	_ = c.icmp4.SetReadDeadline(t)
	_ = c.icmp6.SetReadDeadline(t)
	return nil
}

func (c *xicmpConnClient) SetWriteDeadline(t time.Time) error {
	_ = c.icmp4.SetWriteDeadline(t)
	_ = c.icmp6.SetWriteDeadline(t)
	return nil
}

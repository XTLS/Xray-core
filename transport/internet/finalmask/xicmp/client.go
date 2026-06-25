package xicmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"time"
	_ "unsafe"

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
	closeCh  chan struct{}
	wg       sync.WaitGroup
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
		closeCh:  make(chan struct{}),
	}

	conn.wg.Add(2)
	go conn.recv4()
	go conn.recv6()

	return conn, nil
}

func (c *xicmpConnClient) ring(a, b uint16) uint16 {
	return min(a-b, b-a)
}

func (c *xicmpConnClient) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *xicmpConnClient) recv4() {
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
		case <-c.closeCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) recv6() {
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
		case <-c.closeCh:
			pool.Put(p)
			return
		}
	}
}

func (c *xicmpConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *xicmpConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p)+16 > finalmask.UDPSize {
		errors.LogError(context.Background(), "drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	c.mu.Lock()
	seq := c.seq
	c.seq += 1
	c.seq %= 65536
	c.mu.Unlock()

	ip := addr.(*net.UDPAddr).IP
	if len(c.ips) > 0 {
		ip = c.ips[mathrand.Intn(len(c.ips))].AsSlice()
	}

	if c.udp {
		addr = &net.UDPAddr{IP: ip}
	} else {
		addr = &net.IPAddr{IP: ip}
	}

	b := pool.Get().([]byte)[:finalmask.UDPSize]
	defer pool.Put(b)

	copy(b[8:], c.clientID[:])
	copy(b[16:], p)

	if ip.To4() != nil {
		b = marshal(b, ipv4.ICMPTypeEcho, c.id, seq, 8+len(p))
		_, err = c.icmp4.WriteTo(b, addr)
	} else {
		b = marshal(b, ipv6.ICMPTypeEchoRequest, c.id, seq, 8+len(p))
		_, err = c.icmp6.WriteTo(b, addr)
	}

	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
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

//go:linkname checksum golang.org/x/net/icmp.checksum
func checksum(b []byte) uint16

func marshal(b []byte, typ icmp.Type, id, seq int, dataLen int) []byte {
	is4 := false
	switch typ := typ.(type) {
	case ipv4.ICMPType:
		is4 = true
		b[0] = byte(typ)
	case ipv6.ICMPType:
		b[0] = byte(typ)
	default:
		panic(fmt.Sprintf("%T %v", typ, typ))
	}
	clear(b[1:4])
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	if is4 {
		s := checksum(b[:8+dataLen])
		b[2] ^= byte(s)
		b[3] ^= byte(s >> 8)
	}
	return b[:8+dataLen]
}

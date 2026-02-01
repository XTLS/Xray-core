package xicmp

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

type packet struct {
	p    []byte
	addr net.Addr
}

type xicmpConnClient struct {
	conn     net.PacketConn
	icmpConn *icmp.PacketConn

	typ   icmp.Type
	id    uint16
	seq   uint16
	proto int

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	closed bool
	mutex  sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("xicmp requires being at the outermost level")
	}

	network := "ip4:icmp"
	typ := icmp.Type(ipv4.ICMPTypeEcho)
	proto := 1
	if strings.Contains(c.Ip, ":") {
		network = "ip6:ipv6-icmp"
		typ = ipv6.ICMPTypeEchoRequest
		proto = 58
	}

	icmpConn, err := icmp.ListenPacket(network, c.Ip)
	if err != nil {
		return nil, errors.New("xicmp listen err").Base(err)
	}

	id := uint16(c.Id)
	if id == 0 {
		id = uint16(rand.Int())
	}

	conn := &xicmpConnClient{
		conn:     raw,
		icmpConn: icmpConn,

		typ:   typ,
		id:    id,
		seq:   1,
		proto: proto,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 128),
		writeQueue: make(chan *packet, 128),
	}

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xicmpConnClient) encode(p []byte) ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	msg := icmp.Message{
		Type: c.typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(c.id),
			Seq:  int(c.seq),
			Data: p,
		},
	}

	buf, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	if len(buf) > 8192 {
		return nil, errors.New("xicmp len(buf) > 8192")
	}

	c.seq++

	return buf, nil
}

func (c *xicmpConnClient) recvLoop() {
	seqMap := make(map[int]struct{})

	for {
		if c.closed {
			break
		}

		var buf [8192]byte

		n, addr, err := c.icmpConn.ReadFrom(buf[:])
		if err != nil {
			continue
		}

		msg, err := icmp.ParseMessage(c.proto, buf[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply && msg.Type != ipv6.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if _, ok := seqMap[echo.Seq]; ok {
			continue
		}

		if len(echo.Data) > 2 {
			if binary.BigEndian.Uint16(echo.Data) == c.id {
				seqMap[echo.Seq] = struct{}{}

				buf := make([]byte, len(echo.Data)-2)
				copy(buf, echo.Data[2:])
				select {
				case c.readQueue <- &packet{
					p:    buf,
					addr: &net.UDPAddr{IP: addr.(*net.IPAddr).IP},
				}:
				default:
				}

				select {
				case c.pollChan <- struct{}{}:
				default:
				}
			}
		}
	}

	close(c.pollChan)
	close(c.readQueue)
}

func (c *xicmpConnClient) sendLoop() {
	var addr net.Addr

	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p *packet
		pollTimerExpired := false

		select {
		case p = <-c.writeQueue:
		default:
			select {
			case p = <-c.writeQueue:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if p != nil {
			addr = p.addr

			select {
			case <-c.pollChan:
			default:
			}
		} else if addr != nil {
			encoded, _ := c.encode(nil)
			p = &packet{
				p:    encoded,
				addr: addr,
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if c.closed {
			return
		}

		if p != nil {
			_, err := c.icmpConn.WriteTo(p.p, p.addr)
			if err != nil {
				errors.LogDebug(context.Background(), "xicmp writeto err ", err)
			}
		}
	}
}

func (c *xicmpConnClient) Size() int32 {
	return 0
}

func (c *xicmpConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readQueue
	if !ok {
		return 0, nil, io.EOF
	}
	n = copy(p, packet.p)
	if n != len(packet.p) {
		return 0, nil, io.ErrShortBuffer
	}
	return n, packet.addr, nil
}

func (c *xicmpConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	encoded, err := c.encode(p)
	if err != nil {
		return 0, errors.New("xicmp encode").Base(err)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return 0, errors.New("xicmp closed")
	}

	select {
	case c.writeQueue <- &packet{
		p:    encoded,
		addr: &net.IPAddr{IP: addr.(*net.UDPAddr).IP},
	}:
		return len(p), nil
	default:
		return 0, errors.New("xicmp queue full")
	}
}

func (c *xicmpConnClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.writeQueue)

	_ = c.icmpConn.Close()
	return c.conn.Close()
}

func (c *xicmpConnClient) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.icmpConn.LocalAddr().(*net.IPAddr).IP}
}

func (c *xicmpConnClient) SetDeadline(t time.Time) error {
	return c.icmpConn.SetDeadline(t)
}

func (c *xicmpConnClient) SetReadDeadline(t time.Time) error {
	return c.icmpConn.SetReadDeadline(t)
}

func (c *xicmpConnClient) SetWriteDeadline(t time.Time) error {
	return c.icmpConn.SetWriteDeadline(t)
}

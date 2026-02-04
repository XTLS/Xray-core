package xicmp

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
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
	windowSize          = 1000
)

type packet struct {
	p    []byte
	addr net.Addr
}

type seqStatus struct {
	needSeqByte bool
	seqByte     byte
}

type xicmpConnClient struct {
	conn     net.PacketConn
	icmpConn *icmp.PacketConn

	typ       icmp.Type
	id        int
	seq       int
	proto     int
	seqStatus map[int]*seqStatus

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

	if c.Id == 0 {
		c.Id = int32(crypto.RandBetween(0, 65535))
	}

	conn := &xicmpConnClient{
		conn:     raw,
		icmpConn: icmpConn,

		typ:       typ,
		id:        int(c.Id),
		seq:       1,
		proto:     proto,
		seqStatus: make(map[int]*seqStatus),

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

	needSeqByte := false
	var seqByte byte
	data := p
	if len(p) > 0 {
		needSeqByte = true
		seqByte = p[0]
	}

	msg := icmp.Message{
		Type: c.typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   c.id,
			Seq:  c.seq,
			Data: data,
		},
	}

	buf, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	if len(buf) > 8192 {
		return nil, errors.New("xicmp len(buf) > 8192")
	}

	c.seqStatus[c.seq] = &seqStatus{
		needSeqByte: needSeqByte,
		seqByte:     seqByte,
	}

	delete(c.seqStatus, int(uint16(c.seq-windowSize)))

	c.seq++

	if c.seq == 65536 {
		delete(c.seqStatus, int(uint16(c.seq-windowSize)))
		c.seq = 1
	}

	return buf, nil
}

func (c *xicmpConnClient) recvLoop() {
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

		c.mutex.Lock()
		seqStatus, ok := c.seqStatus[echo.Seq]
		c.mutex.Unlock()

		if !ok {
			continue
		}

		if seqStatus.needSeqByte {
			if len(echo.Data) <= 1 {
				continue
			}
			if echo.Data[0] == seqStatus.seqByte {
				continue
			}
			echo.Data = echo.Data[1:]
		}

		if len(echo.Data) > 0 {
			c.mutex.Lock()
			delete(c.seqStatus, echo.Seq)
			c.mutex.Unlock()

			buf := make([]byte, len(echo.Data))
			copy(buf, echo.Data)
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
	return &net.UDPAddr{
		IP:   c.icmpConn.LocalAddr().(*net.IPAddr).IP,
		Port: c.id,
	}
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

package xdns

import (
	"context"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var pool4K = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsClient struct {
	dialer *finalmask.Dialer

	clientID ClientID
	fragID   atomic.Uint32
	domains  []*Domain

	resolvers     []Resolver
	resolverSends []atomic.Uint32
	resolverIndex atomic.Uint32

	readCh  chan packet
	sendCh  chan []byte
	poolCh  chan struct{}
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewClient(c *Config, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	if len(c.Resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}
	domains := make([]*Domain, 0, len(c.Domains))
	for i := range c.Domains {
		types := make([]uint16, 0, len(c.Domains[i].Types))
		for j := range c.Domains[i].Types {
			types = append(types, uint16(c.Domains[i].Types[j]))
		}
		domain, err := NewDomain(c.Domains[i].Name, int(c.Domains[i].LenLimit), int(c.Domains[i].LabelLimit), types, uint16(c.Domains[i].Edns0))
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	resolvers := make([]Resolver, 0, len(c.Resolvers))
	for i := range c.Resolvers {
		resolver, err := NewResolver(c.Resolvers[i], dialer)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	client := &xdnsClient{
		dialer: dialer,

		clientID: NewClientID(),
		domains:  domains,

		resolvers:     resolvers,
		resolverSends: make([]atomic.Uint32, len(c.Resolvers)),

		readCh:  make(chan packet),
		sendCh:  make(chan []byte, 16),
		poolCh:  make(chan struct{}, pollLimit),
		closeCh: make(chan struct{}),
	}
	go client.run()
	return client, nil
}

func (c *xdnsClient) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *xdnsClient) read(buf []byte, addr net.Addr) bool {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return false
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		return false
	}

	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	if domain == nil || !domain.HasType(uint16(msg.Questions[0].Type)) {
		return false
	}

	edns0 := uint16(0)
	for i := range msg.Additionals {
		if msg.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			edns0 = uint16(msg.Additionals[i].Header.Class)
			break
		}
	}
	errors.LogDebug(context.Background(), addr, " edns0 ", edns0, " buf ", len(buf), " ", msg.Questions[0].Type)

	resp := NewResp(msg, domain, 0)

	p := pool4K.Get().([]byte)
	n := resp.Decode(p)
	p = p[:n]

	b := p
	var bs [][]byte
	for len(b) > 1 {
		length := int(b[0])<<8 | int(b[1])
		b = b[2:]
		if length > len(b) {
			bs = nil
			break
		}
		packet := make([]byte, length)
		copy(packet, b)
		bs = append(bs, packet)
		if length&0xC000 == 0xC000 {
			break
		}
		b = b[length:]
		if len(b) < 2 {
			bs = nil
		}
	}
	pool4K.Put(p[:cap(p)])

	for i := range bs {
		select {
		case <-c.closeCh:
			return true
		case c.readCh <- packet{p: bs[i], addr: addr}:
		}
	}
	return len(bs) > 0
}

func (c *xdnsClient) run() {
	for i := range len(c.resolvers) {
		c.wg.Add(1)
		go c.recv(i)
	}

	c.wg.Add(1)
	go c.send()

	c.wg.Wait()
	close(c.readCh)
	close(c.sendCh)
	close(c.poolCh)
}

func (c *xdnsClient) recv(i int) {
	defer c.wg.Done()

	var buf [4096]byte
	for {
		n, err := c.resolvers[i].Read(buf[:])
		if err != nil {
			if c.closed() {
				return
			}
			errors.LogErrorInner(context.Background(), err, "recv err ", i)
			return
		}
		if c.read(buf[:n], c.resolvers[i].Addr()) {
			c.resolverSends[i].Store(0)
			select {
			case c.poolCh <- struct{}{}:
			default:
			}
		}
	}
}

func (c *xdnsClient) send() {
	defer c.wg.Done()

	var buf [512]byte
	var data [255]byte

	sendMsg := func(p []byte, domain *Domain, qtype uint16) {
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  domain.Encode(p),
					Type:  dnsmessage.Type(qtype),
					Class: dnsmessage.ClassINET,
				},
			},
		}
		if domain.edns0 > 0 {
			msg.Additionals = []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("."),
						Type:  dnsmessage.TypeOPT,
						Class: dnsmessage.Class(domain.edns0),
						TTL:   0,
					},
					Body: &dnsmessage.OPTResource{},
				},
			}
		}
		pack := common.Must2(msg.AppendPack(buf[:0]))
		common.Must2(rand.Read(pack[:2]))

		index := c.resolverIndex.Load()
		cur := c.resolverSends[index].Add(1)
		i := index
		for {
			i++
			if i == uint32(len(c.resolvers)) {
				i = 0
			}
			if i == index {
				break
			}
			if cur > c.resolverSends[i].Load() {
				break
			}
		}
		c.resolverIndex.Store(i)
		c.resolvers[index].Send(pack)
	}

	send := func(p []byte) {
		domain := c.domains[mrand.Intn(len(c.domains))]
		qtype := domain.types[mrand.Intn(len(domain.types))]

		if len(p) == 0 {
			copy(data[:], c.clientID[:])
			data[0] |= TypeMap[qtype]
			data[8] = 8
			common.Must2(rand.Read(data[9:17]))
			sendMsg(data[:17], domain, qtype)
			return
		}

		if len(p) <= domain.cap-12 {
			copy(data[:], c.clientID[:])
			data[0] |= TypeMap[qtype]
			data[8] = 3
			common.Must2(rand.Read(data[9:12]))
			copy(data[12:], p)
			sendMsg(data[:12+len(p)], domain, qtype)
			return
		}

		if len(p) <= 255*(domain.cap-15) {
			copy(data[:], c.clientID[:])
			data[0] |= TypeMap[qtype]
			data[8] = 3 | 0xC0
			common.Must2(rand.Read(data[9:12]))

			fragID := byte(c.fragID.Add(1))
			fragN := len(p) / (domain.cap - 15)
			if len(p)%(domain.cap-15) > 0 {
				fragN++
			}

			for i := range fragN {
				data[12] = fragID
				data[13] = byte(i)
				data[14] = byte(fragN)
				size := min(len(p), domain.cap-15)
				copy(data[15:], p[:size])
				sendMsg(data[:15+size], domain, qtype)
				p = p[size:]
			}
			return
		}

		errors.LogError(context.Background(), "send err ", len(p))
	}

	ticker := time.NewTicker(initPollDelay)
	defer ticker.Stop()
	delay := initPollDelay
	p := []byte(nil)
	timeout := false
	for {
		select {
		case <-c.closeCh:
			return
		default:
			select {
			case <-c.closeCh:
				return
			case p = <-c.sendCh:
			case <-c.poolCh:
			case <-ticker.C:
				timeout = true
			}
		}

		if len(p) > 0 {
			select {
			case <-c.poolCh:
			default:
			}
		}

		send(p)

		if timeout {
			delay *= pollDelayMultiplier
			if delay > maxPollDelay {
				delay = maxPollDelay
			}
			timeout = false
		} else {
			delay = initPollDelay
		}
		ticker.Reset(delay)
	}
}

func (c *xdnsClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		return copy(p, packet.p), packet.addr, nil
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *xdnsClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) > 4096 {
		errors.LogError(context.Background(), "err size ", len(p))
		return 0, errors.New("err size")
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.sendCh <- b:
	default:
	}
	return len(p), nil
}

func (c *xdnsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	for i := range c.resolvers {
		c.resolvers[i].Close()
	}
	return nil
}

func (c *xdnsClient) LocalAddr() net.Addr { return &net.UDPAddr{IP: []byte{0, 0, 0, 0}} }

func (c *xdnsClient) SetDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsClient) SetReadDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsClient) SetWriteDeadline(t time.Time) error { return errors.New("not support") }

type ClientID [8]byte

func NewClientID() ClientID {
	var id ClientID
	common.Must2(rand.Read(id[:]))
	id[0] &= 0xFC
	return id
}

func ClientIDFromRaw(id [8]byte) ClientID {
	id[0] &= 0xFC
	return id
}

func ClientIDFromAddr(addr *net.UDPAddr) ClientID {
	return ClientID(addr.IP[8:])
}

func (id ClientID) Addr() *net.UDPAddr {
	var ip [16]byte
	ip[0] = 0xFD
	copy(ip[8:], id[:])
	return &net.UDPAddr{IP: ip[:]}
}

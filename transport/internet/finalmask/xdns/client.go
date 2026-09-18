package xdns

import (
	"context"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"sort"
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

	clientID    ClientID
	fragID      atomic.Uint32
	domains     []*Domain
	fragManager *FragManager

	resolvers     []Resolver
	resolverSends []atomic.Uint32
	resolverIndex atomic.Uint32

	poolCh  chan struct{}
	readCh  chan packet
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

		clientID:    NewClientID(),
		domains:     domains,
		fragManager: NewFragManager(),

		resolvers:     resolvers,
		resolverSends: make([]atomic.Uint32, len(c.Resolvers)),

		poolCh:  make(chan struct{}, pollLimit),
		readCh:  make(chan packet),
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

func (c *xdnsClient) send(p []byte) {
	domain := c.domains[mrand.Intn(len(c.domains))]
	qtype := domain.types[mrand.Intn(len(domain.types))]

	var buf [512]byte
	var data [255]byte

	send := func(p []byte) {
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

	if len(p) == 0 {
		copy(data[:], c.clientID[:])
		common.Must2(rand.Read(data[8:16]))
		data[0] |= TypeMap[qtype]
		data[8] |= 0x80
		send(data[:16])
		return
	}

	if len(p) <= domain.cap-11 {
		copy(data[:], c.clientID[:])
		common.Must2(rand.Read(data[8:11]))
		copy(data[11:], p)
		data[0] |= TypeMap[qtype]
		data[8] &= 0x7F
		send(data[:11+len(p)])
		return
	}

	if len(p) <= 255*(domain.cap-14) {
		copy(data[:], c.clientID[:])
		common.Must2(rand.Read(data[8:11]))
		data[0] |= 0x40 | TypeMap[qtype]
		data[8] &= 0x7F

		fragID := byte(c.fragID.Add(1))
		fragN := len(p) / (domain.cap - 14)
		if len(p)%(domain.cap-14) > 0 {
			fragN++
		}

		for i := range fragN {
			size := min(len(p), domain.cap-14)
			copy(data[14:], p[:size])
			data[11] = fragID
			data[12] = byte(i)
			data[13] = byte(fragN)
			send(data[:14+size])
			p = p[size:]
		}
		return
	}

	errors.LogError(context.Background(), "send err ", len(p))
}

func (c *xdnsClient) read(buf []byte, addr net.Addr) {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 || len(msg.Answers) == 0 {
		return
	}

	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	if domain == nil || !domain.HasType(uint16(msg.Questions[0].Type)) {
		return
	}

	p := pool4K.Get().([]byte)
	p = p[:0]
	if msg.Questions[0].Type == dnsmessage.TypeTXT {
		if len(msg.Answers) == 1 && domain.IsDomain(msg.Answers[0].Header.Name) && msg.Answers[0].Header.Type == dnsmessage.TypeTXT {
			for i := range msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT {
				p = append(p, msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT[i]...)
			}
		}
		pool4K.Put(p[:cap(p)])
		return
	} else {
		var frags [][]byte
		for i := range msg.Answers {
			if !domain.IsDomain(msg.Answers[i].Header.Name) || msg.Answers[i].Header.Type != msg.Questions[0].Type {
				continue
			}
			switch msg.Questions[0].Type {
			case dnsmessage.TypeA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AResource).A[:])
			case dnsmessage.TypeCNAME:
				var decoded [255]byte
				n, err := domain.Decode(&decoded, msg.Answers[i].Body.(*dnsmessage.CNAMEResource).CNAME)
				if err != nil || n < 2 {
					continue
				}
				frags = append(frags, decoded[:n])
			case dnsmessage.TypeAAAA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AAAAResource).AAAA[:])
			}
		}
		if len(frags) == 0 || len(frags) > 255 {
			pool4K.Put(p[:cap(p)])
			return
		}
		sort.Slice(frags, func(i, j int) bool {
			return frags[i][0] < frags[j][0]
		})
		if frags[0][1] != byte(len(frags)) {
			pool4K.Put(p[:cap(p)])
			return
		}
		p = append(p, frags[0][2:]...)
		for i := range frags {
			if i > 0 {
				if frags[i][0] == frags[i-1][0] {
					pool4K.Put(p[:cap(p)])
					return
				}
				p = append(p, frags[i][1:]...)
			}
		}
	}
	if len(p) < 8+1 {
		pool4K.Put(p[:cap(p)])
		return
	}

	if p[0]&0x80 == 0x80 || (p[0]&0x40 == 0x40 && len(p) < 11+1) || TypeMap_[p[0]&3] != uint16(msg.Questions[0].Type) || c.clientID != ClientIDFromRaw([8]byte(p[:8])) {
		pool4K.Put(p[:cap(p)])
		return
	}
	if p[0]&0x40 == 0x40 {
		out := pool4K.Get().([]byte)
		n := c.fragManager.Feed(out, FragKey{clientID: c.clientID, fragID: p[8]}, p[9], p[10], p[11:])
		pool4K.Put(p[:cap(p)])
		if n > 0 {
			p = out[:n]
		} else {
			if n == 0 {
				select {
				case c.poolCh <- struct{}{}:
				default:
				}
			}
			pool4K.Put(out[:cap(out)])
			return
		}
	} else {
		copy(p, p[8:])
		p = p[:len(p)-8]
	}
	select {
	case c.poolCh <- struct{}{}:
	default:
	}
	select {
	case <-c.closeCh:
		pool4K.Put(p[:cap(p)])
		return
	case c.readCh <- packet{p: p, addr: addr}:
	}
}

func (c *xdnsClient) run() {
	c.wg.Add(1)
	go c.poll()

	for i := range len(c.resolvers) {
		c.wg.Add(1)
		go c.recv(i)
	}

	c.wg.Wait()

	select {
	case packet := <-c.readCh:
		pool4K.Put(packet.p[:cap(packet.p)])
	default:
	}
	close(c.readCh)

	c.fragManager.Close()
	close(c.poolCh)
}

func (c *xdnsClient) poll() {
	defer c.wg.Done()

	select {
	case <-c.closeCh:
		return
	case <-c.poolCh:
	}

	delay := initPollDelay
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-c.poolCh:
			delay = initPollDelay
		case <-ticker.C:
			delay *= pollDelayMultiplier
			if delay > maxPollDelay {
				delay = maxPollDelay
			}
		}
		if c.closed() {
			return
		}
		ticker.Reset(delay)
		c.send(nil)
	}
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
		c.read(buf[:n], c.resolvers[i].Addr())
	}
}

func (c *xdnsClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		n = copy(p, packet.p)
		pool4K.Put(packet.p[:cap(packet.p)])
		return n, packet.addr, nil
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *xdnsClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) > 4096 {
		return 0, errors.New("not support size")
	}
	c.send(p)
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
	id[0] &= 0x3C
	return id
}

func ClientIDFromRaw(id [8]byte) ClientID {
	id[0] &= 0x3C
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

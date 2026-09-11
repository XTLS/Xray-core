package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
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

var pool256 = sync.Pool{
	New: func() any {
		return make([]byte, 256)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsClient struct {
	net.PacketConn

	clientID    [8]byte
	fragID      atomic.Uint32
	domains     []*Domain
	fragManager *FragManager

	addrs []*net.UDPAddr
	conns []net.PacketConn
	sends []atomic.Uint32
	index atomic.Uint32

	poolCh  chan struct{}
	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	if len(c.Addrs) == 0 {
		return nil, errors.New("empty addrs")
	}
	var clientID [8]byte
	common.Must2(rand.Read(clientID[:]))
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
	addrs := make([]*net.UDPAddr, 0, len(c.Addrs))
	conns := make([]net.PacketConn, 0, len(c.Addrs))
	sends := make([]atomic.Uint32, len(c.Addrs))
	for i := range c.Addrs {
		addr, err := net.ResolveUDPAddr("udp", c.Addrs[i])
		if err != nil {
			return nil, err
		}
		conn, err := internet.DialSystem(context.Background(), net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), c.Sockopt)
		if err != nil {
			for j := range conns {
				_ = conns[j].Close()
			}
			return nil, err
		}
		var newConn net.PacketConn
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			newConn = c.PacketConn
		case *cnc.Connection:
			newConn = &internet.FakePacketConn{Conn: c}
		default:
			panic(reflect.TypeOf(c))
		}
		addrs = append(addrs, addr)
		conns = append(conns, newConn)
	}
	client := &xdnsClient{
		PacketConn: raw,

		clientID:    clientID,
		domains:     domains,
		fragManager: NewFragManager(),

		addrs: addrs,
		conns: conns,
		sends: sends,

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

func (c *xdnsClient) is_client_id(id [8]byte) bool {
	if c.clientID[0]&0x3C != id[0]&0x3C {
		return false
	}
	return bytes.Equal(c.clientID[1:], id[1:])
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

		index := c.index.Load()
		cur := c.sends[index].Add(1)
		i := index
		for {
			i++
			if i == uint32(len(c.addrs)) {
				i = 0
			}
			if i == index {
				break
			}
			if cur > c.sends[i].Load() {
				break
			}
		}
		c.index.Store(i)
		_, _ = c.conns[index].WriteTo(pack, c.addrs[index])
	}

	if len(p) == 0 {
		copy(data[:], c.clientID[:])
		common.Must2(rand.Read(data[8:16]))
		data[0] &= 0x3C
		data[0] |= TypeMap[qtype]
		data[8] &= 0x7F
		data[8] |= 0x80
		send(data[:16])
		return
	}

	if len(p) <= domain.cap {
		copy(data[:], c.clientID[:])
		common.Must2(rand.Read(data[8:11]))
		copy(data[11:], p)
		data[0] &= 0x3C
		data[0] |= TypeMap[qtype]
		data[8] &= 0x7F
		send(data[:11+len(p)])
		return
	}

	if len(p) <= domain.capFrags {
		copy(data[:], c.clientID[:])
		data[0] &= 0x3C
		data[0] |= 0x40
		data[0] |= TypeMap[qtype]

		fragID := byte(c.fragID.Add(1))
		fragIdx := byte(0)
		fragN := len(p) / (domain.cap - 3)
		if len(p)%(domain.cap-3) != 0 {
			fragN++
		}

		b := p
		for len(b) > 0 {
			size := min(len(b), domain.cap-3)
			common.Must2(rand.Read(data[8:11]))
			data[11] = fragID
			data[12] = fragIdx
			data[13] = byte(fragN)
			copy(data[14:], b[:size])
			data[8] &= 0x7F
			send(data[:14+size])
			fragIdx++
			b = b[size:]
		}
		return
	}

	errors.LogError(context.Background(), "send err ", len(p))
}

func (c *xdnsClient) read(buf []byte, addr net.Addr) {
	msg := dnsmessage.Message{}
	err := msg.Unpack(buf)
	if err != nil {
		return
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if len(msg.Questions) != 1 || len(msg.Answers) == 0 {
		return
	}
	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	for i := range domain.types {
		if domain.types[i] == uint16(msg.Questions[0].Type) {
			break
		}
		if i == len(domain.types)-1 {
			return
		}
	}

	var frags [][]byte
	for i := range msg.Answers {
		if domain.IsDomain(msg.Answers[i].Header.Name) && msg.Questions[0].Type == msg.Answers[i].Header.Type {
			switch msg.Questions[0].Type {
			case dnsmessage.TypeA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AResource).A[:])
			case dnsmessage.TypeCNAME:
				var decoded [255]byte
				n, err := domain.Decode(decoded[:], msg.Answers[i].Body.(*dnsmessage.CNAMEResource).CNAME)
				if err != nil || n == 0 {
					continue
				}
				frags = append(frags, decoded[:n])
			case dnsmessage.TypeTXT:
				txt := []byte(strings.Join(msg.Answers[i].Body.(*dnsmessage.TXTResource).TXT, ""))
				if len(txt) == 0 {
					continue
				}
				if len(frags) > 0 {
					return
				}
				frags = append(frags, txt)
			case dnsmessage.TypeAAAA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AAAAResource).AAAA[:])
			}
			if len(frags) > 255 {
				return
			}
		}
	}
	if len(frags) == 0 {
		return
	}
	sort.Slice(frags, func(i, j int) bool {
		return frags[i][0] < frags[j][0]
	})
	for i := range frags {
		if i > 0 && frags[i][0] == frags[i-1][0] {
			return
		}
		if frags[i][0] == 0 {
			if len(frags[i]) < 2 {
				return
			}
			if frags[i][1] != byte(len(frags)) {
				return
			}
		}
	}
	p := pool4K.Get().([]byte)
	p = p[:0]
	for i := range frags {
		if i == 0 {
			p = append(p, frags[0][2:]...)
			continue
		}
		p = append(p, frags[i][1:]...)
	}
	if len(p) < 8+1 {
		pool4K.Put(p[:cap(p)])
		return
	}
	if !c.is_client_id([8]byte(p[:8])) {
		pool4K.Put(p[:cap(p)])
		return
	}
	if TypeMap_[p[0]&3] != uint16(msg.Questions[0].Type) {
		pool4K.Put(p[:cap(p)])
		return
	}
	if p[0]&0x40 == 0x40 {
		if len(p) < 11+1 {
			pool4K.Put(p[:cap(p)])
			return
		}
		out := pool4K.Get().([]byte)
		n := c.fragManager.Feed(out, FragKey{clientID: c.clientID, fragID: p[8]}, p[9], p[10], p[11:])
		pool4K.Put(p[:cap(p)])
		if n <= 0 {
			if n == 0 {
				select {
				case c.poolCh <- struct{}{}:
				default:
				}
			}
			pool4K.Put(out[:cap(out)])
			return
		}
		p = out[:n]
	} else {
		copy(p, p[8:])
		p = p[:len(p)-8]
	}
	packet := packet{
		p:    p,
		addr: addr,
	}
	select {
	case c.poolCh <- struct{}{}:
	default:
	}
	select {
	case <-c.closeCh:
		pool4K.Put(p[:cap(p)])
		return
	case c.readCh <- packet:
	}
}

func (c *xdnsClient) run() {
	c.wg.Add(1)
	go c.poll()

	for i := range len(c.addrs) {
		c.wg.Add(1)
		go c.recv(i)
	}

	c.wg.Wait()
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
		n, addr, err := c.conns[i].ReadFrom(buf[:])
		if err != nil {
			if c.closed() {
				return
			}
			errors.LogErrorInner(context.Background(), err, "recv err ", i)
			return
		}
		c.read(buf[:n], addr)
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
	for i := range c.conns {
		_ = c.conns[i].Close()
	}
	return nil
}

func (c *xdnsClient) SetDeadline(t time.Time) error { return nil }

func (c *xdnsClient) SetReadDeadline(t time.Time) error { return nil }

func (c *xdnsClient) SetWriteDeadline(t time.Time) error { return nil }

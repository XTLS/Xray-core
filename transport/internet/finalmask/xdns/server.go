package xdns

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

type resp struct {
	msg  dnsmessage.Message
	addr net.Addr
}

type xdnsServer struct {
	net.PacketConn

	domains      []*Domain
	minAvailable int
	fragManager  *FragManager
	respManager  *RespManager

	readCh  chan packet
	respCh  chan resp
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	if c.MinAvailable < 0 || c.MinAvailable > 8 {
		return nil, errors.New("c.MinAvailable < 0 || c.MinAvailable > 8")
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
	server := &xdnsServer{
		PacketConn: raw,

		domains:      domains,
		minAvailable: int(c.MinAvailable),
		fragManager:  NewFragManager(),
		respManager:  NewRespManager(),

		readCh:  make(chan packet),
		respCh:  make(chan resp),
		closeCh: make(chan struct{}),
	}
	go server.run()
	return server, nil
}

func (c *xdnsServer) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *xdnsServer) read(buf []byte, addr net.Addr) {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return
	}
	if msg.Header.Response {
		return
	}

	opt := false
	edns0 := uint16(0)
	for i := range msg.Additionals {
		if msg.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			if opt {
				msg.Header.RCode = dnsmessage.RCodeFormatError
				c.decref(msg, addr)
				return
			}
			opt = true
			edns0 = uint16(msg.Additionals[i].Header.Class)
			if ver := (msg.Additionals[i].Header.TTL >> 16) & 0xFF; ver != 0 {
				msg.Header.RCode = dnsmessage.RCodeSuccess
				msg.Additionals[i].Header.TTL = 1 << 24
				c.decref(msg, addr)
				return
			}
		}
	}
	if opt && edns0 < 512 {
		edns0 = 512
	}

	if len(msg.Questions) != 1 {
		msg.Header.Response = true
		msg.Header.RCode = dnsmessage.RCodeFormatError
		c.decref(msg, addr)
		return
	}
	if msg.Header.OpCode != 0 {
		msg.Header.Response = true
		msg.Header.RCode = dnsmessage.RCodeNotImplemented
		c.decref(msg, addr)
		return
	}

	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	if domain == nil {
		msg.Header.Response = true
		msg.Header.RCode = dnsmessage.RCodeNameError
		c.decref(msg, addr)
		return
	}
	if !domain.HasType(uint16(msg.Questions[0].Type)) {
		msg.Header.Response = true
		msg.Header.Authoritative = true
		msg.Header.RCode = dnsmessage.RCodeNameError
		c.decref(msg, addr)
		return
	}

	var decoded [255]byte
	n := domain.Decode(&decoded, msg.Questions[0].Name)
	if n < 11+1 {
		msg.Header.Response = true
		msg.Header.Authoritative = true
		msg.Header.RCode = dnsmessage.RCodeNameError
		c.decref(msg, addr)
		return
	}
	if decoded[0]&0x80 == 0x80 || (decoded[0]&0x40 == 0x40 && n < 14+1) || TypeMap_[decoded[0]&3] != uint16(msg.Questions[0].Type) || (decoded[8]&0x80 == 0x80 && n != 16) {
		msg.Header.Response = true
		msg.Header.Authoritative = true
		msg.Header.RCode = dnsmessage.RCodeNameError
		c.decref(msg, addr)
		return
	}
	clientID := ClientIDFromRaw([8]byte(decoded[:8]))

	r := NewResp(msg, domain, addr, edns0, c.SendMsg)
	if r == nil {
		msg.Header.Response = true
		msg.Header.Authoritative = true
		msg.Header.RCode = dnsmessage.RCodeNameError
		c.decref(msg, addr)
		return
	}
	c.respManager.Push(clientID, r)

	if decoded[8]&0x80 == 0x80 {
		return
	}
	p := pool4K.Get().([]byte)
	p = p[:0]
	if decoded[0]&0x40 == 0x40 {
		out := pool4K.Get().([]byte)
		n := c.fragManager.Feed(out, FragKey{clientID: clientID, fragID: decoded[11]}, decoded[12], decoded[13], decoded[14:n])
		pool4K.Put(p[:cap(p)])
		if n > 0 {
			p = out[:n]
		} else {
			pool4K.Put(out[:cap(out)])
			return
		}
	} else {
		p = append(p, decoded[11:n]...)
	}
	select {
	case <-c.closeCh:
		pool4K.Put(p[:cap(p)])
		return
	case c.readCh <- packet{p: p, addr: clientID.Addr()}:
		return
	}
}

func (c *xdnsServer) send(p []byte, addr net.Addr) {
	clientID := ClientIDFromAddr(addr.(*net.UDPAddr))
	resps, fragID := c.respManager.Pop(clientID, c.minAvailable, len(p))
	errors.LogDebug(context.Background(), "pop ", len(p), " ", len(resps))

	buf := pool4K.Get().([]byte)
	defer pool4K.Put(buf[:cap(buf)])
	data := pool4K.Get().([]byte)
	defer pool4K.Put(data[:cap(data)])

	if len(resps) == 1 {
		copy(data[:], clientID[:])
		copy(data[8:], p)
		data[0] |= TypeMap[uint16(resps[0].msg.Questions[0].Type)]
		_, _ = c.PacketConn.WriteTo(resps[0].Encode(buf, data[:8+len(p)]), resps[0].addr)
		return
	}

	if len(resps) > 1 {
		fragN := byte(len(resps))
		for i := range len(resps) {
			copy(data[:], clientID[:])
			size := min(len(p), resps[i].cap-11)
			copy(data[11:], p[:size])
			data[0] |= 0x40 | TypeMap[uint16(resps[i].msg.Questions[0].Type)]
			data[8] = fragID
			data[9] = byte(i)
			data[10] = fragN
			_, _ = c.PacketConn.WriteTo(resps[i].Encode(buf, data[:11+size]), resps[i].addr)
			p = p[size:]
		}
		return
	}
}

func (c *xdnsServer) run() {
	c.wg.Add(1)
	go c.loop()

	c.wg.Add(1)
	go c.recv()

	c.wg.Wait()
	close(c.readCh)
	close(c.respCh)
	c.fragManager.Close()
	c.respManager.Close()
}

func (c *xdnsServer) recv() {
	defer c.wg.Done()

	var buf [512]byte
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if c.closed() {
				return
			}
			errors.LogErrorInner(context.Background(), err, "recv err")
			return
		}
		c.read(buf[:n], addr)
	}
}

func (c *xdnsServer) decref(msg dnsmessage.Message, addr net.Addr) {
	select {
	case c.respCh <- resp{msg: msg, addr: addr}:
	default:
	}
}

func (c *xdnsServer) loop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.closeCh:
			return
		case r := <-c.respCh:
			c.SendMsg(r.msg, r.addr)
		}
	}
}

func (c *xdnsServer) SendMsg(msg dnsmessage.Message, addr net.Addr) {
	var buf [512]byte
	_, _ = c.PacketConn.WriteTo(common.Must2(msg.AppendPack(buf[:0])), addr)
}

func (c *xdnsServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		n = copy(p, packet.p)
		pool4K.Put(packet.p[:cap(packet.p)])
		return n, packet.addr, nil
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *xdnsServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) > 4096 {
		errors.LogError(context.Background(), "err size ", len(p))
		return 0, errors.New("err size")
	}
	c.send(p, addr)
	return len(p), nil
}

func (c *xdnsServer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	_ = c.PacketConn.Close()
	return nil
}

func (c *xdnsServer) SetDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsServer) SetReadDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsServer) SetWriteDeadline(t time.Time) error { return errors.New("not support") }

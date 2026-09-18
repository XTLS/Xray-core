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

const (
	respTTL = fragTTL
)

type Resp struct {
	msg      dnsmessage.Message
	addr     net.Addr
	clientID ClientID
	domain   *Domain

	edns0 uint16
	cap   int
}

func NewResp(msg dnsmessage.Message, addr net.Addr, clientID ClientID, domain *Domain) *Resp {
	if len(msg.Questions) != 1 {
		return nil
	}

	opt := false
	var edns0 uint16
	for i := range msg.Additionals {
		if msg.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			if (msg.Additionals[i].Header.TTL>>16)&0xFF != 0 {
				return nil
			}
			if opt {
				return nil
			}
			opt = true
			edns0 = uint16(msg.Additionals[i].Header.Class)
		}
	}
	if edns0 > 4096 {
		return nil
	}
	if edns0 > 0 && edns0 < 512 {
		edns0 = 512
	}
	size := min(max(int(edns0), 512), max(int(domain.edns0), 512))

	left := size - 12 - int(msg.Questions[0].Name.Length) - 1 - 2 - 2
	if edns0 > 0 {
		left -= 1 + 2 + 2 + 4 + 2 + 0
	}
	cap := 0
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		single := 2 + 2 + 2 + 4 + 2 + 4
		n := left / single
		cap = 4*n - n - 1
	case dnsmessage.TypeCNAME:
		single := 2 + 2 + 2 + 4 + 2 + domain.lenMax
		n := left / single
		cap = domain.cap*n - n - 1
	case dnsmessage.TypeTXT:
		left -= 2 + 2 + 2 + 4 + 2
		single := 1 + 255
		n := left / single
		m := left % single
		cap = 255*n - n
		if m > 1 {
			cap += m - 1
		}
	case dnsmessage.TypeAAAA:
		single := 2 + 2 + 2 + 4 + 2 + 16
		n := left / single
		cap = 16*n - n - 1
	}
	if cap < 11+1 {
		return nil
	}

	msg.Header = dnsmessage.Header{
		ID:            msg.Header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	}
	msg.Answers = nil
	msg.Authorities = nil
	msg.Additionals = nil
	return &Resp{
		msg:      msg,
		addr:     addr,
		clientID: clientID,
		domain:   domain,

		edns0: edns0,
		cap:   cap,
	}
}

// TODO: use dnsmessage.Builder
func (r *Resp) Append(out []byte, data []byte) []byte {
	if len(data) == 0 || len(data) > r.cap {
		panic(len(data))
	}
	msg := r.msg
	switch r.msg.Questions[0].Type {
	case dnsmessage.TypeA:
		fragN := 1
		if (len(data) - (4 - 2)) > 0 {
			fragN += (len(data) - (4 - 2)) / (4 - 1)
			if (len(data)-(4-2))%(4-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			A := [4]byte{byte(i)}
			if i == 0 {
				A[1] = byte(fragN)
				n := copy(A[2:], data)
				data = data[n:]
			} else {
				n := copy(A[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: A},
			})
		}
	case dnsmessage.TypeCNAME:
		fragN := 1
		if (len(data) - (r.domain.cap - 2)) > 0 {
			fragN += (len(data) - (r.domain.cap - 2)) / (r.domain.cap - 1)
			if (len(data)-(r.domain.cap-2))%(r.domain.cap-1) > 0 {
				fragN++
			}
		}

		DATA := make([]byte, r.domain.cap)
		for i := range fragN {
			DATA[0] = byte(i)
			if i == 0 {
				DATA[1] = byte(fragN)
				n := copy(DATA[2:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:n+2])},
				})
			} else {
				n := copy(DATA[1:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:n+1])},
				})
			}
		}
	case dnsmessage.TypeTXT:
		var txt []string
		for len(data) > 0 {
			size := min(len(data), 255)
			txt = append(txt, string(data[:size]))
			data = data[size:]
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  msg.Questions[0].Name,
				Type:  msg.Questions[0].Type,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.TXTResource{TXT: txt},
		})
	case dnsmessage.TypeAAAA:
		fragN := 1
		if (len(data) - (16 - 2)) > 0 {
			fragN += (len(data) - (16 - 2)) / (16 - 1)
			if (len(data)-(16-2))%(16-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			AAAA := [16]byte{byte(i)}
			if i == 0 {
				AAAA[1] = byte(fragN)
				n := copy(AAAA[2:], data)
				data = data[n:]
			} else {
				n := copy(AAAA[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: AAAA},
			})
		}
	}
	if r.edns0 > 0 {
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(r.edns0),
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{},
		})
	}
	return common.Must2(msg.AppendPack(out))
}

type RespInfo struct {
	resp     chan *Resp
	fragID   byte
	capFrags int
	deadline time.Time
}

type xdnsServer struct {
	net.PacketConn

	domains     []*Domain
	fragManager *FragManager
	m           map[ClientID]RespInfo

	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
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

		domains:     domains,
		fragManager: NewFragManager(),
		m:           make(map[ClientID]RespInfo),

		readCh:  make(chan packet),
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

func (c *xdnsServer) push(clientID ClientID, resp *Resp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return
	}
	now := time.Now()
	info, ok := c.m[clientID]
	if !ok || now.After(info.deadline) {
		info = RespInfo{
			resp:     make(chan *Resp, 255),
			deadline: now.Add(respTTL),
		}
	}
	select {
	case info.resp <- resp:
		info.capFrags += resp.cap - 11
	default:
		r := <-info.resp
		info.capFrags -= r.cap - 11
		info.resp <- resp
		info.capFrags += resp.cap - 11
	}
	c.m[clientID] = info
}

func (c *xdnsServer) pop(clientID ClientID, lenp int) ([]*Resp, byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil, 0
	}
	now := time.Now()
	info, ok := c.m[clientID]
	if !ok || now.After(info.deadline) {
		if ok {
			delete(c.m, clientID)
		}
		return nil, 0
	}
	if info.capFrags < lenp {
		return nil, 0
	}
	var resps []*Resp
	size := 0
	for {
		r := <-info.resp
		info.capFrags -= r.cap - 11
		if len(resps) == 0 && lenp <= r.cap-8 {
			return []*Resp{r}, 0
		}
		resps = append(resps, r)
		size += r.cap - 11
		if lenp <= size {
			fragID := info.fragID
			info.fragID++
			return resps, fragID
		}
	}
}

func (c *xdnsServer) read(buf []byte, addr net.Addr) {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return
	}
	if msg.Header.Response || len(msg.Questions) != 1 {
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

	var decoded [255]byte
	n, err := domain.Decode(&decoded, msg.Questions[0].Name)
	if err != nil || n < 11+1 {
		return
	}
	if decoded[0]&0x80 == 0x80 || (decoded[0]&0x40 == 0x40 && n < 14+1) || TypeMap_[decoded[0]&3] != uint16(msg.Questions[0].Type) || (decoded[8]&0x80 == 0x80 && n != 16) {
		return
	}

	clientID := ClientIDFromRaw([8]byte(decoded[:8]))
	resp := NewResp(msg, addr, clientID, domain)
	if resp == nil {
		return
	}
	c.push(clientID, resp)

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
	resps, fragID := c.pop(clientID, len(p))
	if len(resps) == 0 {
		return
	}
	buf := pool4K.Get().([]byte)
	defer pool4K.Put(buf[:cap(buf)])
	data := pool4K.Get().([]byte)
	defer pool4K.Put(data[:cap(data)])
	if len(resps) > 1 {
		fragN := byte(len(resps))
		for i := range len(resps) {
			copy(data[:], resps[i].clientID[:])
			size := min(len(p), resps[i].cap-11)
			copy(data[8:], p[:size])
			data[0] |= 0x40 | TypeMap[uint16(resps[i].msg.Questions[0].Type)]
			data[8] = fragID
			data[9] = byte(i)
			data[10] = fragN
			_, _ = c.PacketConn.WriteTo(resps[i].Append(buf[:0], data[:11+size]), resps[i].addr)
			p = p[size:]
		}
	} else {
		copy(data[:], resps[0].clientID[:])
		copy(data[8:], p)
		data[0] |= TypeMap[uint16(resps[0].msg.Questions[0].Type)]
		_, _ = c.PacketConn.WriteTo(resps[0].Append(buf[:0], data[:8+len(p)]), resps[0].addr)
	}
}

func (c *xdnsServer) run() {
	go c.gc()

	c.wg.Add(1)
	go c.recv()

	c.wg.Wait()
	close(c.readCh)
	c.fragManager.Close()
	for key := range c.m {
		delete(c.m, key)
	}
}

func (c *xdnsServer) gc() {
	ticker := time.NewTicker(respTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for key, info := range c.m {
				if now.After(info.deadline) {
					delete(c.m, key)
				}
			}
			c.mu.Unlock()
		}
	}
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
		return 0, errors.New("not support size")
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

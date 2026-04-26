package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	numPadding          = 3
	numPaddingForPoll   = 8
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsConnClient struct {
	net.PacketConn

	resolverAddrs []*net.UDPAddr
	resolverIdx   uint32
	resolverSend  map[string]*atomic.Uint32

	clientID []byte
	domains  []Name

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	closed bool
	mutex  sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}

	var domains []Name
	var servers []string
	for _, rs := range c.Resolvers {
		parts := strings.Split(rs, "+udp://")
		if len(parts) != 2 {
			return nil, errors.New("invalid resolvers")
		}
		domain, err := ParseName(parts[0])
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
		servers = append(servers, parts[1])
	}

	var resolverAddrs []*net.UDPAddr
	var resolverSend = make(map[string]*atomic.Uint32)
	for _, rs := range servers {
		h, p, err := net.SplitHostPort(rs)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, errors.New("invalid ip address")
		}
		port, _ := strconv.Atoi(p)
		if port == 0 {
			return nil, errors.New("invalid port")
		}
		addr := &net.UDPAddr{IP: ip, Port: port}
		resolverAddrs = append(resolverAddrs, addr)
		resolverSend[addr.String()] = &atomic.Uint32{}
	}

	conn := &xdnsConnClient{
		PacketConn: raw,

		resolverAddrs: resolverAddrs,
		resolverIdx:   0,
		resolverSend:  resolverSend,

		clientID: make([]byte, 8),
		domains:  domains,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 256),
		writeQueue: make(chan *packet, 256),
	}

	common.Must2(rand.Read(conn.clientID))

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	var buf [finalmask.UDPSize]byte

	for {
		if c.closed {
			break
		}

		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if go_errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}

		if addr == nil {
			continue
		}

		send := c.resolverSend[addr.String()]
		if send == nil {
			continue
		}

		resp, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domains)

		r := bytes.NewReader(payload)
		anyPacket := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			anyPacket = true

			buf := make([]byte, len(p))
			copy(buf, p)
			select {
			case c.readQueue <- &packet{
				p:    buf,
				addr: addr,
			}:
			default:
				errors.LogDebug(context.Background(), addr, " mask read err queue full")
			}
		}

		if anyPacket {
			send.Store(0)
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")

	close(c.pollChan)
	close(c.readQueue)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.closed = true
	close(c.writeQueue)
}

func (c *xdnsConnClient) sendLoop() {
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
			select {
			case <-c.pollChan:
			default:
			}
		} else {
			encoded, _ := encode(nil, c.clientID, c.domains[c.resolverIdx])
			p = &packet{
				p: encoded,
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

		cur := c.resolverIdx
		curSend := c.resolverSend[c.resolverAddrs[cur].String()].Add(1)
		_, _ = c.PacketConn.WriteTo(p.p, c.resolverAddrs[cur])
		for {
			c.resolverIdx += 1
			c.resolverIdx %= uint32(len(c.resolverAddrs))
			if c.resolverIdx == cur {
				break
			}
			if c.resolverSend[c.resolverAddrs[c.resolverIdx].String()].Load() < curSend {
				break
			}
		}
	}
}

func (c *xdnsConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, nil
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	encoded, err := encode(p, c.clientID, c.domains[c.resolverIdx%uint32(len(c.resolverAddrs))])
	if err != nil {
		errors.LogDebug(context.Background(), addr, " xdns wireformat err ", err, " ", len(p))
		return 0, nil
	}

	select {
	case c.writeQueue <- &packet{
		p:    encoded,
		addr: addr,
	}:
		return len(p), nil
	default:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, nil
	}
}

func (c *xdnsConnClient) Close() error {
	c.closed = true
	return c.PacketConn.Close()
}

func encode(p []byte, clientID []byte, domain Name) ([]byte, error) {
	var decoded []byte
	{
		if len(p) >= 224 {
			return nil, errors.New("too long")
		}
		var buf bytes.Buffer
		buf.Write(clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		_, _ = io.CopyN(&buf, rand.Reader, int64(n))
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, domain...)
	name, err := NewName(labels)
	if err != nil {
		return nil, err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &Message{
		ID:    id,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  name,
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}

	buf, err := query.WireFormat()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func dnsResponsePayload(resp *Message, domains []Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != RcodeNoError {
		return nil
	}

	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]

	var ok bool
	for _, domain := range domains {
		_, ok = answer.Name.TrimSuffix(domain)
		if ok {
			break
		}
	}
	if !ok {
		return nil
	}

	if answer.Type != RRTypeTXT {
		return nil
	}
	payload, err := DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

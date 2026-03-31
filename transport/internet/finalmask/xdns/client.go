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

type resolverConn struct {
	conn net.PacketConn
	addr *net.UDPAddr
}

func parseResolverAddr(s string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host = s
		port = "53"
	}
	if host == "" {
		return nil, go_errors.New("empty resolver address")
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
}

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsConnClient struct {
	net.PacketConn

	clientID []byte
	domain   Name

	resolverConns []*resolverConn
	resolverIdx   atomic.Uint32
	serverAddr    atomic.Value // stores net.Addr; set by WriteTo, used by recvLoopFrom in resolver mode
	recvWg        sync.WaitGroup
	sendWg        sync.WaitGroup

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	mutex     sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	domain, err := ParseName(c.Domain)
	if err != nil {
		return nil, err
	}

	conn := &xdnsConnClient{
		PacketConn: raw,

		clientID: make([]byte, 8),
		domain:   domain,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 256),
		writeQueue: make(chan *packet, 256),
	}

	common.Must2(rand.Read(conn.clientID))

	if len(c.Resolvers) > 0 {
		for _, rs := range c.Resolvers {
			addr, err := parseResolverAddr(rs)
			if err != nil {
				for _, rc := range conn.resolverConns {
					rc.conn.Close()
				}
				return nil, errors.New("invalid resolver address: ", rs, ": ", err)
			}
			uc, err := net.ListenPacket("udp", ":0")
			if err != nil {
				for _, rc := range conn.resolverConns {
					rc.conn.Close()
				}
				return nil, errors.New("failed to create resolver socket: ", err)
			}
			conn.resolverConns = append(conn.resolverConns, &resolverConn{conn: uc, addr: addr})
		}
		for _, rc := range conn.resolverConns {
			conn.recvWg.Add(1)
			go func(pconn net.PacketConn) {
				defer conn.recvWg.Done()
				conn.recvLoopFrom(pconn)
			}(rc.conn)
		}
	} else {
		conn.recvWg.Add(1)
		go func() {
			defer conn.recvWg.Done()
			conn.recvLoop()
		}()
	}
	conn.sendWg.Add(1)
	go func() {
		defer conn.sendWg.Done()
		conn.sendLoop()
	}()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	c.recvLoopFrom(c.PacketConn)

	errors.LogDebug(context.Background(), "xdns closed")

	close(c.pollChan)
	close(c.readQueue)

	c.closed.Store(true)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	close(c.writeQueue)
}

func (c *xdnsConnClient) recvLoopFrom(conn net.PacketConn) {
	var buf [finalmask.UDPSize]byte

	for {
		if c.closed.Load() {
			break
		}

		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil || n == 0 {
			if go_errors.Is(err, net.ErrClosed) || go_errors.Is(err, io.EOF) {
				break
			}
			continue
		}

		resp, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)
		if payload == nil {
			continue
		}

		pktAddr := net.Addr(addr)
		if len(c.resolverConns) > 0 {
			if sa := c.serverAddr.Load(); sa != nil {
				pktAddr = sa.(net.Addr)
			}
		}

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
				addr: pktAddr,
			}:
			default:
				errors.LogDebug(context.Background(), addr, " mask read err queue full")
			}
		}

		if anyPacket {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

func (c *xdnsConnClient) sendLoop() {
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
			encoded, _ := encode(nil, c.clientID, c.domain)
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
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if c.closed.Load() {
			return
		}

		if p != nil {
			var err error
			if len(c.resolverConns) > 0 {
				idx := c.resolverIdx.Add(1)
				rc := c.resolverConns[idx%uint32(len(c.resolverConns))]
				_, err = rc.conn.WriteTo(p.p, rc.addr)
			} else {
				_, err = c.PacketConn.WriteTo(p.p, p.addr)
			}
			if go_errors.Is(err, net.ErrClosed) || go_errors.Is(err, io.ErrClosedPipe) {
				c.closed.Store(true)
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
	c.serverAddr.Store(addr)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	encoded, err := encode(p, c.clientID, c.domain)
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
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		for _, rc := range c.resolverConns {
			rc.conn.Close()
		}
		c.closeErr = c.PacketConn.Close()
		c.recvWg.Wait()
		if len(c.resolverConns) > 0 {
			close(c.pollChan)
			close(c.readQueue)
			c.mutex.Lock()
			close(c.writeQueue)
			c.mutex.Unlock()
		}
		c.sendWg.Wait()
	})
	return c.closeErr
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

func dnsResponsePayload(resp *Message, domain Name) []byte {
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

	_, ok := answer.Name.TrimSuffix(domain)
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

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
	"sync"
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
	resolverConns []net.PacketConn
	resolverAddrs []*net.UDPAddr
	resolverIdx   uint32

	clientID []byte
	domain   Name

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

	for _, rs := range c.Resolvers {
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
		var uc net.PacketConn
		if ip.To4() != nil {
			uc, err = net.ListenPacket("udp4", ":0")
		} else {
			uc, err = net.ListenPacket("udp6", ":0")
		}
		if err != nil {
			for _, rc := range conn.resolverConns {
				rc.Close()
			}
			return nil, errors.New("failed to create resolver socket: ", err)
		}
		conn.resolverConns = append(conn.resolverConns, uc)
		conn.resolverAddrs = append(conn.resolverAddrs, &net.UDPAddr{IP: ip, Port: port})
	}

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	var wg sync.WaitGroup

	for _, rc := range c.resolverConns {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var buf [finalmask.UDPSize]byte

			for {
				if c.closed {
					break
				}

				n, addr, err := rc.ReadFrom(buf[:])
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
					select {
					case c.pollChan <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	wg.Wait()

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
			encoded, _ := encode(nil, c.clientID, c.domain)
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

		_, _ = c.resolverConns[c.resolverIdx].WriteTo(p.p, c.resolverAddrs[c.resolverIdx])
		c.resolverIdx += 1
		c.resolverIdx %= uint32(len(c.resolverConns))
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
	c.closed = true
	for _, rc := range c.resolverConns {
		rc.Close()
	}
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

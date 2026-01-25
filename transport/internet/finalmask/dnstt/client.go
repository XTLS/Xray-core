package dnstt

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/dnstt/dns"
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

type packetStruct struct {
	p    []byte
	addr net.Addr
}

type dnsttConnClient struct {
	conn net.PacketConn

	clientID []byte
	domain   dns.Name
	pollChan chan struct{}

	readQueue  chan *packetStruct
	writeQueue chan *packetStruct

	closed    chan struct{}
	closeOnce sync.Once
}

func NewConnClient(c *Config, raw net.PacketConn, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("dnstt requires being at the outermost level")
	}

	domain, err := dns.ParseName(c.Domain)
	if err != nil {
		return nil, err
	}

	conn := &dnsttConnClient{
		conn: raw,

		clientID: make([]byte, 8),
		domain:   domain,
		pollChan: make(chan struct{}, pollLimit),

		readQueue:  make(chan *packetStruct, 128),
		writeQueue: make(chan *packetStruct, 128),

		closed: make(chan struct{}),
	}

	rand.Read(conn.clientID)

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *dnsttConnClient) recvLoop() {
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		var buf [4096]byte
		n, addr, err := c.conn.ReadFrom(buf[:])
		if err != nil {
			continue
		}

		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
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
			case c.readQueue <- &packetStruct{
				p:    buf,
				addr: addr,
			}:
			default:
				// silent drop
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

func (c *dnsttConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.closed:
		return 0, nil, io.EOF

	case pkt := <-c.readQueue:
		n := copy(p, pkt.p)
		if n < len(pkt.p) {
			return n, nil, io.ErrShortBuffer
		}
		return n, pkt.addr, nil
	}
}

func (c *dnsttConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	encoded, err := encode(p, c.clientID, c.domain)
	if err != nil {
		return 0, err
	}

	select {
	case <-c.closed:
		return 0, errors.New("closed")

	case c.writeQueue <- &packetStruct{
		p:    encoded,
		addr: addr,
	}:
		return len(p), nil

	default:
		return 0, errors.New("queue full")
	}
}

func (c *dnsttConnClient) sendLoop() {
	var addr net.Addr

	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		var p *packetStruct
		pollTimerExpired := false

		select {
		case p = <-c.writeQueue:
		case <-c.pollChan:
		case <-pollTimer.C:
			pollTimerExpired = true
		}

		if p != nil {
			addr = p.addr

			select {
			case <-c.pollChan:
			default:
			}
		} else if addr != nil {
			encoded, _ := encode(nil, c.clientID, c.domain)
			p = &packetStruct{
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

		if p != nil {
			_, _ = c.conn.WriteTo(p.p, p.addr)
		}
	}
}

func (c *dnsttConnClient) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.conn.Close()
}

func (c *dnsttConnClient) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *dnsttConnClient) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *dnsttConnClient) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *dnsttConnClient) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func encode(p []byte, clientID []byte, domain dns.Name) ([]byte, error) {
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
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
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

func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
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

	if answer.Type != dns.RRTypeTXT {
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

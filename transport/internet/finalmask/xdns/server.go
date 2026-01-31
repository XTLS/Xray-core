package xdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	idleTimeout      = 2 * time.Minute
	responseTTL      = 60
	maxResponseDelay = 1 * time.Second
)

var (
	maxUDPPayload     = 1280 - 40 - 8
	maxEncodedPayload = computeMaxEncodedPayload(maxUDPPayload)
)

func clientIDToAddr(clientID [8]byte) *net.UDPAddr {
	ip := make(net.IP, 16)

	copy(ip, []byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0})
	copy(ip[8:], clientID[:])

	return &net.UDPAddr{
		IP: ip,
	}
}

type record struct {
	Resp *Message
	Addr net.Addr
	// ClientID [8]byte
	ClientAddr net.Addr
}

type queue struct {
	lash  time.Time
	queue chan []byte
	stash chan []byte
}

type xdnsConnServer struct {
	conn net.PacketConn

	domain Name

	ch            chan *record
	readQueue     chan *packet
	writeQueueMap map[string]*queue

	closed bool
	mutex  sync.Mutex
}

func NewConnServer(c *Config, raw net.PacketConn, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("xdns requires being at the outermost level")
	}

	domain, err := ParseName(c.Domain)
	if err != nil {
		return nil, err
	}

	conn := &xdnsConnServer{
		conn: raw,

		domain: domain,

		ch:            make(chan *record, 100),
		readQueue:     make(chan *packet, 128),
		writeQueueMap: make(map[string]*queue),
	}

	go conn.clean()
	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnServer) clean() {
	f := func() bool {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if c.closed {
			return true
		}

		now := time.Now()

		for key, q := range c.writeQueueMap {
			if now.Sub(q.lash) >= idleTimeout {
				close(q.queue)
				close(q.stash)
				delete(c.writeQueueMap, key)
			}
		}

		return false
	}

	for {
		time.Sleep(idleTimeout / 2)
		if f() {
			return
		}
	}
}

func (c *xdnsConnServer) ensureQueue(addr net.Addr) *queue {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	q, ok := c.writeQueueMap[addr.String()]
	if !ok {
		q = &queue{
			queue: make(chan []byte, 128),
			stash: make(chan []byte, 1),
		}
		c.writeQueueMap[addr.String()] = q
	}
	q.lash = time.Now()

	return q
}

func (c *xdnsConnServer) stash(queue *queue, p []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return
	}

	select {
	case queue.stash <- p:
	default:
	}
}

func (c *xdnsConnServer) recvLoop() {
	for {
		if c.closed {
			break
		}

		var buf [4096]byte
		n, addr, err := c.conn.ReadFrom(buf[:])
		if err != nil {
			continue
		}

		query, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}

		resp, payload := responseFor(&query, c.domain)

		var clientID [8]byte
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacketServer(r)
				if err != nil {
					break
				}

				buf := make([]byte, len(p))
				copy(buf, p)
				select {
				case c.readQueue <- &packet{
					p:    buf,
					addr: clientIDToAddr(clientID),
				}:
				default:
				}
			}
		} else {
			if resp != nil && resp.Rcode() == RcodeNoError {
				resp.Flags |= RcodeNameError
			}
		}

		if resp != nil {
			select {
			case c.ch <- &record{resp, addr, clientIDToAddr(clientID)}:
			default:
			}
		}
	}

	close(c.ch)
	close(c.readQueue)
}

func (c *xdnsConnServer) sendLoop() {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-c.ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == RcodeNoError && len(rec.Resp.Question) == 1 {
			rec.Resp.Answer = []RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil,
				},
			}

			var payload bytes.Buffer
			limit := maxEncodedPayload
			timer := time.NewTimer(maxResponseDelay)
			for {
				queue := c.ensureQueue(rec.ClientAddr)
				if queue == nil {
					return
				}

				var p []byte

				select {
				case p = <-queue.stash:
				default:
					select {
					case p = <-queue.stash:
					case p = <-queue.queue:
					default:
						select {
						case p = <-queue.stash:
						case p = <-queue.queue:
						case <-timer.C:
						case nextRec = <-c.ch:
						}
					}
				}

				timer.Reset(0)

				if len(p) == 0 {
					break
				}

				limit -= 2 + len(p)
				if payload.Len() == 0 {

				} else if limit < 0 {
					c.stash(queue, p)

					break
				}

				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}

				_ = binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			timer.Stop()

			rec.Resp.Answer[0].Data = EncodeRDataTXT(payload.Bytes())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			continue
		}

		if len(buf) > maxUDPPayload {
			errors.LogDebug(context.Background(), "xdns server truncate ", len(buf))
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02
		}

		if c.closed {
			return
		}

		_, _ = c.conn.WriteTo(buf, rec.Addr)
	}
}

func (c *xdnsConnServer) Size() int32 {
	return 0
}

func (c *xdnsConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *xdnsConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	q := c.ensureQueue(addr)
	if q == nil {
		return 0, errors.New("xdns closed")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return 0, errors.New("xdns closed")
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case q.queue <- buf:
		return len(p), nil
	default:
		return 0, errors.New("xdns queue full")
	}
}

func (c *xdnsConnServer) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	for key, q := range c.writeQueueMap {
		close(q.queue)
		close(q.stash)
		delete(c.writeQueueMap, key)
	}

	return c.conn.Close()
}

func (c *xdnsConnServer) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *xdnsConnServer) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *xdnsConnServer) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *xdnsConnServer) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func nextPacketServer(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

func responseFor(query *Message, domain Name) (*Message, []byte) {
	resp := &Message{
		ID:       query.ID,
		Flags:    0x8000,
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		return nil, nil
	}

	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= RcodeFormatError
			return resp, nil
		}
		resp.Additional = append(resp.Additional, RR{
			Name:  Name{},
			Type:  RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= ExtendedRcodeBadVers & 0xf
			additional.TTL = (ExtendedRcodeBadVers >> 4) << 24
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	if len(query.Question) != 1 {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}
	question := query.Question[0]

	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	resp.Flags |= 0x0400

	if query.Opcode() != 0 {
		resp.Flags |= RcodeNotImplemented
		return resp, nil
	}

	if question.Type != RRTypeTXT {
		resp.Flags |= RcodeNameError
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	payload = payload[:n]

	if payloadSize < maxUDPPayload {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}

	return resp, payload
}

func computeMaxEncodedPayload(limit int) int {
	maxLengthName, err := NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1
		if n != 255 {
			panic("computeMaxEncodedPayload n != 255")
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &Message{
		Question: []Question{
			{
				Name:  maxLengthName,
				Type:  RRTypeTXT,
				Class: RRTypeTXT,
			},
		},

		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: queryLimit,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, [][]byte{})

	resp.Answer = []RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil,
		},
	}

	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

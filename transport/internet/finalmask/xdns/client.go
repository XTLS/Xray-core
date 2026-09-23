package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"io"
	stdnet "net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
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
	addr stdnet.Addr
}

type xdnsConnClient struct {
	raw         stdnet.PacketConn
	resolvers   []*clientResolver
	resolverIdx uint32
	clientID    []byte
	domains     []Name

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	ctx       context.Context
	cancel    context.CancelFunc
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	wg        sync.WaitGroup

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	closeErr      error
}

type clientResolver struct {
	spec     resolverSpec
	udp      *udpResolver
	exchange exchangeResolver
	pending  atomic.Uint32
}

func NewConnClient(c *Config, raw stdnet.PacketConn) (stdnet.PacketConn, error) {
	return NewConnClientWithDialer(c, raw, nil)
}

func NewConnClientWithDialer(c *Config, raw stdnet.PacketConn, dialer *finalmask.Dialer) (stdnet.PacketConn, error) {
	if len(c.Resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}

	resolverSpecs := make([]resolverSpec, 0, len(c.Resolvers))
	managedConnections := false
	for _, resolver := range c.Resolvers {
		spec, err := parseResolver(resolver)
		if err != nil {
			return nil, errors.New("invalid resolvers").Base(err)
		}
		resolverSpecs = append(resolverSpecs, spec)
		managedConnections = managedConnections || spec.protocol != resolverUDP
	}
	if managedConnections && dialer == nil {
		return nil, errors.New("resolver dialer is required for dot or doh")
	}
	if managedConnections && dialer.DialTCPContext == nil && dialer.DialTCP == nil {
		return nil, errors.New("resolver tcp dialer is required for dot or doh")
	}
	if !managedConnections && raw == nil {
		return nil, errors.New("udp resolver requires packet connection")
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &xdnsConnClient{
		clientID:   make([]byte, 8),
		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 256),
		writeQueue: make(chan *packet, 256),
		ctx:        ctx,
		cancel:     cancel,
		closeCh:    make(chan struct{}),
		raw:        raw,
	}
	common.Must2(rand.Read(conn.clientID))

	type udpGroup struct {
		conn      stdnet.PacketConn
		resolvers []*clientResolver
	}
	groups := make([]udpGroup, 0, len(resolverSpecs))
	resources := make([]io.Closer, 0, len(resolverSpecs)+1)
	if raw != nil {
		resources = append(resources, raw)
	}
	for _, spec := range resolverSpecs {
		resolver := &clientResolver{spec: spec}
		conn.domains = append(conn.domains, spec.domain)
		switch spec.protocol {
		case resolverUDP:
			var packetConn stdnet.PacketConn
			if managedConnections {
				if dialer.DialUDP == nil {
					conn.closeResources(resources)
					return nil, errors.New("resolver udp dialer is required for mixed resolvers")
				}
				var err error
				packetConn, err = dialUDPResolver(dialer, spec)
				if err != nil {
					conn.closeResources(resources)
					return nil, err
				}
				resources = append(resources, packetConn)
			} else {
				packetConn = raw
			}
			addr, err := stdnet.ResolveUDPAddr("udp", spec.server)
			if err != nil {
				conn.closeResources(resources)
				return nil, err
			}
			resolver.udp = &udpResolver{conn: packetConn, addr: addr}
			found := false
			for i := range groups {
				if groups[i].conn == packetConn {
					groups[i].resolvers = append(groups[i].resolvers, resolver)
					found = true
					break
				}
			}
			if !found {
				groups = append(groups, udpGroup{conn: packetConn, resolvers: []*clientResolver{resolver}})
			}
		case resolverDOT:
			resolver.exchange = newDOTResolver(spec, dialer)
			resources = append(resources, resolver.exchange)
		case resolverDOH:
			resolver.exchange = newDOHResolver(spec, dialer)
			resources = append(resources, resolver.exchange)
		}
		conn.resolvers = append(conn.resolvers, resolver)
	}
	for _, group := range groups {
		startUDPReceiver(conn.ctx, &conn.wg, group.conn, group.resolvers, conn.handleUDPResponse)
	}
	conn.wg.Add(1)
	go conn.sendLoop()
	return conn, nil
}

func (c *xdnsConnClient) sendLoop() {
	defer c.wg.Done()
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
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
			case <-c.closeCh:
				return
			}
		}

		if p != nil {
			select {
			case <-c.pollChan:
			default:
			}
		} else {
			p = &packet{}
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

		if c.closed.Load() {
			return
		}
		resolver := c.nextResolver()
		encoded, err := encode(p.p, c.clientID, resolver.spec.domain, resolver.spec.rrType)
		if err != nil {
			errors.LogDebug(context.Background(), p.addr, " xdns wireformat err ", err, " ", len(p.p))
			continue
		}
		resolver.pending.Add(1)
		if resolver.udp != nil {
			if err := resolver.udp.send(encoded); err != nil {
				resolver.pending.Add(^uint32(0))
				logUDPError(resolver.udp.addr, err)
			}
			continue
		}
		c.wg.Add(1)
		go c.exchange(resolver, encoded, p.addr)
	}
}

func (c *xdnsConnClient) nextResolver() *clientResolver {
	idx := c.resolverIdx % uint32(len(c.resolvers))
	resolver := c.resolvers[idx]
	currentPending := resolver.pending.Load()
	for {
		c.resolverIdx = (c.resolverIdx + 1) % uint32(len(c.resolvers))
		if c.resolverIdx == idx || c.resolvers[c.resolverIdx].pending.Load() < currentPending {
			break
		}
	}
	return resolver
}

func (c *xdnsConnClient) exchange(resolver *clientResolver, query []byte, addr stdnet.Addr) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(c.ctx, resolverTimeout)
	defer cancel()
	response, err := resolver.exchange.Exchange(ctx, query)
	if err != nil {
		resolver.pending.Add(^uint32(0))
		errors.LogDebug(context.Background(), "xdns resolver exchange err ", err)
		return
	}
	c.handleResponse(resolver, response, addr)
}

func (c *xdnsConnClient) handleUDPResponse(resolver *clientResolver, response []byte, addr stdnet.Addr) {
	c.handleResponse(resolver, response, addr)
}

func (c *xdnsConnClient) handleResponse(resolver *clientResolver, response []byte, addr stdnet.Addr) {
	if c.closed.Load() {
		return
	}
	resp, err := MessageFromWireFormat(response)
	if err != nil {
		errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
		return
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
		case c.readQueue <- &packet{p: buf, addr: addr}:
		case <-c.closeCh:
			return
		default:
			errors.LogDebug(context.Background(), addr, " mask read err queue full")
		}
	}
	if anyPacket {
		resolver.pending.Store(0)
		select {
		case c.pollChan <- struct{}{}:
		default:
		}
	}
}

func (c *xdnsConnClient) ReadFrom(p []byte) (n int, addr stdnet.Addr, err error) {
	timer := c.readTimer()
	if timer != nil {
		defer timer.Stop()
	}
	var timeout <-chan time.Time
	if timer != nil {
		timeout = timer.C
	}
	var packet *packet
	var ok bool
	select {
	case packet, ok = <-c.readQueue:
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
	if !ok {
		return 0, nil, stdnet.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, nil
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnClient) WriteTo(p []byte, addr stdnet.Addr) (n int, err error) {
	if c.writeExpired() {
		return 0, os.ErrDeadlineExceeded
	}
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) >= 224 {
		errors.LogDebug(context.Background(), addr, " xdns wireformat err too long ", len(p))
		return 0, nil
	}
	select {
	case c.writeQueue <- &packet{
		p:    append([]byte(nil), p...),
		addr: addr,
	}:
		return len(p), nil
	case <-c.closeCh:
		return 0, io.ErrClosedPipe
	default:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, nil
	}
}

func (c *xdnsConnClient) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.cancel()
		close(c.closeCh)
		var resources []io.Closer
		for _, resolver := range c.resolvers {
			if resolver.udp != nil {
				resources = append(resources, resolver.udp.conn)
			}
			if resolver.exchange != nil {
				resources = append(resources, resolver.exchange)
			}
		}
		if c.raw != nil {
			resources = append(resources, c.raw)
		}
		c.closeResources(resources)
		c.wg.Wait()
		close(c.readQueue)
	})
	return c.closeErr
}

func (c *xdnsConnClient) closeResources(resources []io.Closer) {
	closed := make(map[io.Closer]struct{}, len(resources))
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		if _, found := closed[resource]; found {
			continue
		}
		closed[resource] = struct{}{}
		if err := resource.Close(); err != nil && c.closeErr == nil {
			c.closeErr = err
		}
	}
}

func (c *xdnsConnClient) LocalAddr() stdnet.Addr {
	if c.raw != nil {
		return c.raw.LocalAddr()
	}
	for _, resolver := range c.resolvers {
		if resolver.udp != nil {
			return resolver.udp.conn.LocalAddr()
		}
	}
	return &stdnet.UDPAddr{}
}

func (c *xdnsConnClient) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	if c.raw != nil {
		return c.raw.SetDeadline(t)
	}
	return nil
}

func (c *xdnsConnClient) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	if c.raw != nil {
		return c.raw.SetReadDeadline(t)
	}
	return nil
}

func (c *xdnsConnClient) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	if c.raw != nil {
		return c.raw.SetWriteDeadline(t)
	}
	return nil
}

func (c *xdnsConnClient) readTimer() *time.Timer {
	c.deadlineMu.RLock()
	deadline := c.readDeadline
	c.deadlineMu.RUnlock()
	if deadline.IsZero() {
		return nil
	}
	return time.NewTimer(time.Until(deadline))
}

func (c *xdnsConnClient) writeExpired() bool {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	c.deadlineMu.RUnlock()
	return !deadline.IsZero() && !deadline.After(time.Now())
}

func dialUDPResolver(dialer *finalmask.Dialer, spec resolverSpec) (stdnet.PacketConn, error) {
	host, portString, err := stdnet.SplitHostPort(spec.server)
	if err != nil {
		return nil, err
	}
	port, err := xnet.PortFromString(portString)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.DialUDP(xnet.UDPDestination(xnet.ParseAddress(host), port))
	if err != nil {
		return nil, err
	}
	wrapper, ok := conn.(*finalmask.PacketConnWrapper)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("resolver dialer returned invalid udp connection")
	}
	return wrapper.PacketConn, nil
}

func encode(p []byte, clientID []byte, domain Name, qtype uint16) ([]byte, error) {
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
				Type:  qtype,
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

	if len(resp.Answer) == 0 {
		return nil
	}

	for _, answer := range resp.Answer {
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
	}

	return decodeResponsePayload(resp.Answer)
}

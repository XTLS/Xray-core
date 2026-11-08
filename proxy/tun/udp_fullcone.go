package tun

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// udpFlow is one source and destination of UDP packets that came from the tun
type udpFlow struct {
	src net.Destination
	dst net.Destination
}

// udpCone is the session of one source for one route
type udpCone struct {
	src   net.Destination
	route string
}

// sub-handler specifically for udp connections under main handler
//
// It keeps FullCone NAT: the destinations of one source share a session, so they share the outbound and its
// mapping, and anyone can answer through it. Only the first packet of a session is routed, so the destinations
// share a session only while they take the same route. A destination that routes elsewhere, such as DNS that has
// to reach the DNS outbound after the system gave the port of a finished flow to a resolver, gets a session of its
// own. Without routeKey every destination of a source shares one session, whatever the route.
type udpConnectionHandler struct {
	sync.RWMutex

	// flows are the session of every source and destination seen
	flows map[udpFlow]*udpConn
	// cones are the sessions of a source by route
	cones map[udpCone]*udpConn

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
	// routeKey names the route that a packet from src to dst takes. It may take its time: it is not called from
	// the goroutine that reads the tun
	routeKey func(src net.Destination, dst net.Destination) string
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		flows:            make(map[udpFlow]*udpConn),
		cones:            make(map[udpCone]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection by the source addr:port and the
// route of the destination
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data *buf.Buffer) {
	data.UDP = &dst
	flow := udpFlow{src: src, dst: dst}

	u.RLock()
	conn, found := u.flows[flow]
	if found {
		u.push(conn, data, "queue full")
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()

	conn, found = u.flows[flow]
	if !found {
		conn = &udpConn{handler: u, queue: newPacketQueue(udpQueueLimit), src: src, dst: dst, flows: []udpFlow{flow}}
		u.flows[flow] = conn
		if u.routeKey == nil {
			conn = u.settle(conn, "")
		} else {
			// until its route is known the destination waits in a queue of its own
			go u.route(conn)
		}
	}

	u.push(conn, data, "queue full 2")
}

func (u *udpConnectionHandler) push(conn *udpConn, data *buf.Buffer, reason string) {
	if !conn.queue.push(data) {
		errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", data.UDP.NetAddr(), " original ", conn.dst.NetAddr(), " > ", reason)
		data.Release()
	}
}

// route finds the route of a new destination and gives it to the session of its source that takes the same route,
// or makes it a session of its own
func (u *udpConnectionHandler) route(pending *udpConn) {
	key := u.routeKey(pending.src, pending.dst)
	u.Lock()
	defer u.Unlock()
	u.settle(pending, key)
}

// settle gives pending to the session of its source with the same route, or starts it as one, and returns the
// session that carries it now. It is called with the lock held
func (u *udpConnectionHandler) settle(pending *udpConn, key string) *udpConn {
	cone := udpCone{src: pending.src, route: key}
	if conn, found := u.cones[cone]; found {
		for _, flow := range pending.flows {
			u.flows[flow] = conn
		}
		conn.flows = append(conn.flows, pending.flows...)
		pending.queue.moveTo(conn.queue)
		return conn
	}
	pending.route = key
	u.cones[cone] = pending
	go u.handleConnection(pending, pending.dst)
	return pending
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	// Close runs twice per flow; a newer conn may already own this src.
	cone := udpCone{src: conn.src, route: conn.route}
	if u.cones[cone] == conn {
		delete(u.cones, cone)
		for _, flow := range conn.flows {
			if u.flows[flow] == conn {
				delete(u.flows, flow)
			}
		}
		conn.queue.close()
	}
	u.Unlock()
}

// udp connection abstraction
type udpConn struct {
	handler *udpConnectionHandler

	queue *packetQueue
	src   net.Destination
	dst   net.Destination
	// route is the key of the route the session takes
	route string
	// flows are the destinations of src that the session carries
	flows []udpFlow
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, ok := c.queue.pop()
	if !ok {
		return nil, io.EOF
	}
	return buf.MultiBuffer{b}, nil
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	b, ok := c.queue.pop()
	if !ok {
		return 0, io.EOF
	}
	defer b.Release()
	n := copy(p, b.Bytes())
	if n != int(b.Len()) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		err := c.handler.writePacket(b.Bytes(), dst, c.src)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	err := c.handler.writePacket(p, c.dst, c.src)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// udpQueueLimit bounds the packets waiting for one UDP flow; more are dropped.
const udpQueueLimit = 1024

// packetQueue holds the packets waiting for one UDP flow. Unlike a buffered
// channel of the same bound it only allocates for packets actually queued, so
// the many idle flows kept until the idle timeout cost next to nothing.
type packetQueue struct {
	mu     sync.Mutex
	items  []*buf.Buffer
	limit  int
	notify chan struct{}
	closed bool
}

func newPacketQueue(limit int) *packetQueue {
	return &packetQueue{limit: limit, notify: make(chan struct{}, 1)}
}

// push queues b and reports whether it was accepted.
func (q *packetQueue) push(b *buf.Buffer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.items) >= q.limit {
		return false
	}
	q.items = append(q.items, b)
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

// pop blocks until a packet is queued or the queue is closed and drained.
func (q *packetQueue) pop() (*buf.Buffer, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			b := q.items[0]
			q.items[0] = nil
			q.items = q.items[1:]
			if len(q.items) == 0 {
				q.items = nil
			}
			q.mu.Unlock()
			return b, true
		}
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		q.mu.Unlock()
		<-q.notify
	}
}

// moveTo hands what q holds to other, in order, and closes q
func (q *packetQueue) moveTo(other *packetQueue) {
	q.mu.Lock()
	items := q.items
	q.items = nil
	q.mu.Unlock()
	for _, b := range items {
		if !other.push(b) {
			b.Release()
		}
	}
	q.close()
}

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notify)
	}
}

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

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	udpConns map[net.Destination]*udpConn

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[net.Destination]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data *buf.Buffer) {
	data.UDP = &dst

	u.RLock()
	conn, found := u.udpConns[src]
	if found {
		if !conn.queue.push(data) {
			errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
			data.Release()
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()

	conn, found = u.udpConns[src]
	if !found {
		conn = &udpConn{handler: u, queue: newPacketQueue(udpQueueLimit), src: src, dst: dst}
		u.udpConns[src] = conn

		go u.handleConnection(conn, dst)
	}

	// queue the packet for the reader of the connection, or discard it
	if !conn.queue.push(data) {
		errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full 2")
		data.Release()
	}
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	// Close runs twice per flow; a newer conn may already own this src.
	if u.udpConns[conn.src] == conn {
		delete(u.udpConns, conn.src)
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

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notify)
	}
}

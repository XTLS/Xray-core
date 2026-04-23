package turbotunnel

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// taggedPacket is a combination of a []byte and a net.Addr, encapsulating the
// return type of PacketConn.ReadFrom.
type taggedPacket struct {
	P    []byte
	Addr net.Addr
}

// QueuePacketConn implements net.PacketConn by storing queues of packets. There
// is one incoming queue (where packets are additionally tagged by the source
// address of the peer that sent them). There are many outgoing queues, one for
// each remote peer address that has been recently seen. The QueueIncoming
// method inserts a packet into the incoming queue, to eventually be returned by
// ReadFrom. WriteTo inserts a packet into an address-specific outgoing queue,
// which can later by accessed through the OutgoingQueue method.
//
// Besides the outgoing queues, there is also a one-element "stash" for each
// remote peer address. You can stash a packet using the Stash method, and get
// it back later by receiving from the channel returned by Unstash. The stash is
// meant as a convenient place to temporarily store a single packet, such as
// when you've read one too many packets from the send queue and need to store
// the extra packet to be processed first in the next pass. It's the caller's
// responsibility to Unstash what they have Stashed. Calling Stash does not put
// the packet at the head of the send queue; if there is the possibility that a
// packet has been stashed, it must be checked for by calling Unstash in
// addition to OutgoingQueue.
type QueuePacketConn struct {
	remotes   *RemoteMap
	localAddr net.Addr
	recvQueue chan taggedPacket
	closeOnce sync.Once
	closed    chan struct{}
	// What error to return when the QueuePacketConn is closed.
	err atomic.Value
}

// NewQueuePacketConn makes a new QueuePacketConn, set to track recent peers
// for at least a duration of timeout.
func NewQueuePacketConn(localAddr net.Addr, timeout time.Duration) *QueuePacketConn {
	return &QueuePacketConn{
		remotes:   NewRemoteMap(timeout),
		localAddr: localAddr,
		recvQueue: make(chan taggedPacket, queueSize),
		closed:    make(chan struct{}),
	}
}

// QueueIncoming queues and incoming packet and its source address, to be
// returned in a future call to ReadFrom.
func (c *QueuePacketConn) QueueIncoming(p []byte, addr net.Addr) {
	select {
	case <-c.closed:
		// If we're closed, silently drop it.
		return
	default:
	}
	// Copy the slice so that the caller may reuse it.
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.recvQueue <- taggedPacket{buf, addr}:
	default:
		// Drop the incoming packet if the receive queue is full.
	}
}

// OutgoingQueue returns the queue of outgoing packets corresponding to addr,
// creating it if necessary. The contents of the queue will be packets that are
// written to the address in question using WriteTo.
func (c *QueuePacketConn) OutgoingQueue(addr net.Addr) <-chan []byte {
	return c.remotes.SendQueue(addr)
}

// Stash places p in the stash for addr, if the stash is not already occupied.
// Returns true if the packet was placed in the stash, or false if the stash was
// already occupied. This method is similar to WriteTo, except that it puts the
// packet in the stash queue (accessible via Unstash), rather than the outgoing
// queue (accessible via OutgoingQueue).
func (c *QueuePacketConn) Stash(p []byte, addr net.Addr) bool {
	return c.remotes.Stash(addr, p)
}

// Unstash returns the channel that represents the stash for addr.
func (c *QueuePacketConn) Unstash(addr net.Addr) <-chan []byte {
	return c.remotes.Unstash(addr)
}

// ReadFrom returns a packet and address previously stored by QueueIncoming.
func (c *QueuePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: c.LocalAddr().Network(), Addr: c.LocalAddr(), Err: c.err.Load().(error)}
	default:
	}
	select {
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: c.LocalAddr().Network(), Addr: c.LocalAddr(), Err: c.err.Load().(error)}
	case packet := <-c.recvQueue:
		return copy(p, packet.P), packet.Addr, nil
	}
}

// WriteTo queues an outgoing packet for the given address. The queue can later
// be retrieved using the OutgoingQueue method.
func (c *QueuePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, &net.OpError{Op: "write", Net: c.LocalAddr().Network(), Addr: c.LocalAddr(), Err: c.err.Load().(error)}
	default:
	}
	// Copy the slice so that the caller may reuse it.
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.remotes.SendQueue(addr) <- buf:
		return len(buf), nil
	default:
		// Drop the outgoing packet if the send queue is full.
		return len(buf), nil
	}
}

// closeWithError unblocks pending operations and makes future operations fail
// with the given error. If err is nil, it becomes errClosedPacketConn.
func (c *QueuePacketConn) closeWithError(err error) error {
	var newlyClosed bool
	c.closeOnce.Do(func() {
		newlyClosed = true
		// Store the error to be returned by future PacketConn
		// operations.
		if err == nil {
			err = errClosedPacketConn
		}
		c.err.Store(err)
		close(c.closed)
	})
	if !newlyClosed {
		return &net.OpError{Op: "close", Net: c.LocalAddr().Network(), Addr: c.LocalAddr(), Err: c.err.Load().(error)}
	}
	return nil
}

// Close unblocks pending operations and makes future operations fail with a
// "closed connection" error.
func (c *QueuePacketConn) Close() error {
	return c.closeWithError(nil)
}

// LocalAddr returns the localAddr value that was passed to NewQueuePacketConn.
func (c *QueuePacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *QueuePacketConn) SetDeadline(t time.Time) error      { return errNotImplemented }
func (c *QueuePacketConn) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (c *QueuePacketConn) SetWriteDeadline(t time.Time) error { return errNotImplemented }

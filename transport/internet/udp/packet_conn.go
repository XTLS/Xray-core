package udp

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// DialDispatcher returns a packet socket whose first write selects its route.
// The route reads the socket's datagrams and delivers replies to ReadFrom.
func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(WithPacketRouteState(ctx))
	conn := &dispatcherConn{
		dispatcher: dispatcher,
		ctx:        ctx,
		cancel:     cancel,
		input:      NewPacketInbox(policy.BufferPolicyFromContext(ctx).PerConnection),
		replies:    make(chan packetReply, 16),
	}
	context.AfterFunc(ctx, conn.finish)
	return conn, nil
}

type packetReply struct {
	payload *buf.Buffer
	source  net.Destination
}

type dispatcherConn struct {
	dispatcher routing.Dispatcher
	ctx        context.Context
	cancel     context.CancelFunc
	input      *PacketInbox
	replies    chan packetReply

	writeMu sync.Mutex
	mu      sync.Mutex
	started bool
	closed  bool
}

func (c *dispatcherConn) WriteTo(data []byte, address net.Addr) (int, error) {
	peer, ok := address.(*net.UDPAddr)
	if !ok || peer == nil || peer.Port < 1 || peer.Port > 65535 {
		return 0, errors.New("invalid UDP destination")
	}
	dest := net.DestinationFromAddr(peer)
	if dest.Address == nil {
		return 0, errors.New("invalid UDP address")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	if !c.started {
		c.input.AttachRoute(c.ctx)
	}
	n := min(len(data), buf.Size)
	if n != 0 {
		packet := buf.New()
		copy(packet.Extend(int32(n)), data[:n])
		packet.UDP = &dest
		if err := c.input.Put(c.ctx, buf.MultiBuffer{packet}); err != nil {
			return 0, err
		}
	}
	if !c.started {
		c.started = true
		go c.run(dest)
	}
	return n, nil
}

func (c *dispatcherConn) run(dest net.Destination) {
	if c.ctx.Err() != nil {
		return
	}
	reader := NewDispatchPacketReader(c.ctx, c.cancel, c.input, nil)
	idle := signal.CancelAfterInactivity(c.ctx, c.cancel, time.Minute)
	defer idle.SetTimeout(0)
	defer c.finish()
	_ = c.dispatcher.DispatchLink(c.ctx, dest, &transport.Link{
		Reader: reader,
		Writer: &packetConnWriter{conn: c, dest: dest, idle: idle},
	})
}

func (c *dispatcherConn) ReadFrom(data []byte) (int, net.Addr, error) {
	reply, ok := <-c.replies
	if !ok {
		return 0, nil, io.EOF
	}
	defer reply.payload.Release()
	addr := &net.UDPAddr{IP: reply.source.Address.IP(), Port: int(reply.source.Port)}
	return copy(data, reply.payload.Bytes()), addr, nil
}

func (c *dispatcherConn) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cancel()
	c.input.Close()
	close(c.replies)
}

func (c *dispatcherConn) Close() error {
	c.finish()
	for reply := range c.replies {
		reply.payload.Release()
	}
	return nil
}

func (*dispatcherConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: []byte{0, 0, 0, 0}} }
func (*dispatcherConn) SetDeadline(time.Time) error      { return nil }
func (*dispatcherConn) SetReadDeadline(time.Time) error  { return nil }
func (*dispatcherConn) SetWriteDeadline(time.Time) error { return nil }

type packetConnWriter struct {
	conn *dispatcherConn
	dest net.Destination
	idle *signal.ActivityTimer
}

func (w *packetConnWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	c := w.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		buf.ReleaseMulti(packets)
		return io.ErrClosedPipe
	}
	w.idle.Update()
	for _, packet := range packets {
		if packet == nil {
			continue
		}
		if packet.UDP != nil && packet.UDP.Address != nil && packet.UDP.Address.Family().IsIP() {
			w.dest = *packet.UDP
		}
		select {
		case c.replies <- packetReply{payload: packet, source: w.dest}:
		default:
			packet.Release()
		}
	}
	return nil
}

func (w *packetConnWriter) Close() error {
	w.conn.finish()
	return nil
}

func (w *packetConnWriter) Interrupt() { w.conn.finish() }

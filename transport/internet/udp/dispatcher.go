package udp

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type ResponseCallback func(ctx context.Context, packet *udp.Packet)

type connEntry struct {
	link   *transport.Link
	timer  signal.ActivityUpdater
	cancel context.CancelFunc
}

type Dispatcher struct {
	sync.RWMutex
	conns      map[net.Destination]*connEntry
	dispatcher routing.Dispatcher
	callback   ResponseCallback
	callClose  func() error
}

func NewDispatcher(dispatcher routing.Dispatcher, callback ResponseCallback) *Dispatcher {
	return &Dispatcher{
		conns:      make(map[net.Destination]*connEntry),
		dispatcher: dispatcher,
		callback:   callback,
	}
}

func (v *Dispatcher) RemoveRay(dest net.Destination) {
	v.Lock()
	defer v.Unlock()
	if conn, found := v.conns[dest]; found {
		common.Close(conn.link.Reader)
		common.Close(conn.link.Writer)
		delete(v.conns, dest)
	}
}

func (v *Dispatcher) getInboundRay(ctx context.Context, dest net.Destination) (*connEntry, error) {
	v.Lock()
	defer v.Unlock()

	if entry, found := v.conns[dest]; found {
		return entry, nil
	}

	newError("establishing new connection for ", dest).WriteToLog()

	ctx, cancel := context.WithCancel(ctx)
	removeRay := func() {
		cancel()
		v.RemoveRay(dest)
	}
	timer := signal.CancelAfterInactivity(ctx, removeRay, time.Minute)

	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, newError("failed to dispatch request to ", dest).Base(err)
	}

	entry := &connEntry{
		link:   link,
		timer:  timer,
		cancel: removeRay,
	}
	v.conns[dest] = entry
	go handleInput(ctx, entry, dest, v.callback, v.callClose)
	return entry, nil
}

func (v *Dispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	// TODO: Add user to destString
	newError("dispatch request to: ", destination).AtDebug().WriteToLog(session.ExportIDToError(ctx))

	conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		newError("failed to get inbound").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return
	}
	outputStream := conn.link.Writer
	if outputStream != nil {
		if err := outputStream.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			newError("failed to write first UDP payload").Base(err).WriteToLog(session.ExportIDToError(ctx))
			conn.cancel()
			return
		}
	}
}

func handleInput(ctx context.Context, conn *connEntry, dest net.Destination, callback ResponseCallback, callClose func() error) {
	defer func() {
		conn.cancel()
		if callClose != nil {
			callClose()
		}
	}()

	input := conn.link.Reader
	timer := conn.timer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mb, err := input.ReadMultiBuffer()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				newError("failed to handle UDP input").Base(err).WriteToLog(session.ExportIDToError(ctx))
			}
			return
		}
		timer.Update()
		for _, b := range mb {
			callback(ctx, &udp.Packet{
				Payload: b,
				Source:  dest,
			})
		}
	}
}

type dispatcherConn struct {
	dispatcher *Dispatcher
	cache      chan *udp.Packet
	done       *done.Instance
	ctx        context.Context
}

func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	c := &dispatcherConn{
		cache: make(chan *udp.Packet, 16),
		done:  done.New(),
		ctx:   ctx,
	}

	d := &Dispatcher{
		conns:      make(map[net.Destination]*connEntry),
		dispatcher: dispatcher,
		callback:   c.callback,
		callClose:  c.Close,
	}
	c.dispatcher = d
	return c, nil
}

func (c *dispatcherConn) callback(ctx context.Context, packet *udp.Packet) {
	select {
	case <-c.done.Wait():
		packet.Payload.Release()
		return
	case c.cache <- packet:
	default:
		packet.Payload.Release()
		return
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var packet *udp.Packet
s:
	select {
	case <-c.done.Wait():
		select {
		case packet = <-c.cache:
			break s
		default:
			return 0, nil, io.EOF
		}
	case packet = <-c.cache:
	}
	return copy(p, packet.Payload.Bytes()), &net.UDPAddr{
		IP:   packet.Source.Address.IP(),
		Port: int(packet.Source.Port),
	}, nil
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buffer := buf.New()
	raw := buffer.Extend(buf.Size)
	n := copy(raw, p)
	buffer.Resize(0, int32(n))

	c.dispatcher.Dispatch(c.ctx, net.DestinationFromAddr(addr), buffer)
	return n, nil
}

func (c *dispatcherConn) Close() error {
	return c.done.Close()
}

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}

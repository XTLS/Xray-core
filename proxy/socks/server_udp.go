package socks

import (
	"context"
	"io"
	"maps"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func (s *Server) handleUDPPayload(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancelCause(ctx)
	input := udp.NewPacketInbox(policy.BufferPolicyFromContext(ctx).PerConnection)
	stopped := make(chan struct{})
	context.AfterFunc(ctx, func() {
		input.Close()
		conn.SetReadDeadline(time.Now())
		close(stopped)
	})
	received := make(chan struct{})
	go func() {
		defer close(received)
		reader := &buf.PacketReader{Reader: conn}
		for ctx.Err() == nil {
			packet, err := readSocksDatagram(ctx, reader)
			if err != nil {
				cancel(err)
				return
			}
			if err := input.Put(ctx, packet); err != nil {
				cancel(err)
				return
			}
		}
	}()
	defer func() {
		cancel(context.Canceled)
		<-stopped
		<-received
	}()

	var target net.Destination
	association := ctx
	for ctx.Err() == nil {
		first, err := input.Take(ctx, nil)
		if err != nil {
			break
		}
		if ctx.Err() != nil {
			buf.ReleaseMulti(first)
			break
		}
		firstTarget := *first[0].UDP
		if !target.IsValid() {
			target = firstTarget
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				udpInbound := *inbound
				udpInbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
				udpInbound.Local = net.DestinationFromAddr(conn.LocalAddr())
				association = session.ContextWithInbound(ctx, &udpInbound)
				errors.LogInfo(ctx, "client UDP connection from ", udpInbound.Source)
			}
		}

		routeCtx := association
		if inbound := session.InboundFromContext(association); inbound != nil && inbound.Source.IsValid() {
			routeCtx = log.ContextWithAccessMessage(association, &log.AccessMessage{
				From:   inbound.Source,
				To:     firstTarget,
				Status: log.AccessAccepted,
				Email:  inbound.User.Email,
			})
		}
		if err := dispatchSocksUDP(routeCtx, conn, input, dispatcher, target, first); err != nil {
			return err
		}
	}
	return context.Cause(ctx)
}

func readSocksDatagram(ctx context.Context, reader *buf.PacketReader) (buf.MultiBuffer, error) {
	for ctx.Err() == nil {
		packets, err := reader.ReadMultiBuffer()
		if err != nil {
			return nil, err
		}
		payload := packets[0]
		request, err := DecodeUDPPacket(payload)
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to parse UDP request")
			payload.Release()
			continue
		}
		if payload.IsEmpty() {
			payload.Release()
			continue
		}
		destination := request.Destination()
		payload.UDP = &destination
		return packets, nil
	}
	return nil, ctx.Err()
}

func dispatchSocksUDP(ctx context.Context, conn stat.Connection, input *udp.PacketInbox, dispatcher routing.Dispatcher, target net.Destination, first buf.MultiBuffer) error {
	// The dispatcher writes route and sniffing results into these records.
	if previous := session.OutboundsFromContext(ctx); len(previous) > 0 {
		outbounds := make([]*session.Outbound, len(previous))
		for i, previous := range previous {
			outbound := *previous
			outbounds[i] = &outbound
		}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	if previous := session.ContentFromContext(ctx); previous != nil {
		content := *previous
		content.Attributes = maps.Clone(previous.Attributes)
		ctx = session.ContextWithContent(ctx, &content)
	}
	routeCtx, cancel := context.WithCancel(ctx)
	route := &socksUDPRoute{
		ctx:     routeCtx,
		cancel:  cancel,
		conn:    conn,
		input:   input,
		first:   first,
		replyTo: *first[0].UDP,
	}
	woke := make(chan struct{})
	context.AfterFunc(routeCtx, func() {
		conn.SetWriteDeadline(time.Now())
		close(woke)
	})
	route.activity = signal.CancelAfterInactivity(routeCtx, cancel, time.Minute)

	input.AttachRoute(routeCtx)
	if routeCtx.Err() == nil {
		if err := dispatcher.DispatchLink(routeCtx, target, &transport.Link{Reader: route, Writer: route}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to dispatch UDP to ", target)
		}
	}
	route.activity.SetTimeout(0)
	cancel()
	<-woke

	// Finish the old route's output before restoring the association's write deadline.
	route.readMu.Lock()
	if route.first != nil {
		route.first = buf.ReleaseMulti(route.first)
	}
	route.readMu.Unlock()
	route.writeMu.Lock()
	route.writeMu.Unlock()
	input.RetireRoute()

	if err := context.Cause(ctx); err != nil {
		return err
	}
	return conn.SetWriteDeadline(time.Time{})
}

type socksUDPRoute struct {
	ctx      context.Context
	cancel   context.CancelFunc
	conn     stat.Connection
	input    *udp.PacketInbox
	replyTo  net.Destination
	activity *signal.ActivityTimer

	readMu       sync.Mutex
	first        buf.MultiBuffer
	primaryBound bool
	counters     []stats.Counter
	writeMu      sync.Mutex
}

func (r *socksUDPRoute) SetUplinkCounter(counter stats.Counter) {
	r.readMu.Lock()
	defer r.readMu.Unlock()

	if !r.primaryBound {
		r.primaryBound = true
		r.input.BindUplinkCounter(r.ctx, counter)
		if counter != nil {
			counter.Add(int64(r.first.Len()))
		}
	} else if counter != nil {
		// Loopback can re-dispatch the same reader using the same counter.
		r.counters = append(r.counters, counter)
	}
}

func (r *socksUDPRoute) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *socksUDPRoute) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *socksUDPRoute) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if r.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	packet := r.first
	if packet != nil {
		r.first = nil
	} else {
		var err error
		packet, err = r.input.Take(r.ctx, timeout)
		if r.ctx.Err() != nil {
			buf.ReleaseMulti(packet)
			return nil, io.ErrClosedPipe
		}
		if err != nil {
			return nil, err
		}
	}
	size := int64(packet.Len())
	for _, counter := range r.counters {
		counter.Add(size)
	}
	return packet, nil
}

func (r *socksUDPRoute) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	for _, payload := range packets {
		if r.ctx.Err() != nil {
			return io.ErrClosedPipe
		}
		r.activity.Update()
		source := r.replyTo
		if payload.UDP != nil {
			source = *payload.UDP
		}
		reply, err := EncodeUDPPacket(&protocol.RequestHeader{Address: source.Address, Port: source.Port}, payload.Bytes())
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to encode SOCKS UDP response")
			continue
		}
		_, err = r.conn.Write(reply.Bytes())
		reply.Release()
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to write SOCKS UDP response")
		}
	}
	return r.ctx.Err()
}

func (r *socksUDPRoute) Interrupt() {
	r.cancel()
}

func (r *socksUDPRoute) Close() error {
	r.cancel()
	return nil
}
